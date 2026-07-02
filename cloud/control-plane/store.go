// Package main is the TokenFuse Cloud control plane: it ingests call telemetry
// from many gateways and serves an aggregated, per-organization view of spend
// and activity — the "single pane of glass" across a fleet of gateways.
package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// CallRecord is one settled call, pushed by a gateway's CloudSink. The JSON
// shape matches crates/gateway/src/sink.rs::CallRecord.
type CallRecord struct {
	TsMillis     int64  `json:"ts_millis"`
	RunID        string `json:"run_id"`
	Model        string `json:"model"`
	Decision     string `json:"decision"`
	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`
	CostMicrousd int64  `json:"cost_microusd"`
	Step         uint32 `json:"step"`
}

// RunAgg is the aggregated state of one run within an organization.
type RunAgg struct {
	RunID         string `json:"run_id"`
	Model         string `json:"model"`
	SpentMicrousd int64  `json:"spent_microusd"`
	Calls         int    `json:"calls"`
	CacheHits     int    `json:"cache_hits"`
	Steps         uint32 `json:"steps"`
	LastSeen      int64  `json:"last_seen_millis"`
	Killed        bool   `json:"killed"`
}

// Summary is org-wide totals.
type Summary struct {
	Runs          int   `json:"runs"`
	Calls         int   `json:"calls"`
	SpentMicrousd int64 `json:"spent_microusd"`
}

// Store is a concurrency-safe aggregation keyed by org → run. It can persist to
// disk (a periodic JSON snapshot) so state survives a restart; a SQL/columnar
// backend (Postgres/ClickHouse) for scale + retention is a drop-in follow-up
// behind the same methods.
type Store struct {
	mu      sync.RWMutex
	orgs    map[string]map[string]*RunAgg
	killed  map[string]map[string]bool  // org → run → killed
	budgets map[string]map[string]int64 // org → run → budget µUSD
	dirty   bool
}

func NewStore() *Store {
	return &Store{
		orgs:    make(map[string]map[string]*RunAgg),
		killed:  make(map[string]map[string]bool),
		budgets: make(map[string]map[string]int64),
	}
}

// snapshot is the on-disk shape of the whole store.
type snapshot struct {
	Orgs    map[string]map[string]*RunAgg `json:"orgs"`
	Killed  map[string]map[string]bool    `json:"killed"`
	Budgets map[string]map[string]int64   `json:"budgets"`
}

// Load reads a snapshot from `path` into the store. A missing file is not an
// error (fresh start).
func (s *Store) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Orgs != nil {
		s.orgs = snap.Orgs
	}
	if snap.Killed != nil {
		s.killed = snap.Killed
	}
	if snap.Budgets != nil {
		s.budgets = snap.Budgets
	}
	return nil
}

// Save atomically writes a snapshot to `path` (tmp file + rename).
func (s *Store) Save(path string) error {
	s.mu.RLock()
	data, err := json.Marshal(snapshot{Orgs: s.orgs, Killed: s.killed, Budgets: s.budgets})
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Autosave snapshots to `path` every `every` while the store has unsaved
// changes. Runs until the process exits.
func (s *Store) Autosave(path string, every time.Duration) {
	for range time.Tick(every) {
		s.mu.Lock()
		d := s.dirty
		s.dirty = false
		s.mu.Unlock()
		if d {
			if err := s.Save(path); err != nil {
				// best-effort; keep serving
				continue
			}
		}
	}
}

// Kill marks a run killed for an org; gateways poll this and hard-stop it.
func (s *Store) Kill(org, run string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	if s.killed[org] == nil {
		s.killed[org] = make(map[string]bool)
	}
	s.killed[org][run] = true
}

// Kills lists the run ids an org has killed.
func (s *Store) Kills(org string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []string{}
	for run, k := range s.killed[org] {
		if k {
			out = append(out, run)
		}
	}
	return out
}

// SetBudget sets a centrally-managed budget (microdollars) for a run; gateways
// poll this and apply it, overriding the client-supplied budget.
func (s *Store) SetBudget(org, run string, micros int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	if s.budgets[org] == nil {
		s.budgets[org] = make(map[string]int64)
	}
	s.budgets[org][run] = micros
}

// Budgets returns an org's run → budget-micros overrides.
func (s *Store) Budgets(org string) map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int64, len(s.budgets[org]))
	for run, m := range s.budgets[org] {
		out[run] = m
	}
	return out
}

// Ingest folds a batch of records into an org's aggregates.
func (s *Store) Ingest(org string, records []CallRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	runs, ok := s.orgs[org]
	if !ok {
		runs = make(map[string]*RunAgg)
		s.orgs[org] = runs
	}
	for _, r := range records {
		agg, ok := runs[r.RunID]
		if !ok {
			agg = &RunAgg{RunID: r.RunID}
			runs[r.RunID] = agg
		}
		agg.SpentMicrousd += r.CostMicrousd
		agg.Calls++
		if r.Decision == "cache_hit" {
			agg.CacheHits++
		}
		if r.Model != "" {
			agg.Model = r.Model
		}
		if r.Step > agg.Steps {
			agg.Steps = r.Step
		}
		if r.TsMillis > agg.LastSeen {
			agg.LastSeen = r.TsMillis
		}
	}
}

// Runs returns an org's run aggregates (order unspecified; the client sorts).
func (s *Store) Runs(org string) []RunAgg {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []RunAgg{}
	killed := s.killed[org]
	for _, agg := range s.orgs[org] {
		a := *agg
		a.Killed = killed[a.RunID]
		out = append(out, a)
	}
	return out
}

// Summary returns org-wide totals.
func (s *Store) Summary(org string) Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := Summary{}
	for _, agg := range s.orgs[org] {
		sum.Runs++
		sum.Calls += agg.Calls
		sum.SpentMicrousd += agg.SpentMicrousd
	}
	return sum
}
