// Package main is the TokenFuse Cloud control plane: it ingests call telemetry
// from many gateways and serves an aggregated, per-organization view of spend
// and activity — the "single pane of glass" across a fleet of gateways.
package main

import "sync"

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

// Store is an in-memory, concurrency-safe aggregation keyed by org → run.
// (A durable backend — Postgres/ClickHouse — is a drop-in follow-up behind the
// same methods.)
type Store struct {
	mu     sync.RWMutex
	orgs   map[string]map[string]*RunAgg
	killed map[string]map[string]bool // org → run → killed
}

func NewStore() *Store {
	return &Store{
		orgs:   make(map[string]map[string]*RunAgg),
		killed: make(map[string]map[string]bool),
	}
}

// Kill marks a run killed for an org; gateways poll this and hard-stop it.
func (s *Store) Kill(org, run string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// Ingest folds a batch of records into an org's aggregates.
func (s *Store) Ingest(org string, records []CallRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
