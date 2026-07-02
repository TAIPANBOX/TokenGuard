package main

import "testing"

func TestIngestAggregates(t *testing.T) {
	s := NewStore()
	s.Ingest("acme", []CallRecord{
		{RunID: "r1", Model: "claude", Decision: "allow", CostMicrousd: 1000, Step: 1, TsMillis: 100},
		{RunID: "r1", Model: "claude", Decision: "cache_hit", CostMicrousd: 0, Step: 2, TsMillis: 200},
		{RunID: "r2", Model: "gpt", Decision: "allow", CostMicrousd: 500, Step: 1, TsMillis: 150},
	})

	runs := s.Runs("acme")
	if len(runs) != 2 {
		t.Fatalf("want 2 runs, got %d", len(runs))
	}
	var r1 *RunAgg
	for i := range runs {
		if runs[i].RunID == "r1" {
			r1 = &runs[i]
		}
	}
	if r1 == nil {
		t.Fatal("r1 missing")
	}
	if r1.SpentMicrousd != 1000 {
		t.Errorf("r1 spent = %d, want 1000", r1.SpentMicrousd)
	}
	if r1.Calls != 2 {
		t.Errorf("r1 calls = %d, want 2", r1.Calls)
	}
	if r1.CacheHits != 1 {
		t.Errorf("r1 cache hits = %d, want 1", r1.CacheHits)
	}
	if r1.Steps != 2 {
		t.Errorf("r1 steps = %d, want 2", r1.Steps)
	}
	if r1.LastSeen != 200 {
		t.Errorf("r1 last seen = %d, want 200", r1.LastSeen)
	}

	sum := s.Summary("acme")
	if sum.Runs != 2 || sum.Calls != 3 || sum.SpentMicrousd != 1500 {
		t.Errorf("summary = %+v, want runs=2 calls=3 spent=1500", sum)
	}
}

func TestOrgsAreIsolated(t *testing.T) {
	s := NewStore()
	s.Ingest("acme", []CallRecord{{RunID: "r1", CostMicrousd: 100}})
	s.Ingest("globex", []CallRecord{{RunID: "r1", CostMicrousd: 999}})
	if s.Summary("acme").SpentMicrousd != 100 {
		t.Error("acme spend leaked")
	}
	if s.Summary("globex").SpentMicrousd != 999 {
		t.Error("globex spend leaked")
	}
	if len(s.Runs("unknown")) != 0 {
		t.Error("unknown org should have no runs")
	}
}
