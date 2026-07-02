package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer() *server {
	return &server{store: NewStore(), keys: map[string]string{"devkey": "acme"}}
}

func TestIngestThenQueryWithAuth(t *testing.T) {
	srv := newTestServer()
	h := srv.routes()

	body, _ := json.Marshal(map[string]any{
		"records": []CallRecord{
			{RunID: "run-x", Model: "claude", Decision: "allow", CostMicrousd: 2500, Step: 1, TsMillis: 10},
		},
	})
	req := httptest.NewRequest("POST", "/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer devkey")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest status = %d, want 200", rec.Code)
	}

	req = httptest.NewRequest("GET", "/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer devkey")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("runs status = %d, want 200", rec.Code)
	}
	var runs []RunAgg
	if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].RunID != "run-x" || runs[0].SpentMicrousd != 2500 {
		t.Fatalf("unexpected runs: %+v", runs)
	}
}

func TestUnauthorizedRejected(t *testing.T) {
	srv := newTestServer()
	h := srv.routes()

	// No key.
	req := httptest.NewRequest("GET", "/v1/runs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-key status = %d, want 401", rec.Code)
	}

	// Wrong key.
	req = httptest.NewRequest("GET", "/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer nope")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong-key status = %d, want 401", rec.Code)
	}
}

func TestDashboardServed(t *testing.T) {
	srv := newTestServer()
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("TokenFuse Cloud")) {
		t.Error("dashboard HTML not served")
	}
}
