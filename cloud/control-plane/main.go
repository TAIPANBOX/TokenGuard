package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed index.html
var dashboardHTML []byte

// principal is who a key belongs to: an org and a role (admin｜viewer).
type principal struct {
	org  string
	role string
}

// server holds the store and the api-key → principal mapping.
type server struct {
	store    *Store
	keys     map[string]principal
	alertPct float64 // budget fraction at which a run is flagged (default 0.8)
}

// parseKeys reads "key:org[:role],…" (role defaults to admin). Falls back to a
// dev key. A `viewer` role can read but not kill or set budgets.
func parseKeys(spec string) map[string]principal {
	keys := map[string]principal{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.Split(pair, ":")
		if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		role := "admin"
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
			role = strings.TrimSpace(parts[2])
		}
		keys[strings.TrimSpace(parts[0])] = principal{org: strings.TrimSpace(parts[1]), role: role}
	}
	if len(keys) == 0 {
		keys["devkey"] = principal{org: "default", role: "admin"}
	}
	return keys
}

func (s *server) principalFor(r *http.Request) (principal, bool) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		return principal{}, false
	}
	p, ok := s.keys[token]
	return p, ok
}

// orgFor resolves the bearer token to an org (any role), or "" if unauthorized.
func (s *server) orgFor(r *http.Request) string {
	if p, ok := s.principalFor(r); ok {
		return p.org
	}
	return ""
}

// adminOrg authorizes a mutation: returns the org only for an admin principal,
// writing the right status otherwise.
func (s *server) adminOrg(w http.ResponseWriter, r *http.Request) (string, bool) {
	p, ok := s.principalFor(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return "", false
	}
	if p.role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return "", false
	}
	return p.org, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ingest: POST /v1/ingest  {"records":[...]}  (gateway → cloud)
func (s *server) ingest(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	if org == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return
	}
	var body struct {
		Records []CallRecord `json:"records"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	s.store.Ingest(org, body.Records)
	writeJSON(w, http.StatusOK, map[string]int{"accepted": len(body.Records)})
}

// runs: GET /v1/runs  → aggregated runs for the caller's org
func (s *server) runs(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	if org == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return
	}
	writeJSON(w, http.StatusOK, s.store.Runs(org))
}

// summary: GET /v1/summary → org totals
func (s *server) summary(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	if org == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return
	}
	writeJSON(w, http.StatusOK, s.store.Summary(org))
}

// kill: POST /v1/runs/{run}/kill → mark a run killed (operator / dashboard)
func (s *server) kill(w http.ResponseWriter, r *http.Request) {
	org, ok := s.adminOrg(w, r)
	if !ok {
		return
	}
	run := r.PathValue("run")
	s.store.Kill(org, run)
	writeJSON(w, http.StatusOK, map[string]string{"killed": run})
}

// kills: GET /v1/kills → run ids this org has killed (gateways poll this)
func (s *server) kills(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	if org == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return
	}
	writeJSON(w, http.StatusOK, s.store.Kills(org))
}

// setBudget: POST /v1/runs/{run}/budget {"budget_usd": 1.5}
func (s *server) setBudget(w http.ResponseWriter, r *http.Request) {
	org, ok := s.adminOrg(w, r)
	if !ok {
		return
	}
	var body struct {
		BudgetUSD float64 `json:"budget_usd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	micros := int64(body.BudgetUSD * 1e6)
	s.store.SetBudget(org, r.PathValue("run"), micros)
	writeJSON(w, http.StatusOK, map[string]any{"run": r.PathValue("run"), "budget_micros": micros})
}

// budgets: GET /v1/budgets → {run: budget_micros} (gateways poll this)
func (s *server) budgets(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	if org == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return
	}
	writeJSON(w, http.StatusOK, s.store.Budgets(org))
}

// alerts: GET /v1/alerts → runs at or above the alert threshold of their budget.
// The threshold defaults to 0.8 and can be overridden with ?pct= (0..1).
func (s *server) alerts(w http.ResponseWriter, r *http.Request) {
	org := s.orgFor(r)
	if org == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return
	}
	pct := s.alertPct
	if q := r.URL.Query().Get("pct"); q != "" {
		if v, err := strconv.ParseFloat(q, 64); err == nil && v > 0 && v <= 1 {
			pct = v
		}
	}
	writeJSON(w, http.StatusOK, s.store.Alerts(org, pct))
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /v1/ingest", s.ingest)
	mux.HandleFunc("GET /v1/runs", s.runs)
	mux.HandleFunc("GET /v1/summary", s.summary)
	mux.HandleFunc("POST /v1/runs/{run}/kill", s.kill)
	mux.HandleFunc("GET /v1/kills", s.kills)
	mux.HandleFunc("POST /v1/runs/{run}/budget", s.setBudget)
	mux.HandleFunc("GET /v1/budgets", s.budgets)
	mux.HandleFunc("GET /v1/alerts", s.alerts)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write(dashboardHTML)
	})
	return cors(mux)
}

// cors allows the standalone (Next.js) dashboard, served from another origin, to
// call the API from the browser. Auth is a Bearer token (not cookies), so a
// wildcard origin is safe.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	addr := os.Getenv("PORT")
	if addr == "" {
		addr = "8080"
	}
	srv := &server{
		store:    NewStore(),
		keys:     parseKeys(os.Getenv("TOKENFUSE_CLOUD_KEYS")),
		alertPct: 0.8,
	}
	if v := os.Getenv("TOKENFUSE_CLOUD_ALERT_PCT"); v != "" {
		if p, err := strconv.ParseFloat(v, 64); err == nil && p > 0 && p <= 1 {
			srv.alertPct = p
		}
	}
	// Durable persistence: load a snapshot and autosave every 2s (TOKENFUSE_CLOUD_DATA).
	if data := os.Getenv("TOKENFUSE_CLOUD_DATA"); data != "" {
		if err := srv.store.Load(data); err != nil {
			log.Printf("could not load snapshot %s: %v", data, err)
		}
		go srv.store.Autosave(data, 2*time.Second)
		log.Printf("persisting state to %s", data)
	}
	log.Printf("tokenfuse cloud control plane listening on :%s (%d org key(s))", addr, len(srv.keys))
	if err := http.ListenAndServe(":"+addr, srv.routes()); err != nil {
		log.Fatal(err)
	}
}
