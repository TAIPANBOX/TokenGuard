package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

//go:embed index.html
var dashboardHTML []byte

// server holds the store and the api-key → org mapping.
type server struct {
	store *Store
	keys  map[string]string // api key → org
}

// parseKeys reads "key1:org1,key2:org2" into a map. Falls back to a dev key.
func parseKeys(spec string) map[string]string {
	keys := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if k, org, ok := strings.Cut(pair, ":"); ok {
			keys[strings.TrimSpace(k)] = strings.TrimSpace(org)
		}
	}
	if len(keys) == 0 {
		keys["devkey"] = "default"
	}
	return keys
}

// orgFor resolves the bearer token to an org, or "" if unauthorized.
func (s *server) orgFor(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" {
		return ""
	}
	return s.keys[token]
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
	org := s.orgFor(r)
	if org == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
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
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write(dashboardHTML)
	})
	return mux
}

func main() {
	addr := os.Getenv("PORT")
	if addr == "" {
		addr = "8080"
	}
	srv := &server{
		store: NewStore(),
		keys:  parseKeys(os.Getenv("TOKENFUSE_CLOUD_KEYS")),
	}
	log.Printf("tokenfuse cloud control plane listening on :%s (%d org key(s))", addr, len(srv.keys))
	if err := http.ListenAndServe(":"+addr, srv.routes()); err != nil {
		log.Fatal(err)
	}
}
