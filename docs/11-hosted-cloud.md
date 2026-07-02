# 11 · Hosted Cloud — a control plane across your gateways

> Status: **v1 implemented** (`cloud/control-plane` + gateway `CloudSink`). A Go
> control plane ingests telemetry from many gateways and serves an aggregated,
> per-organization view through an embedded web dashboard. Runs anywhere Docker
> runs — no dedicated server.

## Why

One gateway sees its own traffic. A team runs *many* gateways — per service, per
region, per developer laptop. TokenFuse Cloud is the **single pane of glass**:
every gateway pushes its settled-call telemetry to one control plane, which rolls
it up per organization so you can see, across the whole fleet, which runs are
burning money and where.

The gateway stays the enforcement point (fast, local, fail-open). The Cloud is
an **optional** aggregation layer on top — turning it off changes nothing about
enforcement.

## Shape

```
 gateway A ─┐  POST /v1/ingest {records:[…]}   (Bearer org-key)
 gateway B ─┼──────────────────────────────▶  ┌──────────────────────┐
 gateway C ─┘                                  │   control plane (Go) │
                                               │  org → run aggregates│
 browser ──── GET / (dashboard) ───────────▶  │  + embedded dashboard │
          ─── GET /v1/runs, /v1/summary ────▶  └──────────────────────┘
```

### Control plane (`cloud/control-plane`, Go, single static binary)

- **`POST /v1/ingest`** — a gateway pushes a batch of `CallRecord`s; the org is
  resolved from the `Authorization: Bearer <key>` header.
- **`GET /v1/runs`** — the caller org's per-run aggregates (spend, calls, cache
  hits, steps, last-seen).
- **`GET /v1/summary`** — org totals (runs, calls, spend).
- **`GET /`** — an embedded, dependency-free dashboard (vanilla JS; enter your
  org key, auto-refreshes every 3 s).
- **`GET /healthz`**.

Storage is concurrency-safe, keyed `org → run`, and **durable**: set
`TOKENFUSE_CLOUD_DATA=<path>` and the store loads a JSON snapshot on startup and
autosaves every 2 s (atomic tmp+rename), so it survives a restart. A SQL/columnar
backend (Postgres/ClickHouse) for scale + retention is a drop-in behind the same
`Store` methods. Org API keys
come from `TOKENFUSE_CLOUD_KEYS="key1:org1,key2:org2"` (dev default: `devkey`).

### Gateway side (`crates/gateway/src/cloudsink.rs`)

`CloudSink` is an `EventSink` that batches settled calls and POSTs them to the
control plane **asynchronously** (fire-and-forget — the request path never waits
on the network, and a failed push is dropped, not retried; the local Parquet
trace stays the source of truth). A periodic flush ships telemetry promptly even
below the batch size. It composes with the other sinks via `TeeSink`.

Enable it on any gateway:

```bash
TOKENFUSE_CLOUD_URL=http://control-plane:8080 \
TOKENFUSE_CLOUD_KEY=devkey \
  tokenfuse
```

## Run the whole stack

Both images are published to GHCR, so nothing builds locally:

```bash
cd cloud
docker compose up          # pulls ghcr.io/taipanbox/tokenfuse{,-control-plane}
```

Brings up the control plane (`:8080`, with the dashboard) and a gateway (`:4100`)
already wired to it. Open **http://localhost:8080**, enter `devkey`, send traffic
through `:4100`, and watch runs + spend appear live.

Run the control plane on its own anywhere:

```bash
docker run -p 8080:8080 -e TOKENFUSE_CLOUD_KEYS=devkey:acme \
  ghcr.io/taipanbox/tokenfuse-control-plane
```

## Verified end-to-end

Three managed calls through the gateway → the Cloud aggregated **3 runs / 3 calls
/ $0.0315**, per-run spend and last-seen correct; unauthenticated requests get
`401`. Control plane: `go test` (aggregation, org isolation, auth, dashboard).

## Kill from the cloud (implemented)

The dashboard has a **Kill** button per run. It calls `POST /v1/runs/{run}/kill`
on the control plane, which records the kill per org. Every gateway of that org
runs a **kill poller** (`cloudsink::spawn_kill_poller`) that fetches
`GET /v1/kills` every few seconds and applies each id to its local kill set —
so the run is hard-stopped (`402 killed`) across the whole fleet, not just on one
gateway. Enabled automatically whenever `TOKENFUSE_CLOUD_URL` + `_KEY` are set.

## Central budgets (implemented)

Set a run's budget from the Cloud and every gateway of the org enforces it,
overriding the client-supplied `x-fuse-budget-usd` header. The dashboard has a
per-run **Budget** button (`POST /v1/runs/{run}/budget {budget_usd}`); gateways
run a **budget poller** (`cloudsink::spawn_budget_poller`) that fetches
`GET /v1/budgets` and applies the overrides. So an operator can tighten (or
raise) a runaway run's cap centrally without touching the agent.

## Two dashboards

- **Embedded** (`GET /` on the control plane) — dependency-free vanilla JS, zero
  extra deploy. Good for a quick look.
- **Next.js app** (`cloud/dashboard`, App Router, TypeScript, static export) —
  the richer UI: summary cards, a spend-by-run chart, the runs table with kill +
  budget actions, auto-refresh. Talks to the control plane's API from the
  browser (a base-URL + org-key connect form); the control plane sends CORS
  headers so a cross-origin dashboard works. Built to static files and served by
  nginx — published as `ghcr.io/taipanbox/tokenfuse-dashboard` and wired into
  `docker compose` on `:3000`.

## Not yet (follow-ups)
- **SQL/columnar store** (Postgres/ClickHouse) for scale + retention (today: durable JSON snapshot).
- **Auth hardening** — per-org key rotation, TLS, rate limits; dashboard
  org/RBAC and alerts.
