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

Storage is in-memory and concurrency-safe, keyed `org → run`. A durable backend
(Postgres/ClickHouse) is a drop-in behind the same `Store` methods. Org API keys
come from `TOKENFUSE_CLOUD_KEYS="key1:org1,key2:org2"` (dev default: `devkey`).

### Gateway side (`crates/gateway/src/cloudsink.rs`)

`CloudSink` is an `EventSink` that batches settled calls and POSTs them to the
control plane **asynchronously** (fire-and-forget — the request path never waits
on the network, and a failed push is dropped, not retried; the local Parquet
trace stays the source of truth). A periodic flush ships telemetry promptly even
below the batch size. It composes with the other sinks via `TeeSink`.

Enable it on any gateway:

```bash
TOKENFUSE_CLOUD_URL=http://control-plane:8080/v1/ingest \
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

## Not yet (follow-ups)

- **Kill from the cloud** — the dashboard is read-only today; propagating a kill
  back to the owning gateway needs a pull/stream channel (the gateway already has
  a local kill API + Slack button).
- **Central budgets / limits** managed in the Cloud and pushed to gateways.
- **Durable storage** (Postgres/ClickHouse) + retention.
- **Richer dashboard** — the roadmap's Next.js app (charts, alerts, org/RBAC);
  today's embedded page is the dependency-free v1.
- **Auth hardening** — per-org key rotation, TLS, rate limits.
