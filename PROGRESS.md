# TokenFuse — build progress

A living log of *where the code is*, so anyone (or a future session) can pick up
mid-stream. Planning docs live in [`docs/`](docs/); this file tracks implementation.

**Last updated:** 2026-07-03 (mobile companion: B2 — live data from the control plane on the Runs screen)

## Current stage

**Phases 1–4 implemented; v0.1.0 released.** The full request path (budget
enforcement with `TOKENFUSE_MODE=shadow|warn|enforce`, real SSE forwarding at
~0.4 µs p99 in-process / ~1–2 ms on the wire, loop detection, hierarchical
sub-agent budgets), the intelligence/ops layer (semantic cache, WASM policies,
backtesting, Parquet + `tokenfuse sql`, OTel, `tokenfuse top`, Python SDK), the
security packs (agent firewall/taint, DLP, MCP scanner), eBPF Radar, the
**HA raft cluster** (in-process + HTTP transport, hierarchical + durable redb
storage, runtime membership changes), and the **hosted Cloud** (Go control plane
+ dashboard, gateway telemetry, fleet-wide kill-switch).

Shipped as container images on GHCR: `tokenfuse`, `tokenfuse:cluster`,
`tokenfuse-control-plane`, `tokenfuse-dashboard` — runs anywhere, no dedicated
server. The optional-hardening backlog is now also cleared: **cloud RBAC +
budget alerts**, **cluster mutual TLS**, and a **security-hardening pass**
(request-body limits, upstream connect timeout, a `cargo audit` CI gate, and a
documented threat model in [docs/13](docs/13-security-hardening.md)). What's left
is genuinely optional scale/ops work (a SQL/columnar Cloud store; automated cert
rotation) and a formal third-party audit — none of it a blocker.

## Status by component

| Component | State | Notes |
|---|---|---|
| Workspace + tooling | ✅ done | Cargo workspace, `rust-toolchain.toml`, rustfmt, GitHub Actions CI (fmt + clippy + test) |
| `crates/core` — money | ✅ done | Integer microdollar type, tested |
| `crates/core` — pricing | ✅ done | Per-Mtok prices, cache priced separately, overflow-safe, fallback for unknown models |
| `crates/core` — ledger | ✅ done | Reserve → settle, atomic under concurrency (test proves no oversubscription) |
| `crates/core` — policy | ✅ done | shadow/warn/enforce modes; per-step + max-steps rules; records "would block" in shadow |
| `crates/gateway` — HTTP skeleton | ✅ done | axum server, `/healthz` + `/v1/messages`, estimate → enforce → forward → settle, 402 budget contract, shadow/warn/enforce, unmanaged pass-through, `x-fuse-*` response headers |
| Gateway — real forwarding + SSE passthrough | ✅ done | `HttpProvider` (reqwest/rustls) streams chunks through; `UsageParser` extracts usage from Anthropic + OpenAI SSE and non-stream JSON; settle at end-of-stream. `TOKENFUSE_UPSTREAM` selects real vs stub. Verified live. |
| Latency benchmark (p99 < 3 ms) | ✅ done | `examples/bench.rs`; decision path **p99 0.38 µs**, full in-process request **p99 4.67 µs** — ~3 orders under target. See BENCHMARKS.md |
| Client-cancel settle guard | ✅ done | `SettleGuard` settles on Drop — client cancel or upstream error mid-stream never leaks a reservation |
| Loop detection | ✅ done | `crates/core/loops.rs`: identical-tool-call + ping-pong (from the request's own message history) + context-growth (per-run tracker). Wired in: enforce → `402 loop_detected`, shadow/warn → `x-fuse-would-block` header. Verified live. |
| Observability API | ✅ done | `GET /v1/runs` (list runs, spend, %, killed) + `POST /v1/runs/{id}/kill` (hard stop, any mode). Backs the TUI + Slack kill-button |
| `tokenfuse top` TUI | ✅ done | ratatui / crossterm live view: runs table, spend/budget bars, %, steps, select + kill (`k`), refresh, quit. `tokenfuse top` subcommand; polls `/v1/runs` |
| Python SDK | ✅ done | `sdk/python` — dependency-free helpers: `run_headers`, `gateway_url`, and typed exceptions (`BudgetExceeded`/`LoopDetected`/`PolicyViolation`/`Killed`) via `raise_for_fuse`/`check_response`. Own CI job (pytest, 9 tests) |
| Parquet trace sink (`tokenfuse sql`) | ✅ done | `sink.rs`: settled calls → rotating Parquet segments (opt-in via `TOKENFUSE_DATA_DIR`; `NullSink` default). `sqlq.rs` + `tokenfuse sql "…"` query the trace with DataFusion. Verified live end-to-end. |
| Semantic cache (Ring 1.1) | ✅ done | `crates/core/cache.rs`: hard-partition + cosine similarity, entity-guard, length-ratio guard, TTL, FIFO eviction; pluggable `Embedder`. Wired for non-streaming tool-free calls; `TOKENFUSE_CACHE=off\|shadow\|on`. On-hit serves `$0` with `x-fuse-saved-usd`. Verified live. |
| Cache ONNX embedder | ✅ done | Optional `onnx` cargo feature: real multilingual-e5-small embeddings via `fastembed`/ort (`TOKENFUSE_CACHE_EMBEDDER=onnx`). Default stays `HashEmbedder` (dep-free); CI builds default only. Compiles + clippy-clean with the feature. |
| Agent firewall / taint (Ring 3.1) | ✅ done | `crates/core/taint.rs`: tools → labels/capabilities, monotonic per-run taint, rule eval. Gateway accumulates taint from `X-Fuse-Taint` + tool history; a model tool call needing a capability denied under the run's taint → `403 taint_blocked` (enforce) or `x-fuse-taint` note (shadow). `TOKENFUSE_FIREWALL=off\|shadow\|enforce`. SDK gains `TaintBlocked`. |
| DLP secret scanning (Ring 3.2) | ✅ done | `crates/core/dlp.rs`: pattern detectors (AWS/OpenAI/Anthropic/Google/GitHub/Slack keys, JWT, private key, Bearer) with overlap-dedup + redaction. Gateway scans the outgoing prompt; `TOKENFUSE_DLP=off\|shadow\|mask\|block` → `403 dlp_blocked`, masks to `[REDACTED:kind]`, or flags via `x-fuse-dlp`. SDK gains `DlpBlocked`. Verified live. |
| OTel export (W9) | ✅ done | `gateway/otel.rs`: one OTLP/JSON span per call over HTTP (`gen_ai.*` + `tokenfuse.*` attrs; one trace per run) to `TOKENFUSE_OTLP_ENDPOINT`. `TeeSink` composes it with the Parquet trace. No heavy OTel deps; default off. Verified live against a mock collector. |
| WASM policies (W5) | ✅ done | Optional `wasm` cargo feature: custom policy modules run in a `wasmtime` sandbox with a fuel limit. Scalar ABI `evaluate(est,spent,budget,step,taint_bits)->0/1/2`; block → `402 wasm_policy`. `TOKENFUSE_WASM_POLICY=<path>` (.wasm/.wat). Fail-open. Default build excludes it; compiled/tested/clippy-clean + verified live with a `.wat` policy. |
| MCP credential-broker | ✅ done | `tokenfuse mcp-broker` — a JSON-RPC proxy the agent's MCP client points at. On `tools/call` it injects `{{secret:NAME}}` handles from a vault with real secrets **at the boundary** (secret never in the LLM prompt/trace/agent memory); on `tools/list` it runs the poisoning scanner (`off\|warn\|block`). Pure core in `tokenfuse-core::secretbroker` (`SecretVault` + `inject_secrets`, unit-tested); gateway `mcpbroker.rs` + `tests/mcp_broker.rs` (handle→real secret reaches a stub upstream; poisoned list blocked). Config: `TOKENFUSE_MCP_{UPSTREAM,SECRETS,SCAN,ADDR}`. |
| MCP broker — DLP + redaction + stdio | ✅ done | DLP on outgoing args + **redaction of secrets in responses** (`TOKENFUSE_MCP_DLP`), rug-pull lockfile (`TOKENFUSE_MCP_LOCK`), and a **stdio** transport (`mcp-broker --stdio`, newline-delimited JSON-RPC, logs to stderr) sharing `process()` with HTTP. Tests: dlp-block, rug-pull-block, response-redaction. |
| MCP scanner + lockfile (Ring 3.3 / S6) | ✅ done | `crates/core/mcp.rs`: parse `tools/list`, fingerprint tools, scan descriptions for poisoning (injection phrases, zero-width chars), and diff vs a lockfile → **rug-pull** detection. `tokenfuse mcp-scan <tools.json> [--lock f] [--write-lock]`. Verified live. (Live credential-broker proxy = follow-up, needs MCP transport.) |
| eBPF Radar (W1) | ✅ done | `crates/radar` (+ nested `radar-ebpf`, aya): eBPF on `sys_enter_connect` reports every outbound TCP connection (pid/comm/ip:port) and flags LLM providers + local Ollama/vLLM — **zero app config**. Linux-only; excluded from default workspace, own CI job. **Built & run live on a Hetzner Ubuntu 24.04 VPS (kernel 7.0)** — flagged real Anthropic/OpenAI + Ollama traffic, ignored non-LLM. |
| Backtesting (W6) | ✅ done | `crates/core/backtest.rs`: replay a candidate policy (per-run/per-step budget, max-steps) over the Parquet trace → runs/calls blocked + `$ saved`. `tokenfuse backtest --budget … --max-steps …`. Verified live (saved 50% on a demo trace). |
| Hierarchical sub-agent budgets | ✅ done | `X-Fuse-Parent-Run-Id` links a run to its parent; `reserve`/`settle` roll a sub-agent's spend up the ancestor chain and check every level (all-or-nothing). A child that fits its own budget is still blocked by a tighter parent → `402 budget_exceeded` naming the parent. |
| HA cluster / raft (W7) | ✅ done | `crates/cluster` (openraft, storage-v2): the budget ledger replicated across N nodes. `Reserve`/`Settle` are raft log entries, so the affordability check is **linearized** — no cross-node double-spend — and budgets survive a node crash (quorum commit). Reference in-memory storage. `cargo run -p tokenfuse-cluster` demos a 3-node cluster: over-budget reserve denied by consensus, spend read back from a **follower**. Excluded from default workspace; own CI job. |
| Cluster — HTTP transport | ✅ done | `net_http.rs` (HTTP `RaftNetwork`, JSON-over-HTTP via openraft `serde`) + `server.rs` (axum per-node server: `/raft/*` peer RPCs, `/mgmt/init`, `/mgmt/metrics`, `/api/write`, `/api/read/{run}`) → clusters form **across processes/machines**. `tokenfuse-cluster serve --id N --http … --peers …` runs one node; `demo-http` spins 3 over real sockets. 2 HTTP integration tests (form over `:0`, deny over-budget by consensus, follower read; leader-forward). |
| Gateway↔cluster integration | ✅ done | Async `LedgerBackend` trait (`ledger_backend.rs`): `LocalLedger` (default, wraps in-process `Ledger` — no behavior change) or `RaftLedger` (`raft_ledger.rs`, feature `cluster`) which co-locates a raft node so budgets are enforced by consensus across gateways. Hot path refactored sync→async (`open`/`reserve`/`snapshot` await; `settle` stays sync fire-and-forget so `SettleGuard::drop` is unchanged). Configured via `TOKENFUSE_CLUSTER_*`; fails open on consensus outage. Gated tests (`tests/cluster_backend.rs`): enforce/deny/settle + parent-budget. Default gateway 35 tests still green. |
| Cluster — auth + TLS | ✅ done | **Auth:** `TOKENFUSE_CLUSTER_TOKEN` shared secret — all endpoints except `/healthz` require `Authorization: Bearer <token>` (axum middleware), threaded through peer RPCs, admin/app `Client`, leader-forwarded writes, and the gateway. **TLS:** native HTTPS via rustls/axum-server (`TOKENFUSE_CLUSTER_TLS_CERT`/`_KEY` or `serve --tls-cert/--tls-key`); rustls client with optional self-signed CA trust (`TOKENFUSE_CLUSTER_CA`). Both off by default (dev). Tests `cluster_token_secures_endpoints` + `serves_over_https_with_token`. |
| Cluster — membership changes | ✅ done | Nodes join/leave a running cluster: `/mgmt/init-single`, `/mgmt/add-learner {id,addr}`, `/mgmt/change-membership [ids]` (+ `HttpNode` + `Client` methods). A runtime-added node's address travels in the replicated membership (`BasicNode.addr`), so the HTTP network reaches it (falls back to the bootstrap peer map). Test `membership_grow_add_learner_then_promote` (single voter → add learner over HTTP → promote → write replicates to the new node). |
| Cluster — durable storage (redb) | ✅ done | `crates/cluster/src/redbstore.rs`: `RedbLogStore` + `RedbStateMachineStore` implement the openraft storage-v2 traits over [redb](https://docs.rs/redb) (embedded, pure-Rust, ACID; one file per node, no C deps). Writes commit before returning, so budgets survive a **process restart**, not just a node crash. `HttpNode::build_durable(id, peers, dir)`; gateway env `TOKENFUSE_CLUSTER_DATA_DIR`. Read side shared via a `LedgerReader` trait (in-memory or redb). Test `budgets_survive_a_restart` (write → drop → reopen same dir → still there). In-memory backend remains the default. |
| Cluster — hierarchical budgets + steps | ✅ done | The replicated SM models `parent` chains and per-run `steps`, mirroring `tokenfuse-core::Ledger`: `Reserve` fits the run **and every ancestor** (all-or-nothing), rolls up the chain, and names the `blocked_run` on denial; `Settle` rolls up too. So sub-agent budgets (`X-Fuse-Parent-Run-Id`) are enforced in cluster mode, not just locally. In-process test `subagent_reserve_rolls_up_and_parent_budget_blocks` + gateway `raft_backend_enforces_parent_budget`. |
| Container image + GHCR | ✅ done | Multi-stage `Dockerfile` (rust build → debian-slim runtime, non-root, CA roots) + `.github/workflows/release.yml` publishes to `ghcr.io/taipanbox/tokenfuse` on tags / manual dispatch via the built-in `GITHUB_TOKEN`. `docker run -p 4100:4100 ghcr.io/taipanbox/tokenfuse` runs anywhere — **no dedicated server**. Dockerfile takes `--build-arg FEATURES=…`; the release matrix also publishes **`tokenfuse:cluster`** (built with `--features cluster` — raft HA + durable redb baked in) and `tokenfuse-control-plane`. |
| Portable benchmark harness | ✅ done | `bench/` (mock upstream, wrk scripts, `run.sh`, README) reproduces the networked latency benchmark on any Linux box; `.github/workflows/bench.yml` runs it in GitHub Actions (manual). Rescued the ad-hoc VPS files into the repo. Radar's live output preserved at `crates/radar/sample-output.txt`. |
| `TOKENFUSE_MODE` enforcement toggle | ✅ done | Binary reads `TOKENFUSE_MODE=shadow\|warn\|enforce` at startup (default shadow). The Docker image can now actually block (402), not just observe. Verified live on a VPS: enforce → 402 over budget. |
| Hosted Cloud v1 (control plane + dashboard) | ✅ done | `crates/cloud` (Rust/axum, single static binary — **ported from Go**, ADR-7, PR A1–A5): ingests gateway telemetry (`POST /v1/ingest`, Bearer org-key), serves per-org aggregates (`/v1/runs`, `/v1/summary`), mutations (`kill`/`budget` admin-only) + poll endpoints (`/v1/kills`, `/v1/budgets`), `/v1/alerts`, and an embedded live dashboard (`/`). RBAC (`key:org[:role]`, admin/viewer→403), durable JSON snapshot + autosave (`TOKENFUSE_CLOUD_DATA`), CORS. Covered by `cargo test --all` (21 tests); image `tokenfuse-control-plane` from `crates/cloud/Dockerfile`. The Go plane was deleted in the cutover. |
| Cloud Next.js dashboard | ✅ done | `cloud/dashboard` (Next.js App Router, TS, static export): connect form (base URL + org key), summary cards, spend-by-run chart, runs table with **Kill** + **Budget** actions, 3 s auto-refresh. Talks to the control plane from the browser; control plane sends CORS headers. Built to static files, served by nginx → `ghcr.io/taipanbox/tokenfuse-dashboard`, in `docker compose` on `:3000`. Own CI job `dashboard` (npm ci + next build). The embedded vanilla-JS dashboard remains for a zero-deploy quick look. |
| Cloud durable store | ✅ done | Control-plane state (org→run aggregates, kills, budgets) persists across restarts: `TOKENFUSE_CLOUD_DATA=<path>` loads a JSON snapshot on startup and autosaves every 2 s (atomic tmp+rename), zero external deps. Distroless image ships a non-root-owned `/data`; compose mounts a `cloud-data` volume. `TestPersistenceRoundTrip`. SQL/columnar (Postgres/ClickHouse) for scale is a drop-in behind the same `Store`. |
| Cloud central budgets | ✅ done | Control plane: `POST /v1/runs/{run}/budget {budget_usd}` + `GET /v1/budgets`; dashboard **Budget** button per run. Gateway: `cloudsink::spawn_budget_poller` fetches `/v1/budgets` every 3 s → `AppState.cloud_budgets`; `proxy` `open_run` uses the cloud budget over the `x-fuse-budget-usd` header. Verified e2e: header `$999999` + cloud `$0.0001` → 402. Lets an operator tighten a runaway cap centrally. |
| Cloud kill-switch (kill from cloud) | ✅ done | Control plane: `POST /v1/runs/{run}/kill` + `GET /v1/kills` (per-org), `RunAgg.killed`; dashboard gains a per-run **Kill** button. Gateway: `cloudsink::spawn_kill_poller` fetches `/v1/kills` every 3 s and applies each id to the local kill set → the run is hard-stopped (`402 killed`) across the whole org fleet. `TOKENFUSE_CLOUD_URL` is now a base URL. Verified e2e: kill in cloud → gateway returns 402 `killed`. |
| Gateway → Cloud telemetry (`CloudSink`) | ✅ done | `crates/gateway/src/cloudsink.rs`: batches settled `CallRecord`s and POSTs them async (fire-and-forget, periodic flush) to the control plane; `TOKENFUSE_CLOUD_URL` + `TOKENFUSE_CLOUD_KEY`, composed via `TeeSink`. `CallRecord` gained `Serialize`. Verified end-to-end: 3 calls → Cloud shows 3 runs / $0.0315. `cloud/docker-compose.yml` runs the whole stack (`docker compose up`). |
| Cloud RBAC + budget alerts | ✅ done | Control plane keys are now `key:org[:role]` with roles `admin` (default) / `viewer`; reads + ingest work for any valid key, **mutations** (kill, set-budget) require `admin` → `403` for a viewer, `401` for an unknown key. `GET /v1/alerts` flags runs that spent ≥ a fraction of their central budget (`TOKENFUSE_CLOUD_ALERT_PCT`, default 0.8, or `?pct=`); the embedded dashboard shows an alert count + ⚠ on near-budget rows. Go tests: viewer-403, role parsing, alert detection. (#51) |
| Cluster mutual TLS | ✅ done | On top of server TLS + bearer token: `TOKENFUSE_CLUSTER_MTLS_CA` makes a node **require** a CA-signed client cert from every peer (rustls `WebPkiClientVerifier`, `server::serve_mtls`); each node presents its own cert via `TOKENFUSE_CLUSTER_CLIENT_CERT/_KEY` (reqwest `Identity`). Cryptographic peer auth — an unauthenticated TCP client can't complete the handshake. Also `serve --mtls-ca …`. Test `serves_over_mutual_tls`. (#52) |
| Security-hardening pass | ✅ done | Request-body size limit on the gateway + MCP-broker routers (`DefaultBodyLimit`, `TOKENFUSE_MAX_BODY_BYTES`, default 16 MiB); upstream **connect** timeout (`TOKENFUSE_UPSTREAM_CONNECT_TIMEOUT_SECS`, no whole-request timeout so SSE streams aren't cut); a `cargo audit` CI job (workspace + cluster); optional **wasmtime 27→43** clearing 15 advisories (2 critical, `wasm` feature is off by default). Threat model + trust boundaries + the deliberate fail-open rationale documented in [docs/13](docs/13-security-hardening.md). (#53) |
| Published to package registries | ✅ done | The `tokenfuse` name is claimed and **published** on all three registries (v0.3.0): **npm** `npm install tokenfuse` (`sdk/js`), **crates.io** `cargo add tokenfuse` (umbrella crate `crates/tokenfuse`), **PyPI** `pip install tokenfuse-sdk` (`sdk/python`; the plain `tokenfuse` name is blocked on PyPI by the unrelated existing `token-fuse`, so the distribution is `tokenfuse-sdk` while the import stays `import tokenfuse`). Publish tokens were revoked after use. Domain `tokenfuse.dev` is the only remaining name to claim (owner action). |
| Mobile companion (TokenFuse Pocket, iOS) | 🔨 in progress | Native SwiftUI command center: live burn rate in the Dynamic Island, push on anomalies, **Face-ID kill / budget with Secure-Enclave-signed mutations**. Full execution plan (ADRs, wire protocols, PR-by-PR breakdown) in [docs/14-mobile-companion.md](docs/14-mobile-companion.md). Phase A ports the control plane Go→Rust (`crates/cloud`, ADR-7) and adds pairing / signed mutations / SSE / OpenAPI / APNs — **no Xcode required**; Phase B is the iOS app; Phase C ships to the App Store. Dev host verified ready 2026-07-03 (Xcode 26.6, iOS 26.5 SDK + simulators, Swift 6.3.3, XcodeGen 2.45.4). **Done:** A1 (plan + ADR-7, #61); A2 (`crates/cloud` skeleton — health + ingest + in-memory store port, #62); A3 (read endpoints `/v1/runs` `/v1/summary` `/v1/alerts` + durable JSON snapshot/autosave + CORS, restart-persistence verified live, #63); A4 (mutations `kill`/`budget` + `/v1/kills` `/v1/budgets` + RBAC admin-only 403/viewer, #64); A5 (**cutover** — dashboard served from `crates/cloud`, new Rust Dockerfile, release.yml/compose/CI swapped, **Go `cloud/control-plane` deleted**, docs updated, 21 tests, #65 — **Go is gone from the project**). A6 (OpenAPI 3.1 via utoipa — `GET /openapi.json` + `--openapi` dump + CI `openapi` job validates/uploads; #66); A7 (**live data**: SSE `/v1/stream` + burn-rate `/v1/series`; #67); A8 (**hardware-backed kill switch**: device pairing + Secure-Enclave **ES256-signed** mutations; #68); A9 (**APNs push pipeline**: store events → alert pushes + Live Activity updates via a swappable `PushSender`, per-(org,run,reason) dedup; signed device-registration endpoints; real APNs sender behind the `apns` feature — reqwest HTTP/2 + ES256 provider JWT; 42 tests; #69). **✅ PHASE A COMPLETE** — the full backend for TokenFuse Pocket (Go→Rust port, OpenAPI, live SSE+series, Enclave-signed mutations, push). **Phase B in progress:** design system locked ([docs/16](docs/16-design-system.md), the "fuse" identity across iPhone/Watch/Web; mockups in `mobile/design/`); **B1 (#70)** — SwiftUI scaffold (XcodeGen, Swift 6, iOS 17.2), `DesignSystem`/`Fuse`/`RunsView`, CI `ios` job; **B2 (#71)** — **live data**: typed `APIClient` (mirrors committed `openapi.json`), `@Observable RunsStore` (runs+summary+budgets joined into `RunDisplay`), Connect/Root screens, reworked `RunsView` (spent-today hero, pull-to-refresh, states); URLProtocol-mocked tests, CI `ios` now build+test — **verified live against a real Rust plane on the simulator**. **Next: B3** (pairing QR + Secure-Enclave-signed kill/budget from the phone; org key → paired device token in Keychain). Simulator + free Apple ID suffice; paid Apple Developer only at device-push / TestFlight. |

## Test status

`cargo test --all` — 100 passing (core: 60, gateway: 40); Python SDK — 11 passing; **`tokenfuse-cluster` — 12 integration tests** on live raft clusters (in-process + over HTTP sockets, incl. token-auth, HTTPS, **mTLS**, membership, linearizable reads, redb durability; excluded crate, own CI job). `cargo clippy --all-targets --all-features` clean with `-D warnings` across the workspace, radar, and cluster. **`cargo audit` — 0 vulnerabilities** (own CI `security` job; 3 transitive unmaintained warnings only). **eBPF Radar built + run live on a Linux VPS** (flags real LLM traffic). **Networked benchmark (release, 2-vCPU VPS):** the gateway adds **+0.82 ms p50 / +2.0 ms p99** over a direct socket to the upstream (see BENCHMARKS.md). Verified live: mcp-scan poisoning/rug-pull; OTLP export; DLP block; WASM policy block; enforce 402; durable-HA restart persistence; full Cloud stack.

## How to run

```bash
cargo test --all        # run the suite
cargo run -p tokenfuse-gateway   # start the gateway (once the skeleton lands)
```

## How to run against a real provider

```bash
TOKENFUSE_UPSTREAM=https://api.anthropic.com/v1/messages cargo run -p tokenfuse-gateway
# then point your agent at http://127.0.0.1:4100 and pass your provider key through
```

## Next steps

The roadmap (phases 1–4) is implemented and shipped in **v0.2.0**, and the
optional-hardening backlog that followed it is now cleared too:

- ✅ **mTLS / client-cert** auth between nodes (#52)
- ✅ **Durable Cloud store** — JSON snapshot + autosave (#49); a SQL/columnar
  backend for scale is a drop-in behind the same `Store` (see below)
- ✅ **Dashboard RBAC + alerting** (#51)
- ✅ **MCP broker** response redaction + stdio transport (#50)
- ✅ **Security-hardening pass** — body limits, connect timeout, `cargo audit`
  gate, threat model (#53)
- ✅ **Published to npm / crates.io / PyPI** — the `tokenfuse` name is claimed on
  all three (PyPI as `tokenfuse-sdk`); publish tokens revoked afterwards.

What genuinely remains is deferred scale/ops work, not a blocker for a young
project:

1. **SQL/columnar Cloud store** (Postgres/ClickHouse) for scale + long retention,
   behind the existing `Store` interface.
2. **Automated cert rotation / SPIFFE-style identity** for the cluster mesh
   (today: static PEM files; mTLS itself is done).
3. An **independent third-party security audit** before any "GA" claim — the
   in-house hardening pass ([docs/13](docs/13-security-hardening.md)) is explicit
   that it is *not* a substitute for one.
