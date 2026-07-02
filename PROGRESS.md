# TokenFuse — build progress

A living log of *where the code is*, so anyone (or a future session) can pick up
mid-stream. Planning docs live in [`docs/`](docs/); this file tracks implementation.

**Last updated:** 2026-07-02

## Current stage

**Phase 1 complete; Phase 2 core in place.** Budget enforcement, real SSE forwarding (~0.4 µs p99 overhead), loop detection, observability API, `tokenfuse top` TUI, Python SDK, and the Parquet trace sink with `tokenfuse sql`. The entire "90 seconds to wow" demo now runs on real code. Next (later phases): WASM policies, backtesting, hierarchical sub-agent budgets, the semantic cache, then Phase 4 (eBPF Radar, raft cluster, taint/agent-firewall, MCP gateway).

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
| Semantic cache (Ring 1.1) | ✅ done | `crates/core/cache.rs`: hard-partition + cosine similarity, entity-guard, length-ratio guard, TTL, FIFO eviction; pluggable `Embedder` (default `HashEmbedder`, ONNX later). Wired for non-streaming tool-free calls; `TOKENFUSE_CACHE=off\|shadow\|on`. On-hit serves `$0` with `x-fuse-saved-usd`. Verified live. |
| Backtesting (W6) | ✅ done | `crates/core/backtest.rs`: replay a candidate policy (per-run/per-step budget, max-steps) over the Parquet trace → runs/calls blocked + `$ saved`. `tokenfuse backtest --budget … --max-steps …`. Verified live (saved 50% on a demo trace). |
| Hierarchical sub-agent budgets | ✅ done | `X-Fuse-Parent-Run-Id` links a run to its parent; `reserve`/`settle` roll a sub-agent's spend up the ancestor chain and check every level (all-or-nothing). A child that fits its own budget is still blocked by a tighter parent → `402 budget_exceeded` naming the parent. |

## Test status

`cargo test --all` — 69 passing (core: 41, gateway: 28); Python SDK — 9 passing. `cargo clippy --all-targets` clean with `-D warnings`. Verified live: semantic cache hit for $0, `tokenfuse backtest` (50% saved on a demo trace), and sub-agent spend rolling up into a parent budget.

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

1. Latency benchmark (target p99 < 3 ms) — the first public number.
2. Drop guard so a client cancel mid-stream still settles the reservation.
3. Loop detection (Phase 2), then `tokenfuse top` TUI and the Python SDK.
