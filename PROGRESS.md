# Tokenfuse — build progress

A living log of *where the code is*, so anyone (or a future session) can pick up
mid-stream. Planning docs live in [`docs/`](docs/); this file tracks implementation.

**Last updated:** 2026-07-02

## Current stage

**Phase 1 + Phase 2 core largely in place.** Budget enforcement, real SSE forwarding (~0.4 µs p99 overhead), loop detection, an observability API, and the `tokenfuse top` TUI. Remaining headline items: the Python SDK and the Parquet trace sink (`tokenfuse sql`).

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
| Python SDK | ⬜ todo | Phase 1 |
| Parquet trace sink | ⬜ todo | Phase 2 (W8) |

## Test status

`cargo test --all` — 49 passing (core: 27, gateway: 22). `cargo clippy --all-targets` clean with `-D warnings`. Verified live: SSE passthrough to a real upstream, and a looping request surfacing `x-fuse-would-block` in shadow mode.

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
