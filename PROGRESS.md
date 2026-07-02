# Tokenfuse — build progress

A living log of *where the code is*, so anyone (or a future session) can pick up
mid-stream. Planning docs live in [`docs/`](docs/); this file tracks implementation.

**Last updated:** 2026-07-02

## Current stage

**Phase 0 spike #1 landed: real forwarding + SSE passthrough.** The gateway now
forwards to a real upstream over HTTP (`reqwest`, rustls), streams the response
back chunk-by-chunk, parses token usage out of the stream (Anthropic + OpenAI
shapes), and settles the real cost at end-of-stream. Verified live against a mock
SSE upstream. Next: a latency benchmark (target p99 < 3 ms).

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
| Latency benchmark (p99 < 3 ms) | ⬜ next | Phase 0 spike #1 finale — the first public number |
| Client-cancel settle guard | ⬜ todo | Drop guard so a mid-stream disconnect still settles (noted TODO in code) |
| Loop detection | ⬜ todo | Phase 2 |
| `tokenfuse top` TUI | ⬜ todo | Phase 1 (W2) |
| Python SDK | ⬜ todo | Phase 1 |
| Parquet trace sink | ⬜ todo | Phase 2 (W8) |

## Test status

`cargo test --all` — 32 passing (core: 19, gateway: 13, incl. SSE usage-parser + streaming passthrough tests). `cargo clippy --all-targets` clean with `-D warnings`. Verified live: streaming request forwarded through the gateway to a real HTTP SSE upstream, all frames passed through, run settled.

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
