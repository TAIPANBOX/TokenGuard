# Tokenfuse — build progress

A living log of *where the code is*, so anyone (or a future session) can pick up
mid-stream. Planning docs live in [`docs/`](docs/); this file tracks implementation.

**Last updated:** 2026-07-02

## Current stage

**Phase 0 → Phase 1 foundation.** Building the domain core and the gateway
skeleton. No network forwarding yet — that is the next step (Phase 0 spike #1:
SSE passthrough).

## Status by component

| Component | State | Notes |
|---|---|---|
| Workspace + tooling | ✅ done | Cargo workspace, `rust-toolchain.toml`, rustfmt, GitHub Actions CI (fmt + clippy + test) |
| `crates/core` — money | ✅ done | Integer microdollar type, tested |
| `crates/core` — pricing | ✅ done | Per-Mtok prices, cache priced separately, overflow-safe, fallback for unknown models |
| `crates/core` — ledger | ✅ done | Reserve → settle, atomic under concurrency (test proves no oversubscription) |
| `crates/core` — policy | ✅ done | shadow/warn/enforce modes; per-step + max-steps rules; records "would block" in shadow |
| `crates/gateway` — HTTP skeleton | 🚧 in progress | axum server, health, request model, budget-enforcing handler with a provider trait + stub |
| Gateway — real SSE passthrough | ⬜ next | Phase 0 spike #1: stream to Anthropic/OpenAI, extract usage from final chunk |
| Loop detection | ⬜ todo | Phase 2 |
| `tokenfuse top` TUI | ⬜ todo | Phase 1 (W2) |
| Python SDK | ⬜ todo | Phase 1 |
| Parquet trace sink | ⬜ todo | Phase 2 (W8) |

## Test status

`cargo test --all` — core: 18 passing.

## How to run

```bash
cargo test --all        # run the suite
cargo run -p tokenfuse-gateway   # start the gateway (once the skeleton lands)
```

## Next steps

1. Land the gateway skeleton (handler + 402 budget contract) behind a provider trait.
2. Phase 0 spike #1: real streaming passthrough for Anthropic + OpenAI; extract usage.
3. Measure added latency (target p99 < 3 ms) — the first public benchmark.
