# Tokenfuse — latency benchmarks

The headline claim is that Tokenfuse adds negligible latency to an agent's LLM
calls. This documents how that is measured and the numbers so far.

## What is measured

Tokenfuse's **added latency** is the work it does *around* the provider call —
not the provider's own response time (which dominates real requests and is
outside our control). The benchmark isolates two layers:

- **Part A — enforcement decision path.** The synchronous work on every call:
  cost estimate → policy evaluate → ledger reserve → ledger settle. This is the
  honest "added latency" figure.
- **Part B — full in-process request.** A request driven through the entire axum
  handler against a no-op (stub) upstream: routing, body parse, decision path,
  and response building. The stub returns instantly, so this is gateway
  overhead only, with zero network.

Both exclude the provider round trip.

## How to reproduce

```bash
cargo run -p tokenfuse-gateway --release --example bench
# tune sample counts:
BENCH_ITERS_A=200000 BENCH_ITERS_B=50000 cargo run -p tokenfuse-gateway --release --example bench
```

Timings use `std::time::Instant` per iteration (which itself costs tens of ns —
a small fixed tax that inflates the sub-microsecond Part A figures slightly).

## Results

Target: **p99 < 3 ms** added latency.

Measured on the author's machine (macOS, Apple silicon / arm64), `--release`,
single-threaded Tokio runtime, in-process (no network):

| Metric | Part A — decision path | Part B — full request (stub) |
|---|---|---|
| samples | 200,000 | 50,000 |
| mean | 0.24 µs | 4.32 µs |
| p50 | 0.21 µs | 4.25 µs |
| p90 | 0.29 µs | 4.38 µs |
| **p99** | **0.38 µs** | **4.67 µs** |
| p99.9 | 0.46 µs | 23.5 µs |
| max | 24.4 µs | 80.3 µs |

**Both meet the target by roughly three orders of magnitude:** the enforcement
decision costs well under a microsecond at p99, and a full request handled
in-process is under 5 µs at p99 versus the 3 ms budget.

## Caveats and next steps

- Single-machine, in-process numbers. A networked benchmark (client → gateway →
  provider over real sockets) will report end-to-end latency dominated by the
  provider; the *delta* against a direct call is the number to publish next.
- `Instant` overhead slightly inflates Part A; a batched-timing variant would
  tighten it, but the conclusion (sub-µs) is unaffected.
- Numbers will be re-measured on a Linux reference box before the public launch.
