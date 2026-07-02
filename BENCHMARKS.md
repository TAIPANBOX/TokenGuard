# TokenFuse — latency benchmarks

The headline claim is that TokenFuse adds negligible latency to an agent's LLM
calls. This documents how that is measured and the numbers so far.

## What is measured

TokenFuse's **added latency** is the work it does *around* the provider call —
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

## Networked benchmark (real sockets)

The delta above is in-process. To measure the gateway on the wire, we run
`wrk` against (a) the upstream directly and (b) through TokenFuse to the same
upstream, and take the difference. The upstream is a local keep-alive HTTP mock
with a fixed ~41 ms think-time, so the mock's latency cancels in the delta and
what remains is TokenFuse's own cost (accept the connection, parse the body, run
the decision path, forward, stream back, settle).

Reproduce anywhere with [`bench/run.sh`](bench/run.sh) (needs `cargo`, `python3`,
`wrk`) or in GitHub Actions via the manual **bench** workflow — no dedicated
server required. The figures below were measured on a **2 vCPU / 4 GB Ubuntu
24.04 box**, `--release`, `wrk -t2 -c16 -d15s`, gateway with cache/firewall/DLP
off (pure forwarding path):

| Path | p50 | p90 | p99 | req/s |
|---|---|---|---|---|
| Direct → mock upstream | 41.00 ms | 41.15 ms | 42.11 ms | 373 |
| Through TokenFuse → mock | 41.82 ms | 42.80 ms | 44.13 ms | 384 |
| **TokenFuse overhead** | **+0.82 ms** | **+1.65 ms** | **+2.0 ms** | — |

So even on a small 2-vCPU box, the release gateway adds **under a millisecond at
the median and ~2 ms at p99** — comfortably inside the 3 ms target, on top of a
provider call that in reality takes hundreds of ms to seconds. (A debug build on
the same box measured +1.8 ms p50 / +3.4 ms p99, i.e. release roughly halves it.)

## Caveats and next steps

- Single-machine, in-process numbers (Part A/B) plus the 2-vCPU networked delta
  above. A larger reference box would lift the absolute throughput ceiling; the
  *overhead delta* is the number that matters and it is already sub-3 ms p99.
- `Instant` overhead slightly inflates Part A; a batched-timing variant would
  tighten it, but the conclusion (sub-µs) is unaffected.
- Numbers will be re-measured on a Linux reference box before the public launch.
