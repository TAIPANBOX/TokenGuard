# Networked benchmark harness

Reproduce TokenFuse's on-the-wire latency overhead **anywhere** — a laptop, any
Linux box, or GitHub Actions (`.github/workflows/bench.yml`, manual trigger).
Nothing here depends on a particular server.

## What it measures

`wrk` drives load (a) straight to a mock upstream and (b) through the gateway to
the same mock. The mock has a fixed think-time that cancels in the difference, so
the delta between the two runs is TokenFuse's own cost (accept connection, parse
body, run the decision path, forward, stream back, settle).

## Run it

```bash
# needs: cargo, python3, wrk
bench/run.sh
# tune load:
DUR=20 CONN=32 THREADS=4 bench/run.sh
```

## Files

| File | Role |
|---|---|
| `mock_upstream.py` | keep-alive HTTP/1.1 mock LLM on `127.0.0.1:9000` |
| `post_direct.lua` | wrk script — POST straight to the mock (baseline) |
| `post_gw.lua` | wrk script — POST through the gateway (managed run, huge budget) |
| `run.sh` | builds the release gateway, starts both, runs wrk, prints the delta |

The published numbers live in [`../BENCHMARKS.md`](../BENCHMARKS.md).
