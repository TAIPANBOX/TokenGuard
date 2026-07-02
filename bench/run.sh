#!/usr/bin/env bash
#
# Reproduce the networked latency benchmark on ANY Linux box (or in CI) — no
# personal server required. Measures TokenFuse's added latency by running wrk
# (a) straight to a mock upstream and (b) through the gateway to the same mock,
# then diffing the two. The mock's fixed think-time cancels in the delta.
#
# Requirements: cargo, python3, wrk.
# Usage: bench/run.sh          (defaults: 15s, 16 conns, 2 threads)
#        DUR=20 CONN=32 THREADS=4 bench/run.sh
set -euo pipefail

DUR=${DUR:-15}
CONN=${CONN:-16}
THREADS=${THREADS:-2}
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

command -v wrk >/dev/null || { echo "error: wrk not installed"; exit 1; }

echo "building release gateway…"
cargo build --release -p tokenfuse-gateway --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/release/tokenfuse"

python3 "$HERE/mock_upstream.py" &
MOCK=$!
GW=""
cleanup() { kill "$MOCK" ${GW:+$GW} 2>/dev/null || true; }
trap cleanup EXIT
sleep 1

TOKENFUSE_ADDR=127.0.0.1:4100 \
TOKENFUSE_UPSTREAM=http://127.0.0.1:9000/v1/messages \
TOKENFUSE_CACHE=off TOKENFUSE_FIREWALL=off TOKENFUSE_DLP=off \
  "$BIN" >/tmp/tf_bench_gw.log 2>&1 &
GW=$!
sleep 2

echo
echo "===== BASELINE: client -> mock (direct) ====="
wrk -t"$THREADS" -c"$CONN" -d"${DUR}s" --latency -s "$HERE/post_direct.lua" \
  http://127.0.0.1:9000/v1/messages

echo
echo "===== THROUGH GATEWAY: client -> tokenfuse -> mock ====="
wrk -t"$THREADS" -c"$CONN" -d"${DUR}s" --latency -s "$HERE/post_gw.lua" \
  http://127.0.0.1:4100/v1/messages

echo
echo "The gateway overhead is the difference in the latency percentiles above."
