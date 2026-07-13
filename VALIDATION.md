# Live infrastructure validation

TokenFuse was exercised on real Linux infrastructure with a real Anthropic key before any public
launch - three things that never show up on a macOS dev machine or CI fixtures: a real multi-node raft
cluster, real cross-cloud network conditions, and real LLM cost accounting. All infrastructure was
disposable (ephemeral Hetzner VPS boxes, torn down after each run; short-lived cloud instances for the
AWS/GCP leg) and reachable only over `127.0.0.1` / SSH tunnel - nothing was ever exposed publicly.

## Raft HA cluster - from loopback to a real cross-datacenter network

The cluster (`crates/cluster`, raft-replicated budget ledger) was proven correct at three levels of
increasing realism:

| Test | Loopback (3 nodes, one box) | Cross-machine (4 nodes, one DC) | Cross-DC (4 nodes, two DCs) |
|---|---|---|---|
| No double-spend | 30 concurrent reserves vs a 5-unit budget → exactly 5 admitted, byte-identical state | same → 5/25, byte-identical on all 4 nodes | same → 5/25, byte-identical |
| Leader-crash re-election | `kill -9` leader → ~526ms | ~583ms over a real inter-host network | ~568ms |
| Network partition | not testable on one box | isolated leader could not commit (no quorum); majority kept serving; **no split-brain**; healed node caught up on the missed write | same, confirmed cross-DC |

The 4-node cross-machine and cross-DC runs used the product's actual intended shape - one gateway
process per host, TLS between nodes off a shared CA, a shared bearer token - not a bespoke test rig.

## Enforcement under real load

**A representative real run** (the fleet-summary dashboard referenced from the README): 6 agents, 24
runs, 51 real Claude calls - 34 served (200), 17 blocked (402) - **$0.0115 spend, $0.0247 saved**
(breaker $0.02136 + semantic cache $0.00176 + model router $0.00154), 3 budget breaks. The Breaker
tripped live mid-run: 4 calls admitted against a $0.006 budget, the 5th would have exceeded it, so calls
5-8 were held at 402 - enforced by the raft ledger, in seconds, not on next month's invoice. Three
incidents were auto-detected in the same run: `budget_exhausted` (a scraper agent, 3 runaway runs),
and `fanout_explosion` (an orchestrator with 7 children, and a support agent mid-burst).

**A separate, larger enriched multi-agent campaign** (later run, real Claude `claude-haiku-4-5` through
the fully-featured gateway - enforce + router + cache + DLP + firewall + Wardryx PEP + Cloud sink):

- **176 real allowed calls / 65 runs / $0.0206 total spend.**
- All three savings levers fired for real: breaker (blocked spend) **$0.03066** + semantic cache
  **$0.00430** + model router **$0.00154** = **$0.0365 saved**, 12 budget breaks.
- The model router downgraded `claude-sonnet-4-5 → claude-haiku-4-5` on cheap tasks; the semantic
  cache served real repeat prompts - both savings are measured, not theoretical.

This is the same campaign the 34-agent concurrency test below was run against.

**Concurrency, 34 requests fired at once** (different agents, credentials, budgets, policies): good
agents **6/6 served (200)**, money-oversteppers **10/10 blocked (402)**, permission-oversteppers
**6/6 denied (403)**. A shared-budget race - 10 agents against one **$0.0010** cap - admitted **exactly
3, blocked 7**, parent spend stayed under the cap: the raft ledger held a shared budget correctly under
true concurrency, not just sequential load.

**Scale test** (stub provider, to isolate the governance hot path from LLM latency): 100 concurrent
reserves against a 20-unit budget admitted **exactly 20**; 500 concurrent against a 50-unit budget
admitted **exactly 50** - zero over-admission at either scale. Full-gateway throughput: 216 req/s at
c=100, 397 req/s at c=500, 8,000/8,000 requests served, none dropped.

## Cross-cloud cost accounting (AWS + GCP)

A separate question from the Hetzner runs above: does the gateway's cost-enforcement mechanism itself
hold up on the two clouds most of our audience actually runs on? A matched-protocol campaign (176 real
allowed calls, 12 budget-block attempts, same model, same `enforce` mode) was run on AWS (`t3.medium`,
`eu-central-1`) and GCP (`e2-medium`, `europe-west3`):

| metric | Hetzner | AWS | GCP |
|---|---|---|---|
| real calls / budget blocks | 176 / 12 | 176 / 12 | 176 / 12 |
| total LLM spend | $0.0206 | $0.050971 | $0.051214 |
| cost per allowed call | $0.000117 | $0.000290 | $0.000291 |
| p50 / p99 latency | - | 1.227s / 3.795s | 1.227s / 5.006s |

**Honest scope note:** AWS and GCP are scale-matched to Hetzner by call count and validate the gateway
and its cost accounting with real Anthropic traffic - they are not a repeat of the full raft/router/cache/
multi-agent evidence above, which remains Hetzner-only for now. The cost-per-call gap (~2.5x) is not
apples-to-apples either: the Hetzner number includes router downgrades and cache hits that were
deliberately left off on AWS/GCP so those two would isolate pure gateway + real-model cost.

## Real bugs live testing found (and fixed)

All three were invisible on fixtures, the stub provider, and macOS - only real Linux + real traffic
surfaced them. All fixed and merged before the runs above were taken as final.

1. **`x-api-key` not forwarded** (`provider.rs`) - the upstream header allowlist had OpenAI's
   `authorization` but not Anthropic's native `x-api-key`, so the gateway could not authenticate to
   Anthropic's own API. Fixed.
2. **Raft-ledger snapshot panic** (`proxy.rs:360`) - `.expect("run just opened")` panicked a worker
   when a follower's local snapshot lagged a just-opened run under burst load; 1/26 requests silently
   dropped. Fixed with a zero-snapshot fallback (enforcement itself was never at risk - the real gate is
   the raft-linearized `reserve()`).
3. **Price book missing current models** - `claude-haiku-4-5` wasn't in the price book, so reserve
   estimates fell back to a conservative default and mis-sized headroom. Fixed; the price book now
   covers 9 models.

A later concurrency run also caught and fixed a real Wardryx enforcement gap (its PEP decision cache
missed `attestation_method` in its key); see Wardryx's own validation notes for that one, since it lives
in Wardryx's code even though TokenFuse's gateway is what exposed it under load.

## Method

Disposable Hetzner VPS boxes (deleted after each run) and short-lived cloud instances; code delivered as
a `git archive` tarball (no secrets, no `.git`, no token) rather than a token-bearing clone; the Anthropic
key was written to a root-only file, never logged, and revoked after use; every service bound to
`127.0.0.1` only, reached exclusively via SSH tunnel. Nothing from these runs was ever exposed publicly,
and no infrastructure or secret from the campaign persists today.

