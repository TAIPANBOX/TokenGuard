# TokenFuse — Architecture v0.2

> Ambitious edition: Rust core, flagship features. v0.1 (the conservative Go version) lives in the chat history; the key ADRs from it are preserved here.

## 1. Three pillars of "wow"

1. **"It sees what you can't"** — Radar (eBPF) discovers LLM traffic on hosts with no config on its own (pain point: 82% of organizations found shadow agents).
2. **"An agent that knows the cost of its own actions"** — a built-in MCP server: the agent sees its own budget, can request an increase → a human approves with a button in Slack.
3. **"Faster than you can notice"** — Rust, a single ~10 MB static binary, p99 added latency < 3 ms.

## 2. Stack

| Component | Technology |
|---|---|
| Data plane (core) | Rust: tokio + hyper/axum, rustls, zero-copy SSE |
| Policies | CEL/YAML (simple) + WASM sandbox via wasmtime (complex, hot-swap) |
| Counters | in-process (1 node) → Redis (optional, fleet) → embedded openraft (Phase 4) |
| Analytics | Apache Arrow + Parquet segments (local/S3) + DataFusion SQL |
| TUI | ratatui (`tokenfuse top`) |
| eBPF | aya (Radar, Linux-only) |
| Config/policy store | PostgreSQL (configuration only; telemetry lives in Parquet) |
| Cloud control plane | Rust: axum + utoipa (OpenAPI) — *superseded from Go, see ADR-7 and [14-mobile-companion.md](14-mobile-companion.md)* |
| Dashboard | Next.js (client generated from the control-plane OpenAPI spec) |
| SDK | Python + TypeScript (thin: base_url + headers + typed errors) |
| Mobile | Swift 6 / SwiftUI (iOS 26 SDK) — TokenFuse, see [14-mobile-companion.md](14-mobile-companion.md) |

Language split: Rust — everything in the request path **and the Cloud control plane** (one server language, shared `tokenfuse_core` types); Next.js — web without heroics; Swift — the native mobile companion.

## 3. Key architecture decisions (ADRs)

- **ADR-1. Proxy, not SDK** (drop-in: just change `base_url`); the SDK is a convenience layer (headers + `BudgetExceededError`).
- **ADR-2. Reserve → settle ledger.** Before the call we atomically reserve the estimated cost; afterward we reconcile against the actual `usage`. The only correct approach under concurrency (sub-agent fan-out). Money is stored as integer microdollars, never floats.
- **ADR-3. Fail-open by default**, fail-closed optional per-policy. A control plane outage must not break inference (cached policies, local event buffer).
- **ADR-4. We never tear a stream apart mid-flight** — enforcement happens at step boundaries: clamp `max_tokens` before the call + block the next call. Mid-stream kill is only via the manual kill-switch.
- **ADR-5. OSS core (Apache-2.0) + Cloud.**
- **ADR-6. Token estimation is a local approximation** (+15% conservative margin); accuracy is guaranteed by settling against actual usage.
- **ADR-7. Cloud control plane in Rust, not Go** *(supersedes the "Go — Cloud services" choice above and in v0.1).* The mobile companion (ADR-14.1) forces the question, and consolidation wins: one server language across data plane and control plane, direct reuse of `tokenfuse_core` domain types (`CallRecord` is already `Serialize`), a single OpenAPI contract (`utoipa`) that generates both the Swift and the dashboard TypeScript clients, and SSE reusing the gateway's existing streaming stack. The Go plane was ~540 LoC — the port is cheap. Rationale and the full mobile plan live in [14-mobile-companion.md](14-mobile-companion.md). The original Go plane remains in history until the port lands (Phase A, PR A5).

## 4. Core components (a single Rust binary)

1. **Gateway** — `/v1/messages` (Anthropic Messages API). An OpenAI-compatible `/v1/chat/completions` endpoint is planned but NOT yet implemented; the router today serves only `/v1/messages`, `/v1/runs` and `/v1/runs/{id}/kill`. Attribution headers → estimate → policies → reserve → clamp → forward → SSE passthrough → usage from the final chunk → settle → event. Provider keys: pass-through only, never written to disk/logs (CI test enforces this).
2. **Policy engine** — in-process, hot-reload (LISTEN/NOTIFY or 10s polling).
3. **Budget counters** — a Lua script `check_and_reserve` (Redis mode) / atomic structures (in-proc).
4. **Anomaly detector + forecast** — inline heuristics + EWMA forecast of "budget blowout at step ~N".
5. **MCP server** — tools: `get_budget_status`, `estimate_remaining_steps`, `request_budget_increase(reason, amount)` → Slack approve/deny.
6. **OTel export** — GenAI semantic conventions → the client's Grafana/Datadog/Honeycomb.
7. **Metering** — events → local durable queue → Parquet segments.

## 5. Request flow

```
Agent → POST /v1/messages (X-Fuse-Run-Id: r42)
  1. token estimate (local)
  2. check_and_reserve(r42, $est)      ← atomic
  3. clamp max_tokens = min(requested, remaining/price_output)
  4. forward → SSE passthrough (zero-copy)
  5. usage from the final chunk (Anthropic: message_start/message_delta;
     OpenAI: stream_options.include_usage)
  6. settle(r42, $actual)
  7. event → Parquet (async)

Rejection: 402 Payment Required
  { "error": { "type": "budget_exceeded", "run_id": "r42",
      "budget_usd": 5.00, "spent_usd": 4.97,
      "policy_id": "per-run-default", "retryable": false } }
```

**Attribution headers:** `X-Fuse-Run-Id` (required), `X-Fuse-Parent-Run-Id` (sub-agents → hierarchical budgets), `X-Fuse-Task-Type`, `X-Fuse-Step`, `X-Fuse-Tags`.

## 6. Data model

```sql
runs(run_id PK, tenant_id, parent_run_id NULL, task_type, agent_name,
     started_at, ended_at, status, budget_microusd, spent_microusd,
     steps, policy_snapshot jsonb)

calls(call_id PK, run_id FK, step_n, model,
      input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
      cost_microusd, latency_ms,
      decision enum(allow,warn,clamp,downgrade,block),
      tool_signatures text[],
      source_taint text,          -- ← lay this in from day 1 for taint policies (Ring 3)
      ts)

policies(id, tenant_id, name, version, selector jsonb, limits jsonb,
         actions jsonb, mode enum(shadow,warn,enforce), fail_mode enum(open,closed))

decisions_audit(id, call_id, run_id, policy_id, action, reason, details, ts)

model_prices(model, input_per_mtok, output_per_mtok,
             cache_read_per_mtok, cache_write_per_mtok,
             effective_from, source)   -- versioned; updated via PR+CI
```

Telemetry (calls/events) lives in Parquet segments; Postgres holds configuration only.

## 7. Policy DSL

```yaml
policy: per-run-default
mode: enforce            # shadow | warn | enforce  ← rollout path
fail_mode: open
selector: { task_type: "code-review" }
limits:
  budget_per_run_usd: 5.00
  budget_per_step_usd: 0.50
  max_steps: 40
  max_input_tokens_per_call: 150000
  max_wall_clock_minutes: 30
anomalies:
  identical_tool_call: { window: 10, threshold: 3 }
  pingpong_pair:       { window: 8,  threshold: 2 }
  context_growth:      { factor: 1.5, consecutive: 3 }
actions:
  - at: 60%   do: notify(slack: "#ai-costs")
  - at: 85%   do: downgrade(model: "claude-haiku-4-5")   # opt-in
  - at: 100%  do: block
  - on: anomaly.identical_tool_call
    do: block(reason: "loop detected")
```

Tool-call signature: `hash(tool_name + canonicalized args)` (sorted keys, normalized whitespace, excluded fields configurable). The last N signatures are kept in run state.

## 8. Money: accounting and pricing

- Cost = input×p_in + output×p_out + cache_read×p_cr + cache_write×p_cw. Cache must be priced separately (read ~10% of input, write ~125% — otherwise the error is off by a large multiple).
- `model_prices` is versioned (`effective_from`); historical reports use the price in effect at call time.
- Unknown model → fallback: warn + price at the most expensive known model, or block.

## 9. Failure modes

| Failure | Behavior |
|---|---|
| Redis unavailable | fail-open: local in-memory counter + loud alert; fail-closed policies → 503 |
| Postgres down | cached policies; events buffered to disk |
| Gateway down | HA replicas (Cloud); self-host: documented SDK fallback `direct_on_gateway_failure` |
| Pre-flight overestimate | settle refunds the difference; underestimate is bounded by the max_tokens clamp |

## 10. Security and privacy

- **Metadata-only by default** — prompt bodies are not stored. Debug sampling with redaction is opt-in.
- Provider keys — pass-through only; CI test: grep logs/disk for keys after a full run.
- P3: virtual keys (real key held in vault, revoke with one click).
- TLS everywhere; mTLS optional; SOC2 — driven by enterprise demand.

## 11. Flagship features (W series)

| # | Feature | What it does | Phase |
|---|---|---|---|
| W1 | Radar (eBPF) | uprobe SSL_write/read → auto-discovers LLM traffic/shadow agents with no config; Linux-only (aya, CO-RE); macOS — network heuristics | 4 |
| W2 | `tokenfuse top` | ratatui TUI: live runs, $/min sparklines, k=kill, p=pause. The cheapest "wow" (~a week) | 1 |
| W3 | Self-aware agents | MCP: budget introspection + request_budget_increase → Slack approve | 2 |
| W4 | Burn forecast | EWMA + context trend → "blowout at step ~34, 87% confidence" → early alert/soft clamp | 2 |
| W5 | WASM policies | policy.wasm in wasmtime (fuel limit), any language, hot-swap, community policy marketplace | 3 |
| W6 | Time machine | policy backtesting against historical traces: "would have blocked 14 runs, -$312, 2 false positives." Trace recording starts in Phase 1 | 3 |
| W7 | Zero-dep cluster | openraft: 3 nodes form quorum on their own, no Redis/etcd | 4 |
| W8 | Parquet + DataFusion | `tokenfuse sql "..."`; unlimited retention at S3 pricing; data in an open format | 2 |
| W9 | OTel GenAI semconv | spans into the client's existing stack — we don't fight observability | 2 |
| W10 | Kill-switch in Slack | alert with a [Kill run] button | 1 |

## 12. Testing

- **Replay harness (key investment):** JSONL traces → gateway → fake provider → deterministic decision checks. Every prod bug becomes a new trace.
- Golden price tests (including cache).
- Load: 500 concurrent SSE connections, p95 overhead.
- Chaos: kill Redis mid-run → fail-open + alert.
- Secret test in CI.

## 13. NFRs

| Metric | Target |
|---|---|
| Added latency | p95 < 10 ms (Rust target: p99 < 3 ms) |
| SSE | 0 body buffering |
| Time-to-value | < 15 min from README to the first blocked run |
| Telemetry retention | unbounded (Parquet/S3) |
