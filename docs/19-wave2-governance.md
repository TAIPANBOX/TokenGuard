# 19 - Wave-2 governance: router, Wardryx PEP, Cloud replay/evidence

Wave 2 extended TokenFuse from "meter + breaker" toward a governance plane, without changing the enforcement hot path's contract. Three integrations were added, each **off by default**, each a true no-op until its env var is set, each fail-safe. This note records the design and the invariants they preserve. The user-facing configuration table lives in the README ("Wave-2 configuration"); this doc is the why.

## 1. Model router (`crates/gateway/src/router.rs`)

**Goal.** Route each call to the cheapest model that still clears the task's required quality tier, so routine work stops paying frontier-model prices. This is optimisation, not just a guardrail, so the savings must be attributable on their own.

**Contract.**
- `TOKENFUSE_ROUTER=off|shadow|on` (default `off`). `shadow` computes and reports the route but never rewrites the body or the settled price; `on` rewrites the outgoing `model`.
- Rules come from `TOKENFUSE_ROUTER_RULES` (a JSON task-class table) or the built-in defaults. An unreadable path or malformed JSON **fails open to the defaults** and logs a warning, never a hard error.
- It routes to the cheapest candidate that MEETS the class's required tier. That is usually a downgrade, but if the caller requested a model BELOW the class's required tier, the router will pick a sufficient (possibly pricier) model rather than ship an under-tier answer. This is intentional and tested (`explicit_higher_tier_requirement_routes_up_end_to_end`); "never routes up" is an oversimplification, the precise rule is "cheapest model that clears the bar".
- A model absent from the price book is never proven cheaper than anything, so a routed choice is only ever made among priced candidates; an unpriced *requested* model is kept.
- Response header `x-fuse-router`: `<model>=kept` when nothing changed, `<from>-><to>` when a rewrite was applied, and `would-<from>-><to>` in shadow mode. The `would-` prefix (added in the Wave-2 hardening pass, mirroring the Wardryx shadow convention) stops an external consumer from mistaking a hypothetical for an applied rewrite; the authoritative billing signal is `saved_microusd` on the trace, which is `0` in shadow.
- Savings are booked as a distinct dimension from cache savings in `tokenfuse_core::compute_savings`, so a FinOps report shows router ROI as its own number.

## 2. Wardryx policy hook: the PEP/PDP split (`crates/gateway/src/wardryx.rs`, `proxy.rs`)

**Goal.** Let an operator gate an agent's *intent* (which tool, how many steps, how expensive, to which domains) with a declarative policy, decided by a separate service so the policy language can evolve independently of the proxy.

**Split.** TokenFuse is the PEP (Policy Enforcement Point): it calls out, on the request path, to an external [Wardryx](https://github.com/TAIPANBOX/wardryx) PDP (Policy Decision Point) `/v1/decide`, before the call is reserved or forwarded. TokenFuse holds none of the policy logic; it forwards a decision context (agent id, on-behalf-of chain, tool set, declared domains, step count, estimated cost, any approval token) and acts on the verdict.

**Contract.**
- `TOKENFUSE_WARDRYX_MODE=off|shadow|enforce` (default `off`); a missing `TOKENFUSE_WARDRYX_URL` forces `off`. `shadow` reports `would-...` and never blocks.
- `TOKENFUSE_WARDRYX_FAILMODE=open|closed` (default `open`) decides behaviour when the PDP is unreachable or times out (`TOKENFUSE_WARDRYX_TIMEOUT_MS`, default 50). Fail-open is the default so the PDP is never a new single point of failure, consistent with the whole system's fail-open stance.
- Decisions may be cached for `TOKENFUSE_WARDRYX_CACHE_TTL_MS` (default 3000, `0` disables), but ONLY when the PDP marks the decision `cacheable`. Request-specific policies (`max_steps`, `require_human_above_usd`, `allow_domains`) come back `cacheable:false`, and a `hold` is never cached regardless. This is what keeps a short-TTL cache from serving a stale allow past a step/spend threshold. The cache key is `(agent_id, sorted tool-set hash, attestation_method)`: attestation is part of the key so a cacheable `deny_if_unattested` verdict never leaks across attestation states: an unattested request cannot inherit a recently-attested `allow` (or vice-versa) inside the TTL.
- The PEP gates on tools the request DECLARES (`tools[]`), not only tools already invoked, so a `deny_tool` fires before the model can emit the forbidding `tool_use` (see PR #103).

**Decisions.**
- `allow` proceeds.
- `deny` returns `403` + `x-fuse-wardryx: deny`.
- `hold` returns `403` + `x-fuse-wardryx: hold` + `x-fuse-approval-id`. The flow is **stateless**: the gateway does not park the connection or poll. The caller obtains an approval out of band (a human, or an automated approver, calls the PDP) and resubmits the identical request carrying `x-fuse-approval-token`. TTL, single-use, and exactly which fields the token binds to are entirely the PDP's responsibility; TokenFuse only forwards the token. The hold response builder never trusts the PDP-supplied `approval_id` into a header without validating it, and never panics the request task on a malformed one (Wave-2 hardening).

## 3. Cloud replay + regulator evidence (`crates/cloud`)

**Goal.** Turn the agent-event journal into two auditor-facing artifacts without a second data pipeline: a run replay and a compliance evidence pack.

**Contract.**
- `TOKENFUSE_CLOUD_REPLAY_EVENTS` points the control plane at an agent-event NDJSON file it reads (never writes) to reconstruct a run for `/v1/replay/{run}`. Unset, missing, or a corrupt line is tolerated: replay reports `configured:false` or counts malformed lines, and never panics.
- Incident detectors are thresholded by env (`TOKENFUSE_CLOUD_INCIDENT_*`, see the README table) and derive `budget_exhausted` / `sustained_loop` / `spend_spike` / `fanout_explosion` from ingested call records.
- `/v1/replay`, `/v1/compliance`, and `/v1/compliance/evidence` are readable by any authenticated role (the former paid-plan gate is gone: since v0.4.0 there is no paid TokenFuse tier); they never expose `tokenfuse-core` types directly, only cloud-local `*Schema` DTOs (invariant #3).

## 4. Telemetry hardening: per-instance trace segments (`crates/gateway/src/sink.rs`)

The Parquet sink names segments `calls-<instance>-<seq:08>.parquet`, where `<instance>` is a per-process pid + start-nanos token. Before this, `seq` started at 0 in every process and `File::create` truncates, so two gateways sharing one `TOKENFUSE_DATA_DIR` (an HA cluster's nodes, or a restarted process meeting the previous run's files) both wrote `calls-00000000.parquet` and clobbered each other's trace. The per-instance token makes concurrent writers and restarts collision-free. Readers enumerate the directory by the `.parquet` extension, not by parsing the sequence, so the wider filename is transparent to `focus-export` / `outcomes` / `sql`. This is a filename change only; the append-only, nullable-read Parquet schema evolution (invariant #6) is untouched.

## Invariants preserved

- The 402 Breaker response path is byte-identical (invariant #2); none of the above touch it.
- `tokenfuse-core` stays dependency-minimal (invariant #1): the router, the Wardryx client, and the sink all live in `crates/gateway`.
- Everything here is off by default and fail-safe (invariant #4): honesty about limitations over silent magic.
