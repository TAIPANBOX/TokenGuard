# 20 - The identity map: key <-> agent <-> unit binding, strict mode, unit budgets

Status: design + build plan for the `feat/identity-map` slice. Follows the
roadmap line in `PROGRESS.md` ("budgets above the run (per key / agent / team /
org)... the `key_id -> team` mapping and threshold alerts are the next
increment") and builds directly on PR #119 (client keys / `key_id`).

Defensive intent, as everywhere in TokenFuse: everything here exists so an
operator can attribute, constrain and stop THEIR OWN agents inside their own
perimeter. Nothing reaches outside the gateway the operator runs.

## 1. Problem

After #119 the gateway has three disconnected identity layers:

1. A real credential: `x-fuse-key` -> server-resolved `key_id` (who may call).
2. A free-form attribution header: `x-fuse-agent-id` (who claims to be
   calling) - deliberately unauthenticated, so unusable as a budget key.
3. Nothing at all for a business unit / team.

Nothing can currently say: "this credential may only speak as these agents,
those agents belong to unit `treasury`, and `treasury` has a $2,000 monthly
cap". This doc adds exactly that linking, declaratively, with no registry
service and no new dependencies.

## 2. Operator surface

Two new environment variables:

- `TOKENFUSE_IDENTITY_MAP=/path/identity.json` - the declarative map (below).
  Unset = everything off, exactly today's behavior. Set but unreadable or
  invalid = the gateway refuses to start (same fail-closed posture as
  `TOKENFUSE_CLIENT_KEYS`: a typo must never silently disable what the
  operator believes is on).
- `TOKENFUSE_IDENTITY_STRICT=off|warn|enforce` (default `off`) - governs ONLY
  the key<->agent binding check. Unit BUDGETS follow `TOKENFUSE_MODE`
  (shadow|warn|enforce) like every other budget: the money knob governs money,
  the identity knob governs identity.

The map is JSON (not YAML: zero new dependencies, and the stack's config
artifacts - passports, descriptors - are JSON already):

```json
{
  "units": [
    { "id": "treasury", "name": "Treasury", "owner": "user://bank.example/olena",
      "budget_usd_month": 2000.0 }
  ],
  "keys": [
    { "key_id": "treasury-bots", "unit": "treasury",
      "agents": ["agent://bank.example/treasury/*"] }
  ],
  "prefixes": [
    { "match": "agent://bank.example/treasury/*", "unit": "treasury" }
  ]
}
```

- `units[].budget_usd_month` is optional; a unit without it is
  attribution-only.
- `keys[].key_id` refers to a `TOKENFUSE_CLIENT_KEYS` key id. `keys[].agents`
  patterns bound which `x-fuse-agent-id` values that credential may present.
  An empty/missing `agents` list means "any agent id", binding the key to the
  unit for attribution without constraining the id.
- `prefixes` is the fallback for traffic with no (or no mapped) key: pure
  attribution, never a mismatch.
- Patterns are a literal string or a single trailing `*` (prefix match).
  Anything else is rejected at load - no glob engine, no new dependency.
- Every `unit` referenced by `keys`/`prefixes` must exist in `units`
  (load-time refusal: typos must not silently create unattributed spend).
- Unknown JSON fields are tolerated (the stack-wide additive convention).

## 3. Resolution and enforcement semantics

On every managed `/v1/messages` call, after `key_id` and `agent_id` are known:

1. If `key_id` is non-empty and has a `keys[]` binding: the binding's `unit`
   is the call's unit. If the binding lists `agents` patterns and `agent_id`
   does not match any (or is empty), that is a MISMATCH.
2. Otherwise: the first matching `prefixes[]` entry gives the unit; no
   mismatch is possible on this path (nothing is authenticated to check
   against).
3. No match anywhere: unit is empty. Spend stays visible under the implicit
   "unassigned" bucket in every aggregation (never silently dropped).

Mismatch handling by `TOKENFUSE_IDENTITY_STRICT`:

- `off`: resolution still runs (unit attribution on the trace), no check.
- `warn`: the call proceeds; the response carries
  `x-fuse-identity: would-block=<reason>`; the trace row keeps the resolved
  binding's unit.
- `enforce`: `403` with the stable error contract (below), a `CallRecord`
  with `decision: "identity_mismatch"`, and an `identity_mismatch`
  agent-event. The call never reaches the provider.

Unit budget handling (only when the resolved unit has `budget_usd_month`),
by `TOKENFUSE_MODE`:

- `shadow`/`warn`: unit spend is recorded (reserve-then-settle, unchecked),
  never blocks.
- `enforce`: the estimate is reserved against the unit's remaining monthly
  budget BEFORE the run-level reserve; exceeding it returns `402` with
  `type: "unit_budget_exceeded"`, a `CallRecord` with
  `decision: "unit_budget_exceeded"`, and a `breaker_tripped` agent-event
  whose `data` names the unit. If the unit reserve succeeds but the run-level
  reserve then fails, the unit reservation is released (settled at zero).

The month window is the UTC calendar month (FinOps/chargeback-friendly);
counters roll over on the first call of a new month.

### Honest limitations (stated, not buried)

- Unit counters are in-process and per-gateway: they reset on restart and are
  NOT fleet-consistent across multiple gateways. Run budgets can already be
  raft-replicated; unit budgets deliberately do NOT touch the replicated
  ledger in this slice (a new dimension in raft state is a schema-identity
  decision, per this repo's invariants). Fleet-consistent unit caps are a
  future slice; the durable cross-fleet VIEW of unit spend lives in the Cloud
  aggregation, which is fed by the trace and survives restarts.
- Budgets remain estimate-then-settle; the system stays fail-open on internal
  errors, as documented for run budgets.
- With client keys off, `strict` has nothing authenticated to check: binding
  checks idle (a startup log says so) and only prefix attribution applies.

## 4. Wire contract additions

- New Breaker reasons:
  - `unit_budget_exceeded` - HTTP 402, budget-family error body
    (`budget_usd`/`spent_usd` carry the UNIT's numbers).
  - `identity_mismatch` - HTTP 403, minimal error body (like
    `dlp_blocked`/`taint_blocked`: no budget fields).
  The five existing 402 bodies stay byte-identical (golden test).
- New response header in warn mode: `x-fuse-identity: would-block=<reason>`.
- Trace: `CallRecord` gains a `unit` column (empty when unresolved), following
  the nullable-evolution rule: nullable in the read schema so old Parquet
  files keep reading, non-nullable in the write schema going forward - the
  exact pattern `key_id` used in #119.
- Agent events: new `identity_mismatch` type (severity `high`, the
  DLP/taint family); `breaker_tripped` events gain `"unit"` in `data`.
- FOCUS export: a new `x_unit` column, one value per call row.
- Cloud API (additive only):
  - ingest accepts the new `unit` field on records (defaults to empty).
  - `GET /v1/units` - per-unit aggregation for the org (viewer role).
  - `POST /v1/units/{id}/budget` - central monthly-cap override (admin role,
    audited like run-budget changes).
  - `GET /v1/unit-budgets` - flat `{unit: microusd}` map for gateway pollers.
    A separate endpoint (not a new key inside `/v1/budgets`) because the
    existing budgets payload is a flat `run_id -> i64` map old gateways parse
    verbatim; changing its shape would break them.
- Gateway polls `/v1/unit-budgets` (same 3 s cadence and error posture as the
  run-budget poller) and applies overrides on top of the map file's caps.

## 5. Build slices (each independently green)

1. `identitymap.rs` - parse/validate/resolve + unit tests. No behavior wired.
2. `CallRecord.unit` threading - sink schema (read nullable / write
   non-nullable), sqlq mixed-schema coverage, focus-export `x_unit`,
   mechanical construction-site updates. Mirrors #119's `key_id` diff.
3. Enforcement wiring - `unitledger.rs` (UTC-month reserve/settle),
   breaker reasons, `identity_mismatch` event type, proxy gates
   (mismatch 403 / unit 402 / warn header), state + main config, startup
   logs, cross-check warning when a map `key_id` has no client key.
4. Cloud - ingest `unit`, `UnitAgg` + `/v1/units`, unit-budget store +
   `POST /v1/units/{id}/budget` + `/v1/unit-budgets`, audit entries, OpenAPI
   DTOs; gateway unit-budget poller.
5. Docs - README section, PROGRESS.md, this file kept current.

Out of scope for this PR (named follow-ups): dashboard grouping by unit;
fleet-consistent unit caps via the replicated ledger; mockryx drill scenarios
(`identity-mismatch`, `unit-budget`) which live in the mockryx repo;
threshold alerts per unit.

## 6. Decision log (Q1-Q6 from the D15 planning doc, resolved 2026-07-23)

- Q1 strict default: `off`; `warn` is the recommended first step in prod.
- Q2 unit budget window: UTC calendar month.
- Q3 passports directory convention: `~/.taipan/passports/` (consumed by
  onboarding tooling, not read by this slice).
- Q4 first-pilot IdP assumption: Entra ID (affects the console, not this
  slice).
- Q5 WebAuthn action scope (console): kill, break-glass, budget mutation,
  policy write, approval grant.
- Q6 open/paid split confirmed: this slice is open TokenFuse; onboarding
  wizard + IdP login + WebAuthn ceremonies belong to the paid console.
- Map format: JSON, not YAML (zero new dependencies; config artifacts across
  the stack are JSON).
