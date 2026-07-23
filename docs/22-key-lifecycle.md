# 22 - Key lifecycle health: `GET /v1/keys`

Status: v1, shipped as `feat/key-lifecycle-health`. Extends B1
(docs/20-identity-map.md: client keys, the identity map) to key lifecycle: a
read-only report an operator, or the console, can poll to see what shape a
gateway's keys are actually in.

Defensive intent, as everywhere in TokenFuse: this is observability an
operator gets over THEIR OWN keys inside their own perimeter. It mints,
rotates, and revokes nothing.

## 1. Why this exists

After docs/20, a gateway has two independent, declarative sources of key
identity: `TOKENFUSE_CLIENT_KEYS` (which secrets exist) and
`TOKENFUSE_IDENTITY_MAP` (which of those `key_id`s are bound to a unit, and
under what agent-id constraint). Once `TOKENFUSE_DATA_DIR` is set, there is
a third, empirical source too: the Parquet trace remembers every `key_id`
that has ever actually made a call, whether or not either config file still
mentions it.

Nothing before this correlated the three. An operator rotating a key had no
cheap way to tell whether the old key had actually gone quiet, whether a
freshly-added map entry had ever been exercised, or whether a `keys[]`
binding pointed at a `key_id` deleted from `TOKENFUSE_CLIENT_KEYS` months
ago, short of grepping the trace by hand. `GET /v1/keys` is that
correlation, assembled read-only from the three sources plus one small
in-process counter. The console (paid, Genaryx) renders it; this gateway
only serves the data.

There is still no mint tooling, no revocation API, and no hot reload:
config is read once at gateway startup, exactly as before this slice.

## 2. The three sources of truth

1. **Configured** - `TOKENFUSE_CLIENT_KEYS` (`crates/gateway/src/clientkeys.rs`):
   every `key_id` a secret currently resolves to. This report never sees or
   echoes a secret, only the `key_id` half - the non-secret half, safe to
   show.
2. **Bound** - `TOKENFUSE_IDENTITY_MAP` `keys[]`
   (`crates/gateway/src/identitymap.rs`, docs/20 section 2): which `key_id`s
   have a unit binding, the agent-id patterns (verbatim strings) that
   constrain them, and now, optionally, a `created` field (section 4).
3. **History** - the Parquet trace (`TOKENFUSE_DATA_DIR`), when set: every
   `key_id` with a non-empty value on any recorded call, folded into
   per-key call/mismatch counts and first/last-seen timestamps
   (`crates/gateway/src/keysreport.rs`). Absent `TOKENFUSE_DATA_DIR`, this
   source is simply missing: `history_available: false`, and every key's
   `history` is `null`.

A fourth, in-process-only signal sits alongside these: since-startup
counters (`crates/gateway/src/keystats.rs`) - calls, identity mismatches,
and last-seen, per `key_id`, plus an aggregate unauthorized-attempt counter.
These reset on restart (section 6) and are what the report calls
`since_startup`, distinct from the durable `history` fold.

## 3. Wire contract: `GET /v1/keys`

No auth (mirrors `GET /v1/runs`: the gateway binds loopback by default, and
every field here is metadata, never a secret).

```json
{
  "strict_mode": "off",
  "identity_map_configured": true,
  "history_available": true,
  "unauthorized_since_startup": { "attempts": 3, "last_millis": 1737590400000 },
  "keys": [
    {
      "key_id": "billing-agent",
      "configured": true,
      "bound": true,
      "unit": "treasury",
      "agents": ["agent://bank.example/treasury/*"],
      "created": "2026-07-01",
      "since_startup": { "calls": 42, "identity_mismatches": 0, "last_seen_millis": 1737590400000 },
      "history": { "calls": 9001, "identity_mismatches": 3, "first_seen_millis": 1735689600000, "last_seen_millis": 1737590400000 }
    }
  ]
}
```

- `keys[]` is the UNION of `key_id`s across all three sources (section 2),
  sorted ascending.
- `unit`/`agents`/`created` come from the identity map only; a key with no
  binding (`bound: false`) gets `unit: null`, `agents: []`, `created: null`.
- `history` is `null` on every key when `history_available` is `false`.
  When history is available, a key with zero recorded rows still gets a
  populated (not null) object:
  `{"calls":0,"identity_mismatches":0,"first_seen_millis":null,"last_seen_millis":null}`
  - "scanned and found nothing" is a different fact from "did not scan".
- The Parquet scan is cached for 15 seconds per data directory, so console
  polling cannot turn this endpoint into a repeated full-directory scan.
- Secrets never appear in this response, in logs, or in errors; `key_id` is
  the non-secret half, and that is all this endpoint ever shows.

## 4. `created` (docs/20 amendment)

`keys[]` entries in the identity map may now carry an optional `created`
string, convention `YYYY-MM-DD`:

- **Informational only.** Nothing parses it as a date, validates its
  format, or acts on it. It exists so an operator (or the console) can
  compare how old a binding is against how recently it was actually used.
- **Verbatim.** The report echoes back exactly what the map said, except a
  blank or whitespace-only value normalizes to `null` (the one
  normalization rule), matching the "blank reads as absent" convention this
  map already uses elsewhere.
- **Fully additive, both directions.** Absent on an old map: reads as
  `None`, exactly like every field this stack has ever added additively.
  A new map (with `created`) reaching an OLD gateway that predates this
  field: `identitymap.rs` has never set `deny_unknown_fields` and still
  does not, so the field is silently ignored there, same as any future
  field would be.

## 5. Derived status (the CONSOLE computes this, not the gateway)

This endpoint serves raw facts, not a verdict: "stale" is a judgment call
(how stale is too stale depends on the operator's own rotation policy), so
the gateway reports numbers and the console classifies them. The
vocabulary the console is expected to use, from the fields above:

- **active** - configured, bound, and `since_startup.calls` (or
  `history.calls`) recently nonzero.
- **stale** - configured and/or bound, but the most recent `last_seen`
  across whichever sources are available is old relative to the operator's
  own threshold.
- **never-used** - configured and/or bound, `since_startup.calls == 0`,
  and (when history is available) `history.calls == 0` too.
- **unbound** - `configured: true`, `bound: false`: a real credential with
  no unit binding, attribution-only exactly as docs/20 already allows,
  surfaced here as a visible state rather than a silent one.
- **dangling** - `configured: false`, `bound: true`: the identity map names
  a `key_id` no `TOKENFUSE_CLIENT_KEYS` entry resolves to - the same
  condition `main.rs`'s startup log already warns about once; this
  endpoint is the live, queryable version of that one-time warning.
- **removed / ghost** - `configured: false`, `bound: false`, `history` not
  null and non-zero: a key that made real calls in the past and has since
  been removed from both config sources, visible only because the trace
  remembers it.
- **mismatching** - `since_startup.identity_mismatches > 0` (or, when
  history is available, `history.identity_mismatches > 0`): this key has
  actually been presented alongside an `agent_id` its `agents` patterns did
  not allow, at least once. Orthogonal to the other states above (a key can
  be `active` and `mismatching` at the same time) - it is a signal to check
  the binding or the caller, not a lifecycle stage by itself.

## 6. Honest limits (stated, not buried)

- The `401 unauthorized` response stays deliberately indistinguishable
  between "no credential presented" and "an unknown credential presented"
  (`crates/gateway/src/clientkeys.rs`'s documented security stance); this
  report does not, and must not, narrow that down. `unauthorized_since_startup`
  is an AGGREGATE, process-wide counter only, with no per-secret, per-key,
  or per-source breakdown anywhere, on purpose.
- `since_startup` counters are in-process and reset on every restart: not
  durable, not fleet-consistent across multiple gateways (the same
  limitation docs/20 states for unit budget counters). The `history` fold
  is the durable, cross-restart view, but only for whatever this ONE
  gateway process has written to `TOKENFUSE_DATA_DIR`; a fleet-wide view is
  a Cloud aggregation question, out of scope here.
- `history` requires the Parquet trace to be enabled
  (`TOKENFUSE_DATA_DIR`); without it, every key's `history` is `null` and
  `history_available` is `false`. There is no fallback data source.
- Cloud never sees `key_id` today, and this feature does not change that:
  everything here is gateway-local.
- No mint, rotation, or revocation tooling exists yet, and this endpoint
  does not add any. It is read-only observability over state three other
  slices already maintain.

## 7. What this is not

Not a budget, not a policy, not an enforcement decision: nothing here reads
`TOKENFUSE_MODE`, blocks a call, or changes `resolve_client_key`'s
behavior. It is a report assembled from state `clientkeys.rs`,
`identitymap.rs`, and `sink.rs`/`sqlq.rs` already maintain, plus one small
new in-process counter (`keystats.rs`) that piggybacks on request paths
that already run today. No write-schema change of any kind: the Parquet
side of this feature only reads the existing trace.
