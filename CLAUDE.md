# CLAUDE.md — working instructions for tokenfuse

These instructions apply to any model working in this repo. They encode the
process and patterns the project was built with so work stays consistent
regardless of which model is active. Read this before starting a task.

## What tokenfuse is

A drop-in reverse proxy between AI agents and LLM providers. It enforces
per-run hierarchical budgets in real time — an over-budget call gets a hard
`402 Payment Required` ("Breaker"), not a warning after the fact — detects
loops, runs an agent firewall (taint tracking + DLP), scans and brokers
credentials for MCP tools, writes zero-DB Parquet analytics, replicates the
budget ledger across a raft HA cluster, and ships a hosted Cloud plus an
iPhone/Watch app that can send an Apple Secure Enclave–signed kill.

Positioning is FinOps-first: **"enforcement, not observability."** This was a
deliberate pivot (`docs/09-product-strategy.md`, decided 2026-07-02; reframed
2026-07-07 — see the P0 Breaker-reframe commits). Never market tokenfuse as an
MCP security scanner — the MCP scanner/broker is one capability pack inside a
single core, not the product.

## Current status

**v0.3.0 released** (npm, crates.io, PyPI, GHCR). On `main` since the tag:
- `tokenfuse focus-export` — Parquet traces → a FinOps FOCUS-format CSV
  (blocked calls included as $0 rows).
- Agent Passport adoption: an opt-in agent-event NDJSON exporter
  (`TOKENFUSE_EVENTS_PATH`), `x-fuse-on-behalf-of` delegation-chain capture,
  and `parent_run_id` threaded into the Parquet trace (PR #98).
- Outcome tags + the `tokenfuse outcomes` report (PR #99).

None of this has shipped in a tagged release yet. **Point at `PROGRESS.md`**
for full per-component detail and history — it's the living log of where the
code actually is; this file is process, not status.

## The working loop (this repo uses PR flow — unlike idryx/qryx, which push to main)

1. Branch per phase/feature off `main`.
2. Implement one logical increment.
3. Run the gates (below) — all must pass.
4. If working as a subagent for the architect: leave changes **uncommitted**
   for review before committing.
5. Commit with Conventional Commits, message ending in:
   `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
6. Push the branch, open a PR with `gh`.
7. Wait for **all** CI checks to go green. Fix forward if red.
8. **Ask the user** before merging.
9. Merge with a merge commit (`--merge`), matching PRs #94–#99. Don't
   squash or rebase-merge.

**Parallel work in this repo MUST use `git worktree add`** — the main
checkout is frequently shared across sessions/agents.

## Gates (must pass before calling anything done)

```sh
cargo fmt --all -- --check
cargo clippy --all-targets          # CI additionally runs --all-features
cargo test --all
cargo test -p tokenfuse-gateway --features cluster --test cluster_backend
```

The last one is the raft-backed ledger test gated behind the `cluster`
feature — copy this exact invocation, it's what `.github/workflows/ci.yml`
runs. CI also runs separate jobs for the Python SDK (`sdk/python`), the JS SDK
(`sdk/js`), the OpenAPI spec, the Next.js dashboard, the `crates/cluster`
workspace (own fmt/clippy/test), `cargo audit` (workspace + cluster), the
`crates/radar` eBPF build (Linux-only), and a `--features apns` clippy build
for `tokenfuse-cloud`. Job names, if you need to reference one:
`fmt · clippy · test`, `python sdk`, `js sdk`, `openapi spec`, `dashboard
(Next.js)`, `cluster (raft HA)`, `security (cargo audit)`, `radar (eBPF
build)`, `cloud apns (feature build)`.

## Hard invariants

1. **`tokenfuse-core` stays dependency-minimal.** Its full allowed dependency
   list, verbatim from `crates/core/Cargo.toml`, is: `thiserror`, `serde`,
   `serde_json`, `regex`, `sha2` (for the hash-chained audit trail in
   `audit.rs`). Nothing web-, `utoipa`-, or `p256`-shaped leaks in here — those
   belong in `crates/gateway` or `crates/cloud`, which sit on the I/O
   boundary. Core is money, pricing, ledger, policy — it has to stay provable
   and portable.
2. **Enforcement hot path: byte-identical output across refactors.** The
   golden regression test is
   `breaker_error_response_matches_budget_error_byte_for_byte` in
   `crates/gateway/src/proxy.rs`. It asserts the Breaker-facade-backed
   `breaker_error_response` produces the same status, body bytes, and headers
   as the old `budget_error` builder, across all five 402 budget-family
   reasons (PR #92 wired the facade into the real 402 path — don't let it
   drift back apart).
3. **Core types reach the Cloud OpenAPI only via cloud-local `*Schema` DTOs.**
   Never derive/expose `tokenfuse-core` types directly on the Cloud API
   surface — the DTO boundary is what lets core evolve without breaking the
   public schema.
4. **"Honesty is a feature."** Never over-claim compliance coverage or
   hard-guarantee semantics. Budgets are estimate-then-settle, and the system
   fails open by default — docs and READMEs must state these limitations
   plainly, not bury them.
5. **Don't thread new dimensions through `LedgerBackend`/raft casually.** The
   ledger's replicated state (`crates/gateway/src/ledger_backend.rs`,
   `crates/cluster`) is the thing that has to stay linearizable across nodes;
   a new field there is a raft/schema-identity decision, not a routine edit.
6. **Telemetry evolves append-only.** Parquet schema changes follow the
   nullable-evolution pattern set by P2/P3/P4 (see the comments in
   `crates/gateway/src/sink.rs` around `read_schema()` and the mixed-schema
   test in `crates/gateway/src/sqlq.rs`): new columns are nullable in the
   *read* schema so old trace files keep reading, even though the *write*
   schema declares them non-nullable for what we produce going forward. The
   agent-event exporter (`crates/gateway/src/events.rs`) must stay zero-cost
   when `TOKENFUSE_EVENTS_PATH` is unset and fail-open when it's set (log a
   warning, don't crash the gateway) — and it must never fabricate an
   `agent_id`; skip the event if the request doesn't carry one.

## Known pitfalls

- **CI runner disk.** The `fmt · clippy · test` job builds three full profiles
  (clippy `--all-features`, debug tests, the `cluster`-feature test graph); a
  warm cache on the 14 GB runner disk has run dry mid-link before (`ld` dies
  with SIGBUS). The job frees ~25 GB of preinstalled bundles it doesn't need
  (`android`, `dotnet`, `ghc`, `boost`, CodeQL) before building. If SIGBUS
  link failures recur, bump the `Swatinem/rust-cache` `prefix-key` (currently
  `v1`, bumped 2026-07-09 after a poisoned-cache SIGBUS) to force a fresh
  cache namespace.
- `core.fileMode` is already set to `false` in this repo's git config, don't
  re-set it or chase phantom mode-only diffs.
- **Docs are numbered 01-19** (`docs/`); new design docs continue the
  sequence (next is 20). `docs/09-product-strategy.md` is the one to read
  before touching product framing or positioning.

## Model escalation — tell the user, don't just push through

No model can switch itself. When a task hits the criteria below, stop and
say so, then wait for the user before proceeding:

- A real **architectural fork** with expensive rollback — ledger/raft
  changes, Cloud schema-identity decisions, anything that touches how core
  types cross the DTO boundary.
- Anything **irreversible or outward-facing** — cutting a release, publishing
  a package (npm/crates.io/PyPI/GHCR), or any other public action. Note the
  standing decision: **no publicity push** (HN posts, launch announcements,
  etc.) until the user says the stack is ready — don't raise the topic
  unprompted.
- **Subtle correctness on the enforcement path** — anything touching the 402
  Breaker response, budget reservation/settlement, or the loop/taint/DLP
  block decisions, where a missed case ships a wrong allow/deny.

Routine increments are fine on a cheaper model: a new report CLI (like
`focus-export`/`outcomes`), connector-pattern extensions, tests, docs.

## Memory

Session learnings live under
`~/.claude/projects/-Users-factory-Development-tokenfuse/memory/` if present.
Check it for prior lessons before repeating a class of mistake.
