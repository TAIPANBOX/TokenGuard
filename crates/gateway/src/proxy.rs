//! The request path: parse → estimate → enforce → forward → settle.
//!
//! Enforcement happens *before* forwarding (ADR-4): a blocked call returns HTTP
//! 402 with a stable JSON error and never reaches the provider. Cost is settled
//! *after* the response:
//! - streaming requests (`"stream": true`) are passed through chunk-by-chunk and
//!   settled at end-of-stream (usage is parsed out of the bytes as they flow);
//! - non-streaming requests are buffered, so we can also return `x-fuse-cost-*`
//!   headers with the exact settled figures.

use crate::estimate::estimate_cost;
use crate::identitymap::StrictMode;
use crate::keystats::KeyStats;
use crate::provider::{ProviderError, ProviderResponse};
use crate::router::RouterMode;
use crate::settle::SettleGuard;
use crate::sink::{now_millis, CallRecord};
use crate::state::AppState;
use crate::unitledger::UnitReservation;
use crate::wardryx::{DecideContext, WardryxDecision, WardryxMode, WardryxOutcome};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{response::Builder, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use futures::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use tokenfuse_core::agent_event::EventType;
use tokenfuse_core::cache::{CacheMode, Lookup};
use tokenfuse_core::taint::{self, FirewallMode, Labels};
use tokenfuse_core::{
    dlp, evaluate, BreakerReason, BreakerVerdict, BudgetError, DlpMode, Microusd, Mode,
    Reservation, RunSnapshot, SemanticCache,
};

/// Where a non-streaming response should be cached after it settles.
struct CacheCtx {
    partition: u64,
    core: String,
}

/// Default per-run budget when neither the request nor the policy sets one.
const DEFAULT_RUN_BUDGET: Microusd = Microusd(5_000_000); // $5.00

/// Sanity cap on the raw `X-Fuse-On-Behalf-Of` header (agent-passport
/// SPEC.md §5): a chain deep enough to exceed this is almost certainly
/// abuse/misconfiguration, not a real delegation chain. Over-cap does NOT
/// reject the request or truncate the chain (SPEC.md §5: "Products MUST NOT
/// truncate the chain when forwarding") — it ignores the header entirely, as
/// if it were absent, and counts the occurrence (see `ON_BEHALF_OF_OVERCAP`).
const ON_BEHALF_OF_MAX_BYTES: usize = 4096;

/// Count of `X-Fuse-On-Behalf-Of` headers ignored for exceeding
/// [`ON_BEHALF_OF_MAX_BYTES`]. There is no metrics registry in this crate
/// yet, so this is the "metric" the task calls for — logged on every
/// occurrence via `tracing::warn!` in [`on_behalf_of_header`] and readable in
/// tests via the same counter.
static ON_BEHALF_OF_OVERCAP: AtomicU64 = AtomicU64::new(0);

/// Parse the raw `X-Fuse-On-Behalf-Of` header (agent-passport SPEC.md §5): a
/// comma-separated, root-first delegation chain of opaque `agent://`/
/// `user://` URIs. Capture-only this phase — entries are NOT validated,
/// parsed into a structured chain, or truncated; the raw string rides into
/// the trace verbatim (see `sink::CallRecord::on_behalf_of`). Returns `None`
/// for an absent, empty, or over-cap header (fail-open: an over-cap header is
/// ignored, never a request failure).
fn on_behalf_of_header(headers: &HeaderMap) -> Option<String> {
    let raw = header_str(headers, "x-fuse-on-behalf-of")?;
    if raw.is_empty() {
        return None;
    }
    if raw.len() > ON_BEHALF_OF_MAX_BYTES {
        let n = ON_BEHALF_OF_OVERCAP.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            len = raw.len(),
            cap = ON_BEHALF_OF_MAX_BYTES,
            overcap_total = n,
            "x-fuse-on-behalf-of exceeds sanity cap; ignoring header"
        );
        return None;
    }
    Some(raw)
}

/// Split a captured `on_behalf_of` raw header value into the ordered,
/// root-first chain the agent-event envelope's `on_behalf_of` array wants
/// (agent-passport SPEC.md §6.1). Pure string splitting — entries are still
/// opaque strings, not validated URIs (no enforcement semantics this phase).
fn split_on_behalf_of(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Sanity cap on the raw `X-Fuse-Outcome` header (P4, unit economics): an
/// opaque tag this long is almost certainly misuse, not a real outcome label
/// like `case_resolved`/`escalated`/`abandoned`. Mirrors the
/// `X-Fuse-On-Behalf-Of` handling exactly — over-cap does NOT reject the
/// request, it ignores the header entirely (as if absent) and counts the
/// occurrence (see [`OUTCOME_OVERCAP`]).
const OUTCOME_MAX_BYTES: usize = 128;

/// Count of `X-Fuse-Outcome` headers ignored for exceeding
/// [`OUTCOME_MAX_BYTES`]. Same "metric" shape as [`ON_BEHALF_OF_OVERCAP`] —
/// logged on every occurrence via `tracing::warn!` in [`outcome_header`].
static OUTCOME_OVERCAP: AtomicU64 = AtomicU64::new(0);

/// Parse the raw `X-Fuse-Outcome` header (P4, unit economics): an opaque
/// caller-supplied tag (e.g. `case_resolved`, `escalated`, `abandoned`),
/// capture-only — not validated against any fixed vocabulary. Recorded
/// verbatim into the trace (see `sink::CallRecord::outcome`); no run-level
/// state is built here, this call's tag is simply what rides into this one
/// `CallRecord`. Returns `None` for an absent, empty, or over-cap header
/// (fail-open: an over-cap header is ignored, never a request failure — same
/// contract as [`on_behalf_of_header`]).
fn outcome_header(headers: &HeaderMap) -> Option<String> {
    let raw = header_str(headers, "x-fuse-outcome")?;
    if raw.is_empty() {
        return None;
    }
    if raw.len() > OUTCOME_MAX_BYTES {
        let n = OUTCOME_OVERCAP.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            len = raw.len(),
            cap = OUTCOME_MAX_BYTES,
            overcap_total = n,
            "x-fuse-outcome exceeds sanity cap; ignoring header"
        );
        return None;
    }
    Some(raw)
}

/// Emit a `breaker_tripped` agent-event for a Breaker 402 (agent-passport
/// SPEC.md §6.2). Separate from [`breaker_error_response`] so that function
/// stays byte-for-byte untouched (its wire contract is pinned by
/// `breaker_error_response_matches_budget_error_byte_for_byte`) — this is
/// purely an added side-channel at each of the five call sites.
fn emit_breaker_event(
    st: &AppState,
    run_id: &str,
    agent_id: &str,
    on_behalf_of: &[String],
    verdict: &BreakerVerdict,
    unit: &str,
) {
    let outcome = st.events.emit(
        EventType::BreakerTripped,
        now_millis(),
        Some(agent_id),
        Some(run_id),
        (!on_behalf_of.is_empty()).then_some(on_behalf_of),
        serde_json::json!({
            "reason": verdict.reason.map(BreakerReason::as_wire_str),
            "budget_usd": verdict.budget_usd,
            "spent_usd": verdict.spent_usd,
            "policy_id": verdict.policy_id,
            "detail": verdict.detail,
            // The resolved business unit (docs/20); null when the identity
            // map is off or nothing matched.
            "unit": (!unit.is_empty()).then_some(unit),
        }),
        None,
    );
    crate::events::log_outcome(EventType::BreakerTripped, outcome);
}

pub async fn healthz() -> &'static str {
    "ok"
}

/// Anthropic-style messages endpoint. Provider-agnostic: the body is forwarded
/// as-is once the budget check passes.
pub async fn messages(State(st): State<AppState>, headers: HeaderMap, mut body: Bytes) -> Response {
    // Who is calling, resolved from the credential they presented rather than
    // from anything they can write. Empty when client keys are not configured,
    // which is every deployment that has not opted in.
    //
    // Checked FIRST, before the unmanaged pass-through below: an unmanaged call
    // still reaches the provider and still spends the operator's provider
    // credential, so an operator who turned this on to control who may use the
    // gateway would be surprised to find "omit the run id" is a way around it.
    let Some(key_id) = resolve_client_key(&st, &headers) else {
        return unauthorized(&st.keystats);
    };
    // Key lifecycle health (docs/22): one increment per request that
    // resolved a credential, regardless of what happens downstream
    // (success, a 402 Breaker trip, a 403 identity block) - see
    // `KeyStats::record_call`.
    st.keystats.record_call(&key_id);

    let request: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let mut parsed = parse_request(&request);

    // No run id → unmanaged pass-through (drop-in safe).
    let Some(run_id) = header_str(&headers, "x-fuse-run-id") else {
        return match st.provider.send(headers, body).await {
            Ok(resp) => passthrough(resp, "unmanaged"),
            Err(e) => upstream_error(e),
        };
    };

    // A Cloud-managed budget (set by an operator) overrides the client-supplied
    // header; otherwise use the header, then the policy default.
    let budget = st
        .cloud_budget(&run_id)
        .or_else(|| header_f64(&headers, "x-fuse-budget-usd").map(Microusd::from_usd))
        .or(st.policy.budget_per_run)
        .unwrap_or(DEFAULT_RUN_BUDGET);
    // A sub-agent's run rolls up into its parent's budget (hierarchical budgets).
    let parent = header_str(&headers, "x-fuse-parent-run-id");
    st.ledger.open_run(&run_id, budget, parent.as_deref()).await;
    // Now also recorded on the trace (agent-passport SPEC.md §3.2) — before
    // this it lived only in the ledger's in-memory hierarchy above.
    let parent_run_id = parent.clone().unwrap_or_default();

    // Attribution only: which logical agent made this call. Request-scoped like
    // `model` — it rides along into every CallRecord and never touches the
    // ledger/budget. Defaults to "" when the header is absent.
    let agent_id = header_str(&headers, "x-fuse-agent-id").unwrap_or_default();

    // Delegation chain (agent-passport SPEC.md §5): captured raw for the
    // trace, and split into an ordered list for agent-event envelopes. No
    // enforcement semantics this phase — capture only.
    let on_behalf_of_captured = on_behalf_of_header(&headers);
    let on_behalf_of = on_behalf_of_captured.clone().unwrap_or_default();
    let on_behalf_of_chain: Vec<String> = on_behalf_of_captured
        .as_deref()
        .map(split_on_behalf_of)
        .unwrap_or_default();

    // Outcome tag (P4, unit economics): captured raw for the trace, same
    // cap/ignore contract as `on_behalf_of` above. No enforcement semantics —
    // capture only. Named `outcome_tag` (not `outcome`) because `outcome` is
    // already used locally for the agent-event emit result (see
    // `st.events.emit` below and in `buffered_managed`).
    let outcome_tag = outcome_header(&headers).unwrap_or_default();

    // Identity map (docs/20): which business unit this call belongs to, and,
    // in strict mode, whether the presented credential may speak as the
    // claimed agent id at all. `unit` is resolved server-side (never
    // caller-written) and rides into every CallRecord below; the mismatch
    // check gates before anything is routed, priced, or forwarded.
    let (unit, identity_mismatch) = {
        let resolution = st.identity.resolve(&key_id, &agent_id);
        (
            resolution.unit.unwrap_or_default().to_string(),
            resolution.mismatch,
        )
    };
    let mut identity_header: Option<String> = None;
    if let Some(mismatch) = identity_mismatch {
        match st.identity_strict {
            StrictMode::Off => {}
            StrictMode::Warn => {
                // Key lifecycle health (docs/22): warn mode still DETECTS
                // the mismatch, so it still counts, even though the call is
                // allowed through.
                st.keystats.record_identity_mismatch(&key_id);
                identity_header = Some(format!("would-block={}", mismatch.reason));
            }
            StrictMode::Enforce => {
                st.keystats.record_identity_mismatch(&key_id);
                let step = st
                    .ledger
                    .snapshot(&run_id)
                    .await
                    .map(|s| s.steps + 1)
                    .unwrap_or(1);
                st.sink.record(CallRecord {
                    ts_millis: now_millis(),
                    run_id: run_id.clone(),
                    model: parsed.model.clone(),
                    decision: "identity_mismatch".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    // Nothing was spent and no estimate exists yet on this
                    // path (it is derived further down, past this gate).
                    cost_microusd: 0,
                    step,
                    agent_id: agent_id.clone(),
                    saved_microusd: 0,
                    parent_run_id: parent_run_id.clone(),
                    on_behalf_of: on_behalf_of.clone(),
                    outcome: outcome_tag.clone(),
                    key_id: key_id.clone(),
                    unit: unit.clone(),
                    // Blocked before the request ever reached the provider -
                    // no response to observe (I1, docs/21-tool-runs.md).
                    tool_calls: None,
                });
                let outcome = st.events.emit(
                    EventType::IdentityMismatch,
                    now_millis(),
                    Some(&agent_id),
                    Some(&run_id),
                    (!on_behalf_of_chain.is_empty()).then_some(&on_behalf_of_chain),
                    serde_json::json!({
                        "key_id": key_id,
                        "agent_id": agent_id,
                        "reason": mismatch.reason,
                        "unit": (!unit.is_empty()).then_some(&unit),
                    }),
                    None,
                );
                crate::events::log_outcome(EventType::IdentityMismatch, outcome);
                return identity_block(&run_id, mismatch.reason);
            }
        }
    }

    // Model router (FinOps cost optimization): pick the cheapest model that
    // still meets this task's required quality tier, before anything below
    // prices, reserves, or forwards the request. Off is a true no-op:
    // nothing is computed, nothing is added. Shadow computes and reports the
    // decision without touching the request. On rewrites `parsed.model` and
    // the outgoing body's `model` field together, so every downstream
    // consumer (the kill-check's avoided-cost estimate, DLP, the cache
    // partition key, the real estimate/reserve/forward, and settle) sees one
    // consistent model identity for the rest of this request. Never routes a
    // model up to something pricier than what was asked for, unless a rule
    // explicitly requires a higher tier for the task's class -- see
    // router.rs for the exact contract.
    let mut router_header: Option<String> = None;
    let mut router_route: Option<(String, String)> = None;
    if st.router.mode != RouterMode::Off {
        let task_class = header_str(&headers, "x-fuse-task-type").unwrap_or_default();
        let decision = st.router.route(
            &parsed.model,
            &task_class,
            &st.prices,
            body.len(),
            parsed.max_tokens,
        );
        let mut applied = false;
        if st.router.mode == RouterMode::On && decision.routed() {
            if let Some(new_body) = rewrite_model_field(&body, &decision.chosen_model) {
                body = new_body;
                parsed.model = decision.chosen_model.clone();
                router_route = Some((
                    decision.original_model.clone(),
                    decision.chosen_model.clone(),
                ));
                applied = true;
            }
        }
        router_header = Some(if applied {
            decision.header_value()
        } else if st.router.mode == RouterMode::Shadow && decision.routed() {
            // Shadow observed a cheaper route but did NOT rewrite the body.
            // Mark it `would-...` so a consumer never mistakes a hypothetical
            // for an applied rewrite, mirroring the Wardryx shadow convention.
            format!("would-{}", decision.header_value())
        } else {
            format!("{}=kept", parsed.model)
        });
    }

    // Operator kill is a hard stop in any mode.
    if st.is_killed(&run_id) {
        let snap = st.ledger.snapshot(&run_id).await;
        let spent = snap.map(|s| s.spent).unwrap_or(Microusd::ZERO);
        let step = snap.map(|s| s.steps + 1).unwrap_or(1);
        // No estimate has been computed yet on this path (it's derived below,
        // once past the kill/DLP gates) — compute it locally so the avoided
        // spend is still captured for the trace.
        let estimate = estimate_cost(&st.prices, &parsed.model, body.len(), parsed.max_tokens)
            .unwrap_or(Microusd::ZERO);
        st.sink.record(CallRecord {
            ts_millis: now_millis(),
            run_id: run_id.clone(),
            model: parsed.model.clone(),
            decision: "killed".into(),
            input_tokens: 0,
            output_tokens: 0,
            cost_microusd: estimate.0,
            step,
            agent_id: agent_id.clone(),
            saved_microusd: 0,
            parent_run_id: parent_run_id.clone(),
            on_behalf_of: on_behalf_of.clone(),
            outcome: outcome_tag.clone(),
            key_id: key_id.clone(),
            unit: unit.clone(),
            // Blocked before the request ever reached the provider (I1).
            tool_calls: None,
        });
        let verdict = budget_verdict(
            BreakerReason::Killed,
            budget,
            spent,
            &st.policy_id,
            "run killed by operator",
        );
        emit_breaker_event(
            &st,
            &run_id,
            &agent_id,
            &on_behalf_of_chain,
            &verdict,
            &unit,
        );
        return breaker_error_response(&run_id, &verdict);
    }

    // DLP: scan the outgoing prompt for secrets. Block, mask, or just flag.
    let mut dlp_note: Option<String> = None;
    if st.dlp != DlpMode::Off {
        let text = String::from_utf8_lossy(&body).into_owned();
        let findings = dlp::scan(&text);
        if !findings.is_empty() {
            let summary = dlp::summary(&findings);
            match st.dlp {
                DlpMode::Block => {
                    let step = st
                        .ledger
                        .snapshot(&run_id)
                        .await
                        .map(|s| s.steps + 1)
                        .unwrap_or(1);
                    st.sink.record(CallRecord {
                        ts_millis: now_millis(),
                        run_id: run_id.clone(),
                        model: parsed.model.clone(),
                        decision: "dlp_blocked".into(),
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microusd: 0,
                        step,
                        agent_id: agent_id.clone(),
                        saved_microusd: 0,
                        parent_run_id: parent_run_id.clone(),
                        on_behalf_of: on_behalf_of.clone(),
                        outcome: outcome_tag.clone(),
                        key_id: key_id.clone(),
                        unit: unit.clone(),
                        // Blocked before the request ever reached the
                        // provider (I1).
                        tool_calls: None,
                    });
                    let outcome = st.events.emit(
                        EventType::DlpBlock,
                        now_millis(),
                        Some(&agent_id),
                        Some(&run_id),
                        (!on_behalf_of_chain.is_empty()).then_some(&on_behalf_of_chain),
                        serde_json::json!({ "summary": summary }),
                        None,
                    );
                    crate::events::log_outcome(EventType::DlpBlock, outcome);
                    return dlp_block(&run_id, &summary);
                }
                DlpMode::Mask => {
                    body = Bytes::from(dlp::redact(&text, &findings).into_bytes());
                    dlp_note = Some(format!("masked {summary}"));
                }
                DlpMode::Shadow => dlp_note = Some(format!("found {summary}")),
                DlpMode::Off => {}
            }
        }
    }

    // Semantic cache (non-streaming, tool-free requests only). A hit in `on`
    // mode short-circuits before we spend anything; in shadow it just annotates.
    let mut cache_ctx: Option<CacheCtx> = None;
    let mut cache_note: Option<String> = None;
    if !parsed.stream && st.cache.mode() != CacheMode::Off && cache_eligible(&request) {
        let task_type = header_str(&headers, "x-fuse-task-type").unwrap_or_default();
        let core = semantic_core(&request);
        let partition = SemanticCache::partition_key(
            &parsed.model,
            &system_text(&request),
            &tools_text(&request),
            &task_type,
            // Fixed single-tenant value: this gateway process serves one
            // tenant/deployment today, so there is no per-request tenant id
            // to pass here yet. See docs/06-semantic-cache.md ("Current
            // implementation note") before wiring a real tenant id in for a
            // shared/hosted multi-tenant gateway mode.
            "default",
        );
        if let Some(hit) = st.cache.get(partition, &core, now_millis()) {
            match st.cache.mode() {
                CacheMode::On => {
                    let step = st
                        .ledger
                        .snapshot(&run_id)
                        .await
                        .map(|s| s.steps + 1)
                        .unwrap_or(1);
                    st.sink.record(CallRecord {
                        ts_millis: now_millis(),
                        run_id: run_id.clone(),
                        model: parsed.model.clone(),
                        decision: "cache_hit".into(),
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microusd: 0,
                        step,
                        agent_id: agent_id.clone(),
                        // A served cache hit avoided this much real spend.
                        // (`buffered_managed`'s "allow" row can also carry a
                        // nonzero `saved_microusd` now, for router savings --
                        // the two never collide, since a cache hit returns
                        // here and never reaches that row.)
                        saved_microusd: hit.saved_microusd,
                        parent_run_id: parent_run_id.clone(),
                        on_behalf_of: on_behalf_of.clone(),
                        outcome: outcome_tag.clone(),
                        key_id: key_id.clone(),
                        unit: unit.clone(),
                        // `Some(0)`, not a guess: `cache_eligible` (below)
                        // only serves a cached hit for a request that
                        // declared no `tools` at all, so the model backing
                        // this cached response structurally could not have
                        // emitted a tool call (I1).
                        tool_calls: Some(0),
                    });
                    return cached_response(&run_id, &hit, st.policy.mode);
                }
                CacheMode::Shadow => {
                    cache_note = Some(format!(
                        "would-hit; similarity={:.3}; saved=${:.6}",
                        hit.similarity,
                        hit.saved_microusd as f64 / 1e6
                    ));
                }
                CacheMode::Off => {}
            }
        }
        cache_ctx = Some(CacheCtx { partition, core });
    }

    let estimate = estimate_cost(&st.prices, &parsed.model, body.len(), parsed.max_tokens)
        .unwrap_or(Microusd::ZERO);

    // `open_run` above just committed (the in-process ledger applies
    // synchronously; the raft ledger's write returned only after a majority
    // commit). But `snapshot()` here is a *local, eventually-consistent* read
    // (`RaftLedger::snapshot` -> `sm.read_run`, not the linearizable path) —
    // under burst load on a follower node, this node's own copy of the log
    // can legitimately still be catching up when the very next line reads it,
    // so `snapshot()` racing `open_run()` can return `None` for a run that
    // was just, correctly, opened. That is not a data-loss condition: a run
    // with no replicated snapshot yet has by definition had nothing reserved
    // or spent against it, so the accurate state *is* the zero/fresh
    // snapshot — this isn't a guess, it's the true value for that instant.
    // Fall back to it instead of panicking the worker (previously `.expect
    // ("run just opened")`, which dropped the request under exactly this
    // race). This does not weaken enforcement: the actual budget check is
    // `st.ledger.reserve()` below, which for the raft backend goes through
    // consensus against the authoritative committed state, not this local
    // read — so a stale/missing snapshot here can only affect the
    // pre-reserve policy pre-check (max-steps / per-step-cost), and for a
    // just-opened run steps=0 is correct regardless of replication lag.
    let snapshot = st.ledger.snapshot(&run_id).await.unwrap_or(RunSnapshot {
        budget,
        reserved: Microusd::ZERO,
        spent: Microusd::ZERO,
        steps: 0,
    });
    let eval = evaluate(&st.policy, &snapshot, estimate);

    // Loop / runaway detection. Signatures come from the request's own message
    // history; context growth from the per-run input-size tracker.
    let input_tokens = (body.len() as u64) / 4;
    let history = st.record_input(&run_id, input_tokens);
    let loop_reason = if st.policy.anomalies.is_empty() {
        None
    } else {
        let sigs = tokenfuse_core::loops::tool_call_signatures(&request);
        tokenfuse_core::loops::detect(&sigs, &history, &st.policy.anomalies)
    };

    // Enforce-mode blocks (step/max-steps first, then loops), before forwarding.
    if st.policy.mode == Mode::Enforce {
        if eval.decision.is_blocking() {
            st.sink.record(CallRecord {
                ts_millis: now_millis(),
                run_id: run_id.clone(),
                model: parsed.model.clone(),
                decision: "policy_violation".into(),
                input_tokens: 0,
                output_tokens: 0,
                cost_microusd: estimate.0,
                step: snapshot.steps + 1,
                agent_id: agent_id.clone(),
                saved_microusd: 0,
                parent_run_id: parent_run_id.clone(),
                on_behalf_of: on_behalf_of.clone(),
                outcome: outcome_tag.clone(),
                key_id: key_id.clone(),
                unit: unit.clone(),
                // Blocked before the request ever reached the provider (I1).
                tool_calls: None,
            });
            let verdict = budget_verdict(
                BreakerReason::PolicyViolation,
                budget,
                snapshot.spent,
                &st.policy_id,
                &eval.violated.clone().unwrap_or_default(),
            );
            emit_breaker_event(
                &st,
                &run_id,
                &agent_id,
                &on_behalf_of_chain,
                &verdict,
                &unit,
            );
            return breaker_error_response(&run_id, &verdict);
        }
        if let Some(reason) = &loop_reason {
            st.sink.record(CallRecord {
                ts_millis: now_millis(),
                run_id: run_id.clone(),
                model: parsed.model.clone(),
                decision: "loop_detected".into(),
                input_tokens: 0,
                output_tokens: 0,
                cost_microusd: estimate.0,
                step: snapshot.steps + 1,
                agent_id: agent_id.clone(),
                saved_microusd: 0,
                parent_run_id: parent_run_id.clone(),
                on_behalf_of: on_behalf_of.clone(),
                outcome: outcome_tag.clone(),
                key_id: key_id.clone(),
                unit: unit.clone(),
                // Blocked before the request ever reached the provider (I1).
                tool_calls: None,
            });
            let verdict = budget_verdict(
                BreakerReason::LoopDetected,
                budget,
                snapshot.spent,
                &st.policy_id,
                reason,
            );
            emit_breaker_event(
                &st,
                &run_id,
                &agent_id,
                &on_behalf_of_chain,
                &verdict,
                &unit,
            );
            return breaker_error_response(&run_id, &verdict);
        }
    }

    // Custom WASM policy (opt-in): a loaded policy can block on its own logic.
    if let Some(wasm) = &st.wasm {
        let taint_bits = if st.firewall.mode != FirewallMode::Off {
            taint::labels_for_tools(&taint::tool_names_in(&request), &st.firewall.sources)
                .iter()
                .map(|l| crate::wasmpolicy::label_bit(l))
                .fold(0u32, |a, b| a | b)
        } else {
            0
        };
        let decision = wasm.evaluate(
            estimate.0,
            snapshot.spent.0,
            budget.0,
            snapshot.steps,
            taint_bits,
        );
        if decision == 2 {
            st.sink.record(CallRecord {
                ts_millis: now_millis(),
                run_id: run_id.clone(),
                model: parsed.model.clone(),
                decision: "wasm_policy".into(),
                input_tokens: 0,
                output_tokens: 0,
                cost_microusd: estimate.0,
                step: snapshot.steps + 1,
                agent_id: agent_id.clone(),
                saved_microusd: 0,
                parent_run_id: parent_run_id.clone(),
                on_behalf_of: on_behalf_of.clone(),
                outcome: outcome_tag.clone(),
                key_id: key_id.clone(),
                unit: unit.clone(),
                // Blocked before the request ever reached the provider (I1).
                tool_calls: None,
            });
            let verdict = budget_verdict(
                BreakerReason::WasmPolicy,
                budget,
                snapshot.spent,
                &st.policy_id,
                "blocked by custom wasm policy",
            );
            emit_breaker_event(
                &st,
                &run_id,
                &agent_id,
                &on_behalf_of_chain,
                &verdict,
                &unit,
            );
            return breaker_error_response(&run_id, &verdict);
        }
    }

    // Wardryx enforcement hook (a PEP): ask the Wardryx policy service (a
    // PDP) whether this specific agent action should proceed, before
    // anything below reserves or forwards it. Defensive only: this can only
    // block/hold the operator's OWN call, it never acts on its behalf. Off
    // (the default) is a true no-op, no allocation and no network call.
    let mut wardryx_header: Option<String> = None;
    if st.wardryx.mode != WardryxMode::Off {
        let mut tool_names = taint::tool_names_in(&request);
        // A request-path PEP must also gate on tools the request DECLARES
        // (offered to the model), not only tools already invoked: a deny_tool
        // policy has to fire before the model can emit the tool_use that would
        // reveal the forbidden call. See taint::declared_tool_names_in.
        tool_names.extend(taint::declared_tool_names_in(&request));
        tool_names.sort();
        tool_names.dedup();
        let approval_token = header_str(&headers, "x-fuse-approval-token");
        let attestation_method = header_str(&headers, "x-fuse-attestation-method");
        let wardryx_outcome = st
            .wardryx
            .decide(DecideContext {
                agent_id: agent_id.clone(),
                run_id: run_id.clone(),
                on_behalf_of: on_behalf_of_chain.clone(),
                tool_names,
                // Best-effort, declared-only: domains this request's tools
                // explicitly name as an http(s) URL. Full runtime
                // tool-egress enforcement (blocking a tool from actually
                // reaching an undeclared domain when it is called) is the
                // MCP broker's job, not this hook's -- see
                // `referenced_domains`'s doc comment.
                domains: referenced_domains(&request),
                steps: snapshot.steps,
                model: parsed.model.clone(),
                est_cost_usd: estimate.as_usd(),
                attestation_method,
                approval_token,
            })
            .await;

        if st.wardryx.mode == WardryxMode::Shadow {
            // Shadow never blocks: just report what WOULD have happened.
            wardryx_header = Some(format!("would-{}", wardryx_outcome.decision.as_wire_str()));
        } else {
            match wardryx_outcome.decision {
                WardryxDecision::Allow => {
                    wardryx_header = Some(wardryx_outcome.decision.as_wire_str().to_string());
                }
                WardryxDecision::Deny => {
                    st.sink.record(CallRecord {
                        ts_millis: now_millis(),
                        run_id: run_id.clone(),
                        model: parsed.model.clone(),
                        // Distinct from the budget-family decisions: this is
                        // an avoided-harm security block, not avoided spend,
                        // so it must never be counted as budget savings.
                        decision: "wardryx_deny".into(),
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microusd: 0,
                        step: snapshot.steps + 1,
                        agent_id: agent_id.clone(),
                        saved_microusd: 0,
                        parent_run_id: parent_run_id.clone(),
                        on_behalf_of: on_behalf_of.clone(),
                        outcome: outcome_tag.clone(),
                        key_id: key_id.clone(),
                        unit: unit.clone(),
                        // Blocked before the request ever reached the
                        // provider (I1).
                        tool_calls: None,
                    });
                    // Wardryx already emits its own `source: wardryx` policy
                    // event, so there is no `st.events.emit` call here (it
                    // would be a duplicate).
                    return wardryx_deny_response(&run_id, &wardryx_outcome);
                }
                WardryxDecision::Hold => {
                    st.sink.record(CallRecord {
                        ts_millis: now_millis(),
                        run_id: run_id.clone(),
                        model: parsed.model.clone(),
                        decision: "wardryx_hold".into(),
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microusd: 0,
                        step: snapshot.steps + 1,
                        agent_id: agent_id.clone(),
                        saved_microusd: 0,
                        parent_run_id: parent_run_id.clone(),
                        on_behalf_of: on_behalf_of.clone(),
                        outcome: outcome_tag.clone(),
                        key_id: key_id.clone(),
                        unit: unit.clone(),
                        // Blocked before the request ever reached the
                        // provider (I1).
                        tool_calls: None,
                    });
                    // Stateless: the connection is not parked. The caller is
                    // expected to resubmit the same request later, carrying
                    // x-fuse-approval-token, once approved out of band.
                    return wardryx_hold_response(&run_id, &wardryx_outcome);
                }
            }
        }
    }

    // For shadow/warn, surface whichever signal tripped in the response header.
    let would_block = eval.violated.clone().or(loop_reason);

    // Unit budget gate (docs/20): the resolved unit's monthly cap, checked
    // BEFORE the run-level reserve so a unit-capped call never holds a run
    // reservation it is about to lose. Enforce blocks (402 with the UNIT's
    // numbers); shadow/warn record the unit spend without blocking, exactly
    // the contract run budgets have. `None` when no unit resolved or the
    // unit has no cap in effect: nothing reserved, nothing to settle.
    let unit_reservation: Option<UnitReservation> = if unit.is_empty() {
        None
    } else {
        match st.policy.mode {
            Mode::Enforce => match st.units.try_reserve(&unit, estimate, now_millis()) {
                Ok(r) => r,
                Err(exceeded) => {
                    st.sink.record(CallRecord {
                        ts_millis: now_millis(),
                        run_id: run_id.clone(),
                        model: parsed.model.clone(),
                        decision: "unit_budget_exceeded".into(),
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microusd: estimate.0,
                        step: snapshot.steps + 1,
                        agent_id: agent_id.clone(),
                        saved_microusd: 0,
                        parent_run_id: parent_run_id.clone(),
                        on_behalf_of: on_behalf_of.clone(),
                        outcome: outcome_tag.clone(),
                        key_id: key_id.clone(),
                        unit: unit.clone(),
                        // Blocked before the request ever reached the
                        // provider (I1).
                        tool_calls: None,
                    });
                    let verdict = budget_verdict(
                        BreakerReason::UnitBudgetExceeded,
                        exceeded.budget,
                        exceeded.spent,
                        &st.policy_id,
                        &format!("unit '{}' monthly budget exceeded", exceeded.unit),
                    );
                    emit_breaker_event(
                        &st,
                        &run_id,
                        &agent_id,
                        &on_behalf_of_chain,
                        &verdict,
                        &unit,
                    );
                    return breaker_error_response(&run_id, &verdict);
                }
            },
            Mode::Shadow | Mode::Warn => st.units.reserve_unchecked(&unit, estimate, now_millis()),
        }
    };

    // Budget gate: enforce uses the atomic checked reserve; shadow/warn record
    // the reservation without blocking.
    let reservation = match st.policy.mode {
        Mode::Enforce => match st.ledger.reserve(&run_id, estimate).await {
            Ok(r) => r,
            Err(BudgetError::Exceeded {
                run_id: hit_run,
                budget,
                spent,
                ..
            }) => {
                // The unit reservation above was taken optimistically;
                // release it (settle at zero) so a run-level refusal does
                // not leak reserved unit headroom.
                if let Some(ur) = &unit_reservation {
                    st.units.settle(ur, Microusd::ZERO, now_millis());
                }
                let reason = if hit_run == run_id {
                    "per-run budget exceeded".to_string()
                } else {
                    format!("parent run '{hit_run}' budget exceeded")
                };
                st.sink.record(CallRecord {
                    ts_millis: now_millis(),
                    run_id: run_id.clone(),
                    model: parsed.model.clone(),
                    decision: "budget_exceeded".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microusd: estimate.0,
                    step: snapshot.steps + 1,
                    agent_id: agent_id.clone(),
                    saved_microusd: 0,
                    parent_run_id: parent_run_id.clone(),
                    on_behalf_of: on_behalf_of.clone(),
                    outcome: outcome_tag.clone(),
                    key_id: key_id.clone(),
                    unit: unit.clone(),
                    // Blocked before the request ever reached the provider (I1).
                    tool_calls: None,
                });
                let verdict = budget_verdict(
                    BreakerReason::BudgetExceeded,
                    budget,
                    spent,
                    &st.policy_id,
                    &reason,
                );
                emit_breaker_event(
                    &st,
                    &run_id,
                    &agent_id,
                    &on_behalf_of_chain,
                    &verdict,
                    &unit,
                );
                return breaker_error_response(&run_id, &verdict);
            }
            Err(BudgetError::UnknownRun { .. }) => {
                if let Some(ur) = &unit_reservation {
                    st.units.settle(ur, Microusd::ZERO, now_millis());
                }
                // Unreachable today on both backends: the in-process ledger's
                // `open_run` (above, before this match) always registers
                // this exact `run_id` before `reserve` runs, and the raft
                // backend's `reserve` never returns `UnknownRun` at all (an
                // unknown/rejected run folds into `BudgetError::Exceeded`
                // there instead; see `RaftLedger::reserve` in
                // `raft_ledger.rs`). Kept explicit rather than deleted so a
                // future backend change can't quietly reopen this as a
                // budget-check bypass: fail CLOSED (deny) here, not the
                // `reserve_unchecked` bypass this arm used to call.
                st.sink.record(CallRecord {
                    ts_millis: now_millis(),
                    run_id: run_id.clone(),
                    model: parsed.model.clone(),
                    decision: "budget_exceeded".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microusd: estimate.0,
                    step: snapshot.steps + 1,
                    agent_id: agent_id.clone(),
                    saved_microusd: 0,
                    parent_run_id: parent_run_id.clone(),
                    on_behalf_of: on_behalf_of.clone(),
                    outcome: outcome_tag.clone(),
                    key_id: key_id.clone(),
                    unit: unit.clone(),
                    // Blocked before the request ever reached the provider (I1).
                    tool_calls: None,
                });
                let verdict = budget_verdict(
                    BreakerReason::BudgetExceeded,
                    Microusd::ZERO,
                    Microusd::ZERO,
                    &st.policy_id,
                    &format!(
                        "run '{run_id}' has no ledger reservation; denying instead of bypassing the budget check"
                    ),
                );
                emit_breaker_event(
                    &st,
                    &run_id,
                    &agent_id,
                    &on_behalf_of_chain,
                    &verdict,
                    &unit,
                );
                return breaker_error_response(&run_id, &verdict);
            }
        },
        Mode::Shadow | Mode::Warn => st.ledger.reserve_unchecked(&run_id, estimate).await,
    };

    // Agent firewall: accumulate the run's taint from this request (header +
    // tool history) so the response's tool calls can be judged against it.
    // Computed before `send` consumes `headers`.
    let firewall_labels = if st.firewall.mode != FirewallMode::Off {
        let mut labels = taint_header_labels(&headers);
        labels.extend(taint::labels_for_tools(
            &taint::tool_names_in(&request),
            &st.firewall.sources,
        ));
        st.accumulate_taint(&run_id, labels)
    } else {
        Labels::new()
    };

    let resp = match st.provider.send(headers, body).await {
        Ok(r) => r,
        Err(e) => {
            // Failed call cost us nothing - release the reservation(s).
            st.ledger.settle(&reservation, Microusd::ZERO);
            if let Some(ur) = &unit_reservation {
                st.units.settle(ur, Microusd::ZERO, now_millis());
            }
            return upstream_error(e);
        }
    };

    if parsed.stream {
        stream_managed(
            resp,
            reservation,
            would_block,
            dlp_note,
            &parsed.model,
            &st,
            agent_id,
            parent_run_id,
            on_behalf_of,
            outcome_tag,
            key_id,
            unit,
            unit_reservation,
            identity_header,
            router_header,
            wardryx_header,
        )
    } else {
        buffered_managed(
            resp,
            reservation,
            would_block,
            dlp_note,
            &parsed.model,
            &st,
            cache_ctx,
            cache_note,
            firewall_labels,
            &agent_id,
            &parent_run_id,
            &on_behalf_of,
            &on_behalf_of_chain,
            &outcome_tag,
            &key_id,
            &unit,
            unit_reservation,
            identity_header,
            router_header,
            router_route,
            wardryx_header,
        )
        .await
    }
}

/// Add `name: value` to `builder`, but only if `value` is representable as a
/// legal HTTP header value (no CR, LF, or other control bytes). Some header
/// values are built from client-controlled strings with no header-safety
/// guarantee of their own: `x-fuse-router`'s value embeds the request
/// body's `model` field verbatim (see `RouteDecision::header_value` in
/// `router.rs`), so a request like `{"model":"foo\nbar"}` must never reach
/// the `.expect("valid response")` at the end of a response-builder chain
/// unguarded. Dropping the header on a malformed value is correct and
/// lossless: every header this helper guards is purely informational,
/// unlike the enforcement-path status/body/headers pinned by
/// `breaker_error_response_matches_budget_error_byte_for_byte` (that path
/// never calls this helper, see invariant #2 in CLAUDE.md).
///
/// Mirrors the `x-fuse-approval-id` guard added to `wardryx_hold_response`
/// in PR #104 for the same panic class on the Wardryx PDP's echoed approval
/// id: this generalizes that fix to the router header's vector, a
/// client-supplied model name instead of a PDP response field.
fn set_header_checked(builder: Builder, name: &'static str, value: &str) -> Builder {
    match HeaderValue::from_str(value) {
        Ok(v) => builder.header(name, v),
        Err(_) => {
            tracing::debug!(
                header = name,
                "dropping header value illegal for HTTP (client-controlled string contained a disallowed byte)"
            );
            builder
        }
    }
}

/// Streaming managed response: pass chunks through and settle at end-of-stream.
/// Cost headers are omitted because headers are sent before the body — the
/// settled figures go to the ledger (and, later, the event sink).
#[allow(clippy::too_many_arguments)]
fn stream_managed(
    resp: ProviderResponse,
    reservation: Reservation,
    would_block: Option<String>,
    dlp_note: Option<String>,
    model: &str,
    st: &AppState,
    agent_id: String,
    parent_run_id: String,
    on_behalf_of: String,
    outcome: String,
    key_id: String,
    unit: String,
    unit_reservation: Option<UnitReservation>,
    identity_header: Option<String>,
    router_header: Option<String>,
    wardryx_header: Option<String>,
) -> Response {
    let inner = resp.body;
    // Capture the header values before `reservation` is moved into the guard.
    let run_id = reservation.run_id.clone();
    let step = reservation.step;
    let guard = SettleGuard::new(
        st.ledger.clone(),
        st.prices.clone(),
        st.sink.clone(),
        model.to_string(),
        resp.usage.clone(),
        reservation.amount,
        reservation,
        agent_id,
        parent_run_id,
        on_behalf_of,
        outcome,
        key_id,
        unit,
        st.units.clone(),
        unit_reservation,
    );

    // The guard settles at end-of-stream via `complete()`; if this future is
    // dropped first (client cancel) or an upstream error propagates via `?`, the
    // guard's Drop settles instead, so the reservation is never leaked.
    let wrapped = async_stream::try_stream! {
        let guard = guard;
        futures::pin_mut!(inner);
        while let Some(chunk) = inner.next().await {
            let chunk = chunk?;
            yield chunk;
        }
        guard.complete();
    };
    // Pin with an explicit error type so `Body::from_stream` can pick up the
    // `Into<BoxError>` bound.
    let wrapped: futures::stream::BoxStream<'static, Result<Bytes, ProviderError>> =
        Box::pin(wrapped);

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK))
        .header(
            "content-type",
            resp.content_type.as_deref().unwrap_or("text/event-stream"),
        )
        .header("x-fuse", "managed")
        .header("x-fuse-stream", "passthrough")
        .header("x-fuse-run-id", run_id)
        .header("x-fuse-step", step.to_string())
        .header("x-fuse-mode", mode_str(st.policy.mode));
    if let Some(reason) = would_block {
        builder = builder.header("x-fuse-would-block", reason);
    }
    if let Some(note) = dlp_note {
        builder = builder.header("x-fuse-dlp", note);
    }
    if let Some(rh) = router_header {
        builder = set_header_checked(builder, "x-fuse-router", &rh);
    }
    if let Some(wh) = wardryx_header {
        builder = builder.header("x-fuse-wardryx", wh);
    }
    if let Some(ih) = identity_header {
        builder = builder.header("x-fuse-identity", ih);
    }
    builder
        .body(Body::from_stream(wrapped))
        .expect("valid response")
}

/// Non-streaming managed response: buffer the body, settle with the exact cost,
/// and return full `x-fuse-*` accounting headers.
#[allow(clippy::too_many_arguments)]
async fn buffered_managed(
    resp: ProviderResponse,
    reservation: Reservation,
    would_block: Option<String>,
    dlp_note: Option<String>,
    model: &str,
    st: &AppState,
    cache_ctx: Option<CacheCtx>,
    cache_note: Option<String>,
    firewall_labels: Labels,
    agent_id: &str,
    parent_run_id: &str,
    on_behalf_of: &str,
    on_behalf_of_chain: &[String],
    outcome_tag: &str,
    key_id: &str,
    unit: &str,
    unit_reservation: Option<UnitReservation>,
    identity_header: Option<String>,
    router_header: Option<String>,
    router_route: Option<(String, String)>,
    wardryx_header: Option<String>,
) -> Response {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK);
    let content_type = resp
        .content_type
        .clone()
        .unwrap_or_else(|| "application/json".to_string());

    let bytes = match collect(resp.body).await {
        Ok(b) => b,
        Err(e) => {
            st.ledger.settle(&reservation, Microusd::ZERO);
            if let Some(ur) = &unit_reservation {
                st.units.settle(ur, Microusd::ZERO, now_millis());
            }
            return upstream_error(e);
        }
    };

    let usage = resp.usage.lock().unwrap().take();
    let actual = usage
        .as_ref()
        .and_then(|u| st.prices.cost(model, u))
        .unwrap_or(reservation.amount);
    st.ledger.settle(&reservation, actual);
    if let Some(ur) = &unit_reservation {
        st.units.settle(ur, actual, now_millis());
    }
    let spent = st
        .ledger
        .snapshot(&reservation.run_id)
        .await
        .map(|s| s.spent)
        .unwrap_or(actual);

    // Router savings (FinOps): when this call was actually routed to a
    // cheaper model (see the router step in `messages`), the difference
    // between what the originally requested model would have cost for this
    // exact usage and what the chosen model actually cost is real avoided
    // spend. Fold it into `saved_microusd` on this row so it rolls up
    // through the same accounting path cache hits use, distinguishable by
    // `decision == "allow"` (a cache hit records its own `cache_hit` row and
    // returns before reaching here, so an "allow" row with nonzero
    // `saved_microusd` can only come from the router). `saturating_sub`
    // keeps this at zero rather than negative on the one case the router
    // routes up (an explicit higher-tier requirement) -- there is no
    // "savings" to report when the call ended up pricier than requested.
    let router_saved = match (&router_route, usage.as_ref()) {
        (Some((original_model, chosen_model)), Some(u)) => {
            match (
                st.prices.cost(original_model, u),
                st.prices.cost(chosen_model, u),
            ) {
                (Some(would_have_cost), Some(did_cost)) => would_have_cost.saturating_sub(did_cost),
                _ => Microusd::ZERO,
            }
        }
        _ => Microusd::ZERO,
    };

    let u = usage.unwrap_or_default();
    st.sink.record(CallRecord {
        ts_millis: now_millis(),
        run_id: reservation.run_id.clone(),
        model: model.to_string(),
        decision: "allow".into(),
        input_tokens: u.input_tokens,
        output_tokens: u.output_tokens,
        cost_microusd: actual.0,
        step: reservation.step,
        agent_id: agent_id.to_string(),
        saved_microusd: router_saved.0,
        parent_run_id: parent_run_id.to_string(),
        on_behalf_of: on_behalf_of.to_string(),
        outcome: outcome_tag.to_string(),
        key_id: key_id.to_string(),
        unit: unit.to_string(),
        // The model-emitted tool-call count parsed out of this response's
        // body, same source as `input_tokens`/`output_tokens` above (I1,
        // docs/21-tool-runs.md).
        tool_calls: u.tool_calls,
    });

    // Agent firewall: judge the model's requested tool calls against the run's
    // accumulated taint. Enforce → 403; shadow/warn → header note.
    let mut firewall_note: Option<String> = None;
    if st.firewall.mode != FirewallMode::Off {
        let resp_json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        let resp_tools = taint::tool_names_in(&resp_json);
        let requested = taint::capabilities_for_tools(&resp_tools, &st.firewall.capabilities);
        if let Some(reason) = taint::evaluate(&firewall_labels, &requested, &st.firewall.rules) {
            if st.firewall.mode == FirewallMode::Enforce {
                // The call already happened and its real cost was recorded as
                // "allow" above — this second record is the security verdict
                // that blocks the *response* from reaching the caller, so it
                // carries no additional cost (avoids double-counting spend).
                st.sink.record(CallRecord {
                    ts_millis: now_millis(),
                    run_id: reservation.run_id.clone(),
                    model: model.to_string(),
                    decision: "taint_blocked".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microusd: 0,
                    step: reservation.step,
                    agent_id: agent_id.to_string(),
                    saved_microusd: 0,
                    parent_run_id: parent_run_id.to_string(),
                    on_behalf_of: on_behalf_of.to_string(),
                    outcome: outcome_tag.to_string(),
                    key_id: key_id.to_string(),
                    unit: unit.to_string(),
                    // The real observation already landed on the sibling
                    // "allow" row above; this verdict row isn't a second
                    // model response, so it carries none of its own (I1).
                    tool_calls: None,
                });
                let outcome = st.events.emit(
                    EventType::TaintBlock,
                    now_millis(),
                    Some(agent_id),
                    Some(&reservation.run_id),
                    (!on_behalf_of_chain.is_empty()).then_some(on_behalf_of_chain),
                    serde_json::json!({ "reason": reason }),
                    None,
                );
                crate::events::log_outcome(EventType::TaintBlock, outcome);
                return firewall_block(&reservation.run_id, &reason);
            }
            firewall_note = Some(reason);
        }
        // Executing these tools will taint future turns — record their labels now.
        st.accumulate_taint(
            &reservation.run_id,
            taint::labels_for_tools(&resp_tools, &st.firewall.sources),
        );
    }

    // Store a successful response for future cache hits.
    if status == StatusCode::OK {
        if let Some(ctx) = cache_ctx {
            st.cache.put(
                ctx.partition,
                &ctx.core,
                bytes.clone(),
                content_type.clone(),
                actual.0,
                now_millis(),
            );
        }
    }

    let mut builder = Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("x-fuse", "managed")
        .header("x-fuse-run-id", reservation.run_id.clone())
        .header("x-fuse-step", reservation.step.to_string())
        .header("x-fuse-mode", mode_str(st.policy.mode))
        .header("x-fuse-cost-usd", format!("{:.6}", actual.as_usd()))
        .header("x-fuse-spent-usd", format!("{:.6}", spent.as_usd()))
        .header(
            "x-fuse-price",
            if st.prices.is_known(model) {
                "known"
            } else {
                "fallback"
            },
        );
    if let Some(reason) = would_block {
        builder = builder.header("x-fuse-would-block", reason);
    }
    if let Some(note) = cache_note {
        builder = builder.header("x-fuse-cache", note);
    }
    if let Some(note) = firewall_note {
        builder = builder.header("x-fuse-taint", format!("would-block: {note}"));
    }
    if let Some(note) = dlp_note {
        builder = builder.header("x-fuse-dlp", note);
    }
    if let Some(rh) = router_header {
        builder = set_header_checked(builder, "x-fuse-router", &rh);
    }
    if let Some(wh) = wardryx_header {
        builder = builder.header("x-fuse-wardryx", wh);
    }
    if let Some(ih) = identity_header {
        builder = builder.header("x-fuse-identity", ih);
    }
    builder.body(Body::from(bytes)).expect("valid response")
}

/// DLP block: a secret was found in the outgoing prompt.
/// The caller's `key_id`, or `None` if their credential does not admit them.
///
/// `Some("")` when client keys are not configured: the gateway then behaves
/// exactly as it did before this existed, which is what keeps a drop-in proxy
/// drop-in on upgrade. So `Some` means "allowed, with this identity" and the
/// identity is allowed to be empty; only `None` refuses.
///
/// When keys ARE configured this fails closed, and a missing header and an
/// unknown secret both yield `None` - deliberately indistinguishable, since
/// telling the caller which of the two they got wrong tells an attacker
/// whether a secret exists.
fn resolve_client_key(st: &AppState, headers: &HeaderMap) -> Option<String> {
    if !st.client_keys.enabled() {
        return Some(String::new());
    }
    let presented = header_str(headers, crate::clientkeys::CLIENT_KEY_HEADER).unwrap_or_default();
    st.client_keys
        .resolve(presented.trim())
        .map(ToString::to_string)
}

/// `401` for a metered call with no usable client credential. Never echoes the
/// presented secret back, not even truncated: an error body is exactly the
/// place a credential ends up in someone's log aggregator.
///
/// Also stamps the aggregate unauthorized counter (`stats`,
/// docs/22-key-lifecycle.md) - the only side effect this function gains for
/// that feature. The response bytes and headers below are unchanged: the
/// counter is aggregate-only and never keyed by the presented secret, so it
/// cannot narrow the "missing vs unknown credential" distinction this
/// response deliberately elides.
fn unauthorized(stats: &KeyStats) -> Response {
    stats.record_unauthorized();
    let body = serde_json::json!({
        "error": {
            "type": "unauthorized",
            "reason": format!(
                "this gateway requires a client credential in the `{}` header",
                crate::clientkeys::CLIENT_KEY_HEADER
            ),
            "retryable": false,
        }
    });
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .header("x-fuse", "unauthorized")
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

fn dlp_block(run_id: &str, summary: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "type": "dlp_blocked",
            "run_id": run_id,
            "reason": summary,
            "retryable": false,
        }
    });
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("x-fuse", "blocked")
        .header("x-fuse-run-id", run_id.to_string())
        .header("x-fuse-dlp", format!("blocked: {summary}"))
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

/// Firewall block: the model asked for a capability denied under the run's taint.
fn firewall_block(run_id: &str, reason: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "type": "taint_blocked",
            "run_id": run_id,
            "reason": reason,
            "retryable": false,
        }
    });
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("x-fuse", "blocked")
        .header("x-fuse-run-id", run_id.to_string())
        .header("x-fuse-taint", format!("blocked: {reason}"))
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

/// Identity mismatch (docs/20): strict mode refused to let the presented
/// credential speak as the claimed agent id. A 403 auth-family block like
/// `dlp_block`/`firewall_block`; the body comes from the Breaker facade's
/// minimal shape (no budget fields), keeping the wire contract in one place.
fn identity_block(run_id: &str, reason: &str) -> Response {
    let verdict = BreakerVerdict {
        tripped: true,
        reason: Some(BreakerReason::IdentityMismatch),
        detail: Some(reason.to_string()),
        budget_usd: None,
        spent_usd: None,
        policy_id: None,
        would_trip_only: false,
    };
    let body = verdict.to_error_json(run_id);
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("x-fuse", "blocked")
        .header("x-fuse-run-id", run_id.to_string())
        .header("x-fuse-identity", format!("blocked={reason}"))
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

/// Wardryx deny: the PDP denied this agent action outright. Mirrors
/// `dlp_block`/`firewall_block`'s response shape (a 403, not the 402 budget
/// breaker): this is a policy denial, not a budget one.
fn wardryx_deny_response(run_id: &str, outcome: &WardryxOutcome) -> Response {
    let reason = outcome.reason.as_deref().unwrap_or("denied by policy");
    let body = serde_json::json!({
        "error": {
            "type": "wardryx_denied",
            "run_id": run_id,
            "reason": reason,
            "policy_version": outcome.policy_version,
            "retryable": false,
        }
    });
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("x-fuse", "blocked")
        .header("x-fuse-run-id", run_id.to_string())
        .header("x-fuse-wardryx", "deny")
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

/// Wardryx hold: the PDP wants this specific call approved (by a human, or
/// some other out-of-band process) before it proceeds. Stateless: the
/// gateway does not park the connection or poll for the approval. The
/// caller is expected to resubmit the exact same request once approved,
/// carrying the approval id via `x-fuse-approval-token`.
fn wardryx_hold_response(run_id: &str, outcome: &WardryxOutcome) -> Response {
    let approval_id = outcome.approval_id.as_deref().unwrap_or_default();
    let reason = outcome.reason.as_deref().unwrap_or("held pending approval");
    let body = serde_json::json!({
        "error": {
            "type": "wardryx_hold",
            "run_id": run_id,
            "reason": reason,
            "approval_id": approval_id,
            "approval_token_required": outcome.approval_token_required,
            "policy_version": outcome.policy_version,
            "detail": "resubmit this request with header x-fuse-approval-token after approval",
            "retryable": true,
        }
    });
    let mut builder = Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("x-fuse", "blocked")
        .header("x-fuse-run-id", run_id.to_string())
        .header("x-fuse-wardryx", "hold");
    // `approval_id` is echoed verbatim from the external Wardryx PDP. Only
    // surface it as a header if it is a legal header value; a malformed id
    // must never panic this request's task. The JSON body always carries the
    // approval_id regardless, so no information is lost when the header is
    // dropped.
    if let Ok(v) = HeaderValue::from_str(approval_id) {
        builder = builder.header("x-fuse-approval-id", v);
    }
    builder
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())
                .expect("a static 403 with an empty body always builds")
        })
}

/// Parse the `X-Fuse-Taint` header (comma-separated labels the caller declares).
fn taint_header_labels(headers: &HeaderMap) -> Labels {
    header_str(headers, "x-fuse-taint")
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_lowercase())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Build a response served straight from the semantic cache.
fn cached_response(run_id: &str, hit: &Lookup, mode: Mode) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", hit.content_type.clone())
        .header("x-fuse", "cached")
        .header("x-fuse-cache", "hit")
        .header("x-fuse-run-id", run_id.to_string())
        .header("x-fuse-mode", mode_str(mode))
        .header("x-fuse-similarity", format!("{:.3}", hit.similarity))
        .header("x-fuse-cost-usd", "0.000000")
        .header(
            "x-fuse-saved-usd",
            format!("{:.6}", hit.saved_microusd as f64 / 1e6),
        )
        .body(Body::from(hit.response.clone()))
        .expect("valid response")
}

/// Unmanaged pass-through (no run id): stream the upstream body straight back
/// with no accounting.
fn passthrough(resp: ProviderResponse, managed: &str) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK))
        .header(
            "content-type",
            resp.content_type.as_deref().unwrap_or("application/json"),
        )
        .header("x-fuse", managed)
        .body(Body::from_stream(resp.body))
        .expect("valid response")
}

async fn collect(
    mut body: futures::stream::BoxStream<'static, Result<Bytes, ProviderError>>,
) -> Result<Vec<u8>, ProviderError> {
    let mut acc = Vec::new();
    while let Some(chunk) = body.next().await {
        acc.extend_from_slice(&chunk?);
    }
    Ok(acc)
}

/// Build a budget-family block response from a `BreakerVerdict`, the single
/// owner of the 402 budget/policy/loop/kill/wasm wire contract. Status, body,
/// and headers are byte-identical to the pre-refactor `budget_error` builder;
/// the verdict's `to_error_json` mirrors that JSON shape exactly.
fn breaker_error_response(run_id: &str, verdict: &BreakerVerdict) -> Response {
    let status = verdict
        .reason
        .map(BreakerReason::http_status)
        .and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or(StatusCode::PAYMENT_REQUIRED);
    let body = verdict.to_error_json(run_id);
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-fuse", "blocked")
        .header("x-fuse-run-id", run_id)
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

/// Construct the 402 budget-family verdict the five block sites share: tripped,
/// with budget/spent/policy_id always present (matching the old `budget_error`
/// args) and `detail` carrying the human-readable reason string.
fn budget_verdict(
    reason: BreakerReason,
    budget: Microusd,
    spent: Microusd,
    policy_id: &str,
    detail: &str,
) -> BreakerVerdict {
    BreakerVerdict {
        tripped: true,
        reason: Some(reason),
        detail: Some(detail.to_string()),
        budget_usd: Some(budget.as_usd()),
        spent_usd: Some(spent.as_usd()),
        policy_id: Some(policy_id.to_string()),
        would_trip_only: false,
    }
}

fn upstream_error(e: ProviderError) -> Response {
    let body =
        serde_json::json!({ "error": { "type": "upstream_error", "detail": e.to_string() } });
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

struct ParsedRequest {
    model: String,
    max_tokens: Option<u64>,
    stream: bool,
}

fn parse_request(value: &serde_json::Value) -> ParsedRequest {
    ParsedRequest {
        model: value
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown")
            .to_string(),
        max_tokens: value.get("max_tokens").and_then(|m| m.as_u64()),
        stream: value
            .get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false),
    }
}

/// Re-serialize `body` with its top-level `"model"` field set to `model`
/// (the router's chosen candidate), the same "parse, mutate, re-serialize"
/// shape the DLP mask path already uses to rewrite the outgoing body.
/// Returns `None` if `body` is not a JSON object we can safely rewrite, so
/// the caller can fail safe and leave the request untouched rather than
/// forward a body/estimate mismatch.
fn rewrite_model_field(body: &Bytes, model: &str) -> Option<Bytes> {
    let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let obj = value.as_object_mut()?;
    obj.insert(
        "model".to_string(),
        serde_json::Value::String(model.to_string()),
    );
    serde_json::to_vec(&value).ok().map(Bytes::from)
}

/// A request is cache-eligible only if it defines no tools (tool calls can have
/// side effects and must not be replayed from cache).
fn cache_eligible(request: &serde_json::Value) -> bool {
    match request.get("tools") {
        None => true,
        Some(serde_json::Value::Array(a)) => a.is_empty(),
        Some(_) => false,
    }
}

/// The system prompt text (Anthropic `system` field), for the partition key.
/// Handles both shapes Anthropic's API accepts: a plain string, and an array
/// of content blocks (the shape used with `cache_control` for prompt
/// caching, e.g. `[{"type":"text","text":"..."}]`). Two requests with
/// different array-shaped system prompts must produce different output here
/// -- otherwise they'd land in the same cache partition and one tenant/agent
/// could be served another's response generated under a different system
/// prompt, violating the hard-partition guarantee documented on
/// `SemanticCache::partition_key` (crates/core/src/cache.rs).
fn system_text(request: &serde_json::Value) -> String {
    match request.get("system") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(blocks)) => concat_text_blocks(blocks),
        _ => String::new(),
    }
}

/// Concatenates the `text` field of each text-shaped content block in an
/// Anthropic content-block array (e.g. `[{"type":"text","text":"..."}]`),
/// space-separated and trimmed. Shared by `system_text` (the `system`
/// field) and `semantic_core` (a message's `content` field) -- both accept
/// this same array shape from the Anthropic API.
fn concat_text_blocks(blocks: &[serde_json::Value]) -> String {
    let mut buf = String::new();
    for b in blocks {
        if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
            buf.push_str(t);
            buf.push(' ');
        }
    }
    buf.trim().to_string()
}

/// A stable string for the tools schema, for the partition key.
fn tools_text(request: &serde_json::Value) -> String {
    request
        .get("tools")
        .map(|t| t.to_string())
        .unwrap_or_default()
}

/// Best-effort extraction of domains this request's declared tools
/// reference, for Wardryx's `domains` field (see `wardryx::DecideContext`).
/// Walks every string value nested anywhere under the top-level `"tools"`
/// field -- any depth, since Anthropic native tools, OpenAI functions, and
/// MCP tool wrappers all shape a tool definition differently -- and keeps
/// the ones that parse as an absolute http(s) URL, collecting each one's
/// lowercased host, deduplicated. Returns an empty vec when the request has
/// no `"tools"` field, an empty `"tools"` array, or no URL-shaped string
/// anywhere in it: a plain LLM call with no URL-bearing tools declares
/// nothing to restrict, which Wardryx treats as a no-op, never a denial.
///
/// Deliberately narrow: a string has to BE a URL (the whole value parses
/// with `reqwest::Url`, scheme http/https), not merely mention one --
/// this never regex-searches prose (a tool description, a system prompt)
/// for an embedded URL. That keeps it bounded and simple, at the cost of
/// missing a URL a tool schema only names in free text; the task this
/// serves is "what did the request explicitly declare," not "find every
/// URL anywhere."
///
/// This only covers domains DECLARED in the request. Full runtime
/// tool-egress enforcement (stopping a tool from actually reaching a URL
/// at call time, declared or not) is the MCP broker's responsibility, not
/// this gateway hook's.
fn referenced_domains(request: &serde_json::Value) -> Vec<String> {
    let Some(tools) = request.get("tools") else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    collect_url_hosts(tools, 0, &mut hosts);
    hosts.sort();
    hosts.dedup();
    hosts
}

/// A tool schema is never more than a handful of levels deep in practice
/// (array -> tool object -> input_schema -> properties -> property object),
/// so this is a generous hard stop against a pathologically nested request
/// body, not a realistic limit.
const MAX_DOMAIN_SCAN_DEPTH: usize = 12;

/// Recursive walk backing [`referenced_domains`]: collects the lowercased
/// host of every string value, at any depth under `value`, that parses as
/// an absolute http(s) URL.
fn collect_url_hosts(value: &serde_json::Value, depth: usize, out: &mut Vec<String>) {
    if depth > MAX_DOMAIN_SCAN_DEPTH {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            if let Ok(url) = reqwest::Url::parse(s) {
                if url.scheme() == "http" || url.scheme() == "https" {
                    if let Some(host) = url.host_str() {
                        out.push(host.to_ascii_lowercase());
                    }
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_url_hosts(item, depth + 1, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_url_hosts(v, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// The "semantic core" of a request: the last user message's text, truncated.
/// Handles Anthropic (string or content-block array) and OpenAI (string).
fn semantic_core(request: &serde_json::Value) -> String {
    let mut text = String::new();
    if let Some(messages) = request.get("messages").and_then(|m| m.as_array()) {
        for msg in messages.iter().rev() {
            if msg.get("role").and_then(|r| r.as_str()) != Some("user") {
                continue;
            }
            match msg.get("content") {
                Some(serde_json::Value::String(s)) => text = s.clone(),
                Some(serde_json::Value::Array(blocks)) => text = concat_text_blocks(blocks),
                _ => {}
            }
            break;
        }
    }
    text.chars().take(512).collect()
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn header_f64(headers: &HeaderMap, name: &str) -> Option<f64> {
    header_str(headers, name).and_then(|s| s.parse().ok())
}

fn mode_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Shadow => "shadow",
        Mode::Warn => "warn",
        Mode::Enforce => "enforce",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_backend::{LedgerBackend, LocalLedger};
    use crate::provider::StubProvider;
    use crate::sink::EventSink;
    use axum::body::to_bytes;
    use axum::http::Request;
    use std::sync::{Arc, Mutex};
    use tokenfuse_core::{Ledger, ModelPrice, Policy, PriceBook};
    use tower::ServiceExt;

    /// Test-only serialization lock for the shared `OUTCOME_OVERCAP` process
    /// global (test-isolation only, not a production concern). `cargo test`
    /// runs tests in parallel threads within one process, and every test
    /// that pushes an over-cap `x-fuse-outcome` header through
    /// `outcome_header` increments the same counter. Without this lock,
    /// `outcome_header_over_cap_is_ignored_not_rejected`'s
    /// before/increment/assert window can be interleaved by another test's
    /// increment landing in between, making the observed delta more than 1
    /// and the assert fail intermittently. Every test that reads or
    /// increments `OUTCOME_OVERCAP` must hold this for its full body.
    /// `unwrap_or_else(|e| e.into_inner())` (not `unwrap()`) so a panic in
    /// one guarded test does not poison-cascade the rest into failing too.
    static OVERCAP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// An in-memory `EventSink` test double. Cheap to clone — the clone shares
    /// the same underlying buffer — so a handle can be kept in the test while
    /// the sink itself is moved into `AppState`.
    #[derive(Clone, Default)]
    struct RecordingSink {
        records: Arc<Mutex<Vec<CallRecord>>>,
    }

    impl RecordingSink {
        fn snapshot(&self) -> Vec<CallRecord> {
            self.records.lock().unwrap().clone()
        }
    }

    impl EventSink for RecordingSink {
        fn record(&self, rec: CallRecord) {
            self.records.lock().unwrap().push(rec);
        }
        fn flush(&self) {}
    }

    /// A `LedgerBackend` that delegates everything to a real in-process
    /// ledger *except* `snapshot`, which always reports `None` — a
    /// deterministic stand-in for `RaftLedger::snapshot` racing `open_run`
    /// under replication lag (see `raft_ledger.rs`: `snapshot` is a local,
    /// eventually-consistent read; `open_run`'s write only needs a majority
    /// commit, so this node's own copy can still be catching up when the
    /// very next request reads it). Reserve/settle still go through the real
    /// ledger, so this proves the handler's fallback doesn't just avoid a
    /// panic but still enforces and settles correctly.
    struct SnapshotLaggingLedger(LocalLedger);

    #[async_trait::async_trait]
    impl LedgerBackend for SnapshotLaggingLedger {
        async fn open_run(&self, run_id: &str, budget: Microusd, parent: Option<&str>) {
            self.0.open_run(run_id, budget, parent).await;
        }

        async fn reserve(
            &self,
            run_id: &str,
            estimate: Microusd,
        ) -> Result<Reservation, BudgetError> {
            self.0.reserve(run_id, estimate).await
        }

        async fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation {
            self.0.reserve_unchecked(run_id, estimate).await
        }

        async fn snapshot(&self, _run_id: &str) -> Option<RunSnapshot> {
            None
        }

        async fn list_runs(&self) -> Vec<(String, RunSnapshot)> {
            self.0.list_runs().await
        }

        fn settle(&self, reservation: &Reservation, actual: Microusd) {
            self.0.settle(reservation, actual);
        }
    }

    fn state(mode: Mode, provider: StubProvider) -> AppState {
        let prices = PriceBook::new().with(
            "test-model",
            ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
        );
        AppState::new(
            Arc::new(Ledger::new()),
            Arc::new(prices),
            Arc::new(Policy {
                mode,
                ..Default::default()
            }),
            Arc::new(provider),
            "test-policy",
        )
    }

    fn body(max_tokens: u64) -> String {
        format!(r#"{{"model":"test-model","max_tokens":{max_tokens}}}"#)
    }

    fn body_stream(max_tokens: u64) -> String {
        format!(r#"{{"model":"test-model","max_tokens":{max_tokens},"stream":true}}"#)
    }

    async fn call(st: AppState, req: Request<Body>) -> Response {
        crate::app(st).oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn healthz_is_ok() {
        let req = Request::get("/healthz").body(Body::empty()).unwrap();
        let resp = call(state(Mode::Enforce, StubProvider::default()), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn managed_request_within_budget_settles_cost() {
        let st = state(Mode::Enforce, StubProvider::default());
        let ledger = Arc::clone(&st.ledger);
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-1")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body(500)))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-fuse").unwrap(), "managed");
        assert!(resp.headers().contains_key("x-fuse-cost-usd"));

        let snap = ledger.snapshot("run-1").await.unwrap();
        assert!(snap.spent > Microusd::ZERO);
        assert_eq!(snap.steps, 1);
    }

    #[tokio::test]
    async fn snapshot_none_for_just_opened_run_does_not_panic() {
        // Regression test for the live cluster bug: `st.ledger.snapshot(&run_id)`
        // used to be unwrapped with `.expect("run just opened")`, an assumption
        // that holds for the in-process ledger (open_run applies synchronously,
        // so a same-task snapshot can never miss it) but is false for the raft
        // ledger under burst load on a follower node, where `snapshot()` is a
        // local eventually-consistent read that can race the just-committed
        // `open_run` write. `SnapshotLaggingLedger` reproduces exactly that:
        // `snapshot` always returns `None`, deterministically, regardless of
        // whether the run was actually just opened.
        let mut st = state(Mode::Enforce, StubProvider::default());
        st.ledger = Arc::new(SnapshotLaggingLedger(LocalLedger(Arc::new(Ledger::new()))));
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-lagging")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body(500)))
            .unwrap();

        // Before the fix, this call panicked the request's tokio task instead
        // of returning a response at all.
        let resp = call(st, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a missing snapshot for a just-opened run must fall back to a fresh \
             snapshot, not panic or otherwise fail the request"
        );
        assert_eq!(resp.headers().get("x-fuse").unwrap(), "managed");
    }

    #[tokio::test]
    async fn enforce_over_budget_returns_402_contract() {
        let st = state(
            Mode::Enforce,
            StubProvider {
                input_tokens: 1_000,
                output_tokens: 100_000,
                sse: false,
                body_override: None,
            },
        );
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-2")
            .header("x-fuse-budget-usd", "0.000001")
            .body(Body::from(body(100_000)))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "budget_exceeded");
        assert_eq!(json["error"]["run_id"], "run-2");
        assert_eq!(json["error"]["retryable"], false);
    }

    #[tokio::test]
    async fn budget_block_records_avoided_estimate_in_sink() {
        // A blocked call must still show up in the trace, carrying the
        // estimate it would have cost as an avoided-spend figure — not zero,
        // and not silently invisible to the sink.
        let sink = RecordingSink::default();
        let st = state(
            Mode::Enforce,
            StubProvider {
                input_tokens: 1_000,
                output_tokens: 100_000,
                sse: false,
                body_override: None,
            },
        )
        .with_sink(Arc::new(sink.clone()));
        let prices = Arc::clone(&st.prices);
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-block")
            .header("x-fuse-budget-usd", "0.000001")
            .body(Body::from(body(100_000)))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

        let expected = estimate_cost(&prices, "test-model", body(100_000).len(), Some(100_000))
            .unwrap_or(Microusd::ZERO);
        assert!(
            expected > Microusd::ZERO,
            "sanity: estimate must be nonzero"
        );

        let records = sink.snapshot();
        assert_eq!(records.len(), 1, "exactly one record for the blocked call");
        assert_eq!(records[0].decision, "budget_exceeded");
        assert_eq!(records[0].run_id, "run-block");
        assert_eq!(records[0].cost_microusd, expected.0);
    }

    #[tokio::test]
    async fn shadow_over_budget_allows_but_flags_would_block() {
        let mut st = state(Mode::Shadow, StubProvider::default());
        st.policy = Arc::new(Policy {
            mode: Mode::Shadow,
            max_steps: Some(0),
            ..Default::default()
        });
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-3")
            .body(Body::from(body(100)))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("x-fuse-would-block"));
    }

    // ---- client credentials (key identity) --------------------------------

    fn with_keys(st: AppState, spec: &str) -> AppState {
        st.with_client_keys(Arc::new(
            crate::clientkeys::ClientKeys::from_spec(spec).expect("valid spec"),
        ))
    }

    const KEYS: &str = "sk-live-abc:billing-agent";

    #[tokio::test]
    async fn without_client_keys_nothing_changes_and_key_id_is_empty() {
        // The upgrade path for every existing deployment: no credential is
        // required, and the new trace column is simply empty.
        let sink = RecordingSink::default();
        let st = state(Mode::Enforce, StubProvider::default()).with_sink(Arc::new(sink.clone()));
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "no-keys")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::OK);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].key_id, "",
            "no credential configured means no identity to record"
        );
    }

    #[tokio::test]
    async fn a_missing_or_unknown_credential_is_refused_identically() {
        // Identical responses on purpose: telling the caller WHICH of the two
        // they got wrong tells an attacker whether a secret exists.
        let mut bodies = Vec::new();
        for header in [None, Some("sk-live-wrong")] {
            let st = with_keys(state(Mode::Enforce, StubProvider::default()), KEYS);
            let mut req = Request::post("/v1/messages")
                .header("x-fuse-run-id", "auth")
                .header("x-fuse-budget-usd", "5.0");
            if let Some(h) = header {
                req = req.header(crate::clientkeys::CLIENT_KEY_HEADER, h);
            }
            let resp = call(st, req.body(Body::from(body(100))).unwrap()).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "header = {header:?}"
            );
            let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            bodies.push(String::from_utf8(bytes.to_vec()).unwrap());
        }
        assert_eq!(
            bodies[0], bodies[1],
            "the two refusals must be indistinguishable"
        );
        assert!(
            !bodies[1].contains("sk-live-wrong"),
            "the presented secret must never be echoed into an error body: {}",
            bodies[1]
        );
    }

    /// Key lifecycle health (docs/22): `unauthorized()` gains exactly ONE
    /// side effect (the keystats aggregate counter), and the 401 wire
    /// contract must stay byte-for-byte identical to before that existed.
    /// Copies `a_missing_or_unknown_credential_is_refused_identically`'s
    /// response-shape assertions verbatim, then checks the new counter.
    #[tokio::test]
    async fn unauthorized_increments_keystats_without_changing_the_response() {
        let st = with_keys(state(Mode::Enforce, StubProvider::default()), KEYS);
        let keystats = st.keystats.clone();
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "auth-stats")
            .header("x-fuse-budget-usd", "5.0")
            .header(crate::clientkeys::CLIENT_KEY_HEADER, "sk-live-wrong")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers().get("x-fuse").unwrap(), "unauthorized");
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "error": {
                    "type": "unauthorized",
                    "reason": format!(
                        "this gateway requires a client credential in the `{}` header",
                        crate::clientkeys::CLIENT_KEY_HEADER
                    ),
                    "retryable": false,
                }
            }),
            "the 401 body must stay byte-for-byte identical now that it has a side effect"
        );

        let snap = keystats.snapshot();
        assert_eq!(snap.unauthorized.attempts, 1);
        assert!(snap.unauthorized.last_millis.is_some());
        assert!(
            snap.per_key.is_empty(),
            "a refused credential must never create a per-key entry"
        );
    }

    #[tokio::test]
    async fn an_unmanaged_call_cannot_walk_around_the_credential() {
        // No run id would take the drop-in pass-through, which still reaches
        // the provider and still spends the operator's provider credential. An
        // operator who turned client keys on to control who may use this
        // gateway would not expect "omit a header" to be the way around it.
        let st = with_keys(state(Mode::Enforce, StubProvider::default()), KEYS);
        let req = Request::post("/v1/messages")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_valid_credential_is_accepted_and_its_key_id_reaches_the_trace() {
        let sink = RecordingSink::default();
        let st = with_keys(
            state(Mode::Enforce, StubProvider::default()).with_sink(Arc::new(sink.clone())),
            KEYS,
        );
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "authed")
            .header("x-fuse-budget-usd", "5.0")
            .header(crate::clientkeys::CLIENT_KEY_HEADER, "sk-live-abc")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::OK);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].key_id, "billing-agent",
            "the trace records the resolved key_id, not the secret"
        );
    }

    #[tokio::test]
    async fn the_key_id_on_the_trace_cannot_be_set_by_a_header() {
        // The whole point of the field: a caller who sends their own `key_id`
        // (or an `agent_id` claiming to be someone else) does not move the
        // identity a budget above the run would be keyed on.
        let sink = RecordingSink::default();
        let st = with_keys(
            state(Mode::Enforce, StubProvider::default()).with_sink(Arc::new(sink.clone())),
            KEYS,
        );
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "spoof")
            .header("x-fuse-budget-usd", "5.0")
            .header(crate::clientkeys::CLIENT_KEY_HEADER, "sk-live-abc")
            .header("x-fuse-agent-id", "someone-elses-agent")
            .header("key_id", "someone-elses-key")
            .header("x-fuse-key-id", "someone-elses-key")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::OK);
        let recs = sink.snapshot();
        assert_eq!(
            recs[0].key_id, "billing-agent",
            "only the credential decides key_id"
        );
        assert_eq!(
            recs[0].agent_id, "someone-elses-agent",
            "agent_id stays client-supplied attribution, unchanged and still not a budget key"
        );
    }

    #[tokio::test]
    async fn successful_call_increments_keystats_calls_and_last_seen() {
        let st = with_keys(state(Mode::Enforce, StubProvider::default()), KEYS);
        let keystats = st.keystats.clone();
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "authed-stats")
            .header("x-fuse-budget-usd", "5.0")
            .header(crate::clientkeys::CLIENT_KEY_HEADER, "sk-live-abc")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::OK);

        let snap = keystats.snapshot();
        let k = snap
            .per_key
            .get("billing-agent")
            .expect("the resolved key_id must be tracked");
        assert_eq!(k.calls, 1);
        assert!(k.last_seen_millis.is_some());
        assert_eq!(k.identity_mismatches, 0);
    }

    #[tokio::test]
    async fn keystats_calls_increments_even_when_the_call_is_402_blocked() {
        // "all downstream outcomes included" (docs/22): a resolved
        // credential still counts even when the request itself gets
        // Breaker-blocked further down the pipeline.
        let st = with_keys(
            state(
                Mode::Enforce,
                StubProvider {
                    input_tokens: 1_000,
                    output_tokens: 100_000,
                    sse: false,
                    body_override: None,
                },
            ),
            KEYS,
        );
        let keystats = st.keystats.clone();
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "authed-402-stats")
            .header("x-fuse-budget-usd", "0.000001")
            .header(crate::clientkeys::CLIENT_KEY_HEADER, "sk-live-abc")
            .body(Body::from(body(100_000)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::PAYMENT_REQUIRED);

        let snap = keystats.snapshot();
        assert_eq!(
            snap.per_key.get("billing-agent").unwrap().calls,
            1,
            "a 402-blocked call still resolved a real credential, so it still counts"
        );
    }

    #[tokio::test]
    async fn unmanaged_passthrough_without_run_id() {
        let req = Request::post("/v1/messages")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(state(Mode::Enforce, StubProvider::default()), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-fuse").unwrap(), "unmanaged");
    }

    #[tokio::test]
    async fn dlp_block_stops_request_with_a_secret() {
        let mut st = state(Mode::Shadow, StubProvider::default());
        st.dlp = DlpMode::Block;
        let payload = r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"my key is AKIA1234567890ABCDEF"}]}"#;
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "dlp")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(payload))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "dlp_blocked");
    }

    #[tokio::test]
    async fn dlp_block_records_zero_cost_in_sink() {
        // Security blocks are avoided-harm, not avoided-spend: the call never
        // reached the provider, so cost is 0 — unlike budget-family blocks.
        let sink = RecordingSink::default();
        let mut st = state(Mode::Shadow, StubProvider::default()).with_sink(Arc::new(sink.clone()));
        st.dlp = DlpMode::Block;
        let payload = r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"my key is AKIA1234567890ABCDEF"}]}"#;
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "dlp-sink")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(payload))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let records = sink.snapshot();
        assert_eq!(records.len(), 1, "exactly one record for the blocked call");
        assert_eq!(records[0].decision, "dlp_blocked");
        assert_eq!(records[0].run_id, "dlp-sink");
        assert_eq!(records[0].cost_microusd, 0);
    }

    // -- x-fuse-outcome header parsing (P4, unit economics) -----------------

    #[test]
    fn outcome_header_absent_is_none() {
        let headers = HeaderMap::new();
        assert_eq!(outcome_header(&headers), None);
    }

    #[test]
    fn outcome_header_empty_is_none() {
        let mut headers = HeaderMap::new();
        headers.insert("x-fuse-outcome", "".parse().unwrap());
        assert_eq!(outcome_header(&headers), None);
    }

    #[test]
    fn outcome_header_valid_tag_is_captured_verbatim() {
        let mut headers = HeaderMap::new();
        headers.insert("x-fuse-outcome", "case_resolved".parse().unwrap());
        assert_eq!(outcome_header(&headers), Some("case_resolved".to_string()));
    }

    #[test]
    fn outcome_header_at_exactly_the_cap_is_captured() {
        let tag = "a".repeat(OUTCOME_MAX_BYTES);
        let mut headers = HeaderMap::new();
        headers.insert("x-fuse-outcome", tag.parse().unwrap());
        assert_eq!(outcome_header(&headers), Some(tag));
    }

    #[test]
    fn outcome_header_over_cap_is_ignored_not_rejected() {
        // Serialize against every other test that increments OUTCOME_OVERCAP
        // (a process-global static) so this before/increment/assert window
        // can't observe another test's concurrent increment (test isolation
        // only, see OVERCAP_TEST_LOCK doc comment above).
        let _overcap_guard = OVERCAP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let before = OUTCOME_OVERCAP.load(Ordering::Relaxed);
        let tag = "a".repeat(OUTCOME_MAX_BYTES + 1);
        let mut headers = HeaderMap::new();
        headers.insert("x-fuse-outcome", tag.parse().unwrap());
        // Fail-open: an over-cap header reads as absent, never an error.
        assert_eq!(outcome_header(&headers), None);
        // ...but the occurrence is counted (same "metric" shape as
        // `ON_BEHALF_OF_OVERCAP`).
        assert_eq!(OUTCOME_OVERCAP.load(Ordering::Relaxed), before + 1);
    }

    #[tokio::test]
    async fn outcome_header_is_recorded_verbatim_in_the_sink() {
        let sink = RecordingSink::default();
        let st = state(Mode::Enforce, StubProvider::default()).with_sink(Arc::new(sink.clone()));
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-outcome")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-outcome", "case_resolved")
            .body(Body::from(body(100)))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let records = sink.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, "case_resolved");
    }

    #[tokio::test]
    // `#[tokio::test]` gives each test its own single-threaded runtime and
    // drives it with `block_on` (not `spawn`), so this guard is never handed
    // to another thread or contended by another task while held: safe to
    // hold across the `.await` below despite the lint.
    #[allow(clippy::await_holding_lock)]
    async fn outcome_header_over_cap_is_dropped_not_recorded() {
        // Same OUTCOME_OVERCAP race as
        // `outcome_header_over_cap_is_ignored_not_rejected`: this test also
        // drives the over-cap increment path (via the full request handler),
        // so it must hold the same lock for its whole body to keep that
        // test's before/after snapshot race-free.
        let _overcap_guard = OVERCAP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let sink = RecordingSink::default();
        let st = state(Mode::Enforce, StubProvider::default()).with_sink(Arc::new(sink.clone()));
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-outcome-overcap")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-outcome", "a".repeat(OUTCOME_MAX_BYTES + 1))
            .body(Body::from(body(100)))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "over-cap header never fails the request"
        );

        let records = sink.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].outcome, "",
            "over-cap tag is ignored, not truncated"
        );
    }

    #[tokio::test]
    async fn outcome_header_absent_records_empty_string() {
        let sink = RecordingSink::default();
        let st = state(Mode::Enforce, StubProvider::default()).with_sink(Arc::new(sink.clone()));
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-no-outcome")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body(100)))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let records = sink.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, "");
    }

    #[tokio::test]
    async fn dlp_shadow_flags_but_forwards() {
        let mut st = state(Mode::Shadow, StubProvider::default());
        st.dlp = DlpMode::Shadow;
        let payload = r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"key AKIA1234567890ABCDEF"}]}"#;
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "dlp2")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(payload))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("x-fuse-dlp"));
    }

    #[tokio::test]
    async fn firewall_blocks_exec_after_web_taint() {
        use crate::firewall::FirewallConfig;
        let mut st = state(
            Mode::Shadow,
            StubProvider {
                body_override: Some(
                    r#"{"content":[{"type":"tool_use","name":"run_shell","input":{}}]}"#.into(),
                ),
                ..StubProvider::default()
            },
        );
        st.firewall = Arc::new(FirewallConfig::defaults(FirewallMode::Enforce));

        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "fw")
            .header("x-fuse-taint", "web") // context touched the web
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st, req).await;
        // Model wants run_shell (exec) but the context is web-tainted → 403.
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "taint_blocked");
    }

    #[tokio::test]
    async fn firewall_allows_exec_without_taint() {
        use crate::firewall::FirewallConfig;
        let mut st = state(
            Mode::Shadow,
            StubProvider {
                body_override: Some(
                    r#"{"content":[{"type":"tool_use","name":"run_shell","input":{}}]}"#.into(),
                ),
                ..StubProvider::default()
            },
        );
        st.firewall = Arc::new(FirewallConfig::defaults(FirewallMode::Enforce));
        // No taint header, no untrusted tools in history → exec is allowed.
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "fw2")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn subagent_blocked_by_parent_budget() {
        // Parent has a tiny budget; a sub-agent call rolls up and is blocked.
        let st = state(Mode::Enforce, StubProvider::default());
        // Parent budget is tiny — smaller than a single child call's estimate.
        st.ledger
            .open_run("parent", Microusd::from_usd(0.001), None)
            .await;

        let child = Request::post("/v1/messages")
            .header("x-fuse-run-id", "child")
            .header("x-fuse-parent-run-id", "parent")
            .header("x-fuse-budget-usd", "100.0") // child's own budget is huge
            .body(Body::from(body(500)))
            .unwrap();
        let resp = call(st, child).await;
        // Child fits its own budget but the parent's $0.001 can't take the
        // ~$0.0087 estimate → 402.
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "budget_exceeded");
        assert!(json["error"]["reason"].as_str().unwrap().contains("parent"));
    }

    #[tokio::test]
    async fn cache_on_serves_second_identical_request() {
        use tokenfuse_core::cache::{CacheConfig, CacheMode, HashEmbedder};
        let mut st = state(Mode::Shadow, StubProvider::default());
        st.cache = Arc::new(SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                ..Default::default()
            },
        ));
        let payload = r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"how do refunds work?"}]}"#;
        let mk = || {
            Request::post("/v1/messages")
                .header("x-fuse-run-id", "run-c")
                .header("x-fuse-budget-usd", "5.0")
                .body(Body::from(payload))
                .unwrap()
        };

        // First call: forwarded and stored.
        let r1 = call(st.clone(), mk()).await;
        assert_eq!(r1.headers().get("x-fuse").unwrap(), "managed");

        // Second identical call: served from cache, $0.
        let r2 = call(st.clone(), mk()).await;
        assert_eq!(r2.headers().get("x-fuse").unwrap(), "cached");
        assert_eq!(r2.headers().get("x-fuse-cache").unwrap(), "hit");
        assert_eq!(r2.headers().get("x-fuse-cost-usd").unwrap(), "0.000000");
    }

    #[tokio::test]
    async fn killed_run_is_hard_blocked_and_listed() {
        let st = state(Mode::Shadow, StubProvider::default());

        // First call establishes the run.
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-k")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st.clone(), req).await.status(), StatusCode::OK);

        // Kill it via the endpoint.
        let kill = Request::post("/v1/runs/run-k/kill")
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(st.clone(), kill).await.status(), StatusCode::OK);

        // Next call is hard-blocked even though the policy is shadow.
        let again = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-k")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st.clone(), again).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "killed");

        // The run shows up in the listing, flagged killed.
        let list = Request::get("/v1/runs").body(Body::empty()).unwrap();
        let resp = call(st, list).await;
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let runs: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(runs[0]["run_id"], "run-k");
        assert_eq!(runs[0]["killed"], true);
    }

    #[tokio::test]
    async fn enforce_blocks_on_detected_loop() {
        use tokenfuse_core::{AnomalyConfig, Window};
        let mut st = state(Mode::Enforce, StubProvider::default());
        st.policy = Arc::new(Policy {
            mode: Mode::Enforce,
            anomalies: AnomalyConfig {
                identical_tool_call: Some(Window {
                    window: 10,
                    threshold: 3,
                }),
                ..Default::default()
            },
            ..Default::default()
        });
        // A request whose own history shows the same tool called three times.
        let call_block = r#"{"role":"assistant","content":[{"type":"tool_use","name":"grep","input":{"q":"x"}}]}"#;
        let body = format!(
            r#"{{"model":"test-model","max_tokens":100,"messages":[{call_block},{call_block},{call_block}]}}"#
        );
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-loop")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "loop_detected");
    }

    #[tokio::test]
    async fn client_cancel_midstream_still_settles() {
        use futures::StreamExt;
        // A managed streaming reservation whose body is only partially consumed
        // (client disconnects) must still be settled — reservation released.
        let st = state(
            Mode::Enforce,
            StubProvider {
                input_tokens: 1_000,
                output_tokens: 500,
                sse: true,
                body_override: None,
            },
        );
        st.ledger
            .open_run("run-cancel", Microusd::from_usd(5.0), None)
            .await;
        let reservation = st
            .ledger
            .reserve("run-cancel", Microusd::from_usd(0.5))
            .await
            .unwrap();
        let resp = st
            .provider
            .send(HeaderMap::new(), Bytes::new())
            .await
            .unwrap();

        let response = stream_managed(
            resp,
            reservation,
            None,
            None,
            "test-model",
            &st,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            None,
            None,
            None,
            None,
        );
        {
            // Consume a single chunk, then drop the stream (simulated cancel).
            let mut data = response.into_body().into_data_stream();
            let _first = data.next().await;
        }

        let snap = st.ledger.snapshot("run-cancel").await.unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO); // released, not leaked
        assert!(snap.spent > Microusd::ZERO); // conservative fallback charge
    }

    #[tokio::test]
    async fn streaming_request_passes_through_and_settles_at_end() {
        let st = state(
            Mode::Enforce,
            StubProvider {
                input_tokens: 1_000,
                output_tokens: 500,
                sse: true,
                body_override: None,
            },
        );
        let ledger = Arc::clone(&st.ledger);
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "run-stream")
            .header("x-fuse-budget-usd", "5.0")
            .body(Body::from(body_stream(500)))
            .unwrap();

        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-fuse-stream").unwrap(), "passthrough");

        // Draining the body is what triggers settle at end-of-stream.
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("message_start"));
        assert!(text.contains("[DONE]"));

        let snap = ledger.snapshot("run-stream").await.unwrap();
        assert!(snap.spent > Microusd::ZERO);
        assert_eq!(snap.reserved, Microusd::ZERO); // reservation released on settle
    }

    /// The pre-refactor `budget_error` builder, kept verbatim as the golden
    /// wire format. The new `breaker_error_response` path MUST reproduce this
    /// byte-for-byte (body, status, headers) — that is the whole point of the
    /// facade refactor. Do NOT "fix" this to match new code: this is the
    /// contract clients already depend on and it must not change.
    fn golden_budget_error(
        kind: &str,
        run_id: &str,
        budget: Microusd,
        spent: Microusd,
        policy_id: &str,
        reason: &str,
    ) -> Response {
        let body = serde_json::json!({
            "error": {
                "type": kind,
                "run_id": run_id,
                "budget_usd": budget.as_usd(),
                "spent_usd": spent.as_usd(),
                "policy_id": policy_id,
                "reason": reason,
                "retryable": false,
            }
        });
        Response::builder()
            .status(StatusCode::PAYMENT_REQUIRED)
            .header("content-type", "application/json")
            .header("x-fuse", "blocked")
            .header("x-fuse-run-id", run_id)
            .body(Body::from(body.to_string()))
            .expect("valid response")
    }

    /// For each of the five 402 budget-family reasons, assert the new
    /// facade-backed `breaker_error_response` is byte-identical to the old
    /// `budget_error` builder: same status, same body bytes, same headers.
    #[tokio::test]
    async fn breaker_error_response_matches_budget_error_byte_for_byte() {
        let cases = [
            (
                BreakerReason::Killed,
                "killed",
                "run killed by operator",
                Microusd(5_000_000),
                Microusd(0),
            ),
            (
                BreakerReason::PolicyViolation,
                "policy_violation",
                "max_steps exceeded",
                Microusd(5_000_000),
                Microusd(2_500_000),
            ),
            (
                BreakerReason::LoopDetected,
                "loop_detected",
                "repeated tool-call signature",
                Microusd(5_000_000),
                Microusd(1_250_000),
            ),
            (
                BreakerReason::WasmPolicy,
                "wasm_policy",
                "blocked by custom wasm policy",
                Microusd(2_000_000),
                Microusd(100_000),
            ),
            (
                BreakerReason::BudgetExceeded,
                "budget_exceeded",
                "per-run budget exceeded",
                Microusd(5_000_000),
                Microusd(5_250_000),
            ),
        ];

        for (reason, kind, detail, budget, spent) in cases {
            let run_id = "run-golden";
            let policy_id = "default";

            let old = golden_budget_error(kind, run_id, budget, spent, policy_id, detail);
            let verdict = budget_verdict(reason, budget, spent, policy_id, detail);
            let new = breaker_error_response(run_id, &verdict);

            // Status.
            assert_eq!(new.status(), old.status(), "status mismatch for {kind}");
            assert_eq!(new.status(), StatusCode::PAYMENT_REQUIRED);

            // Headers (content-type, x-fuse, x-fuse-run-id).
            for h in ["content-type", "x-fuse", "x-fuse-run-id"] {
                assert_eq!(
                    new.headers().get(h),
                    old.headers().get(h),
                    "header {h} mismatch for {kind}"
                );
            }

            // Body bytes.
            let old_bytes = to_bytes(old.into_body(), usize::MAX).await.unwrap();
            let new_bytes = to_bytes(new.into_body(), usize::MAX).await.unwrap();
            assert_eq!(new_bytes, old_bytes, "body bytes mismatch for {kind}");
        }
    }

    // --- referenced_domains (Wardryx `domains` extraction) ---

    #[test]
    fn referenced_domains_empty_when_no_tools_field() {
        let request = serde_json::json!({ "model": "m", "messages": [] });
        assert!(referenced_domains(&request).is_empty());
    }

    #[test]
    fn referenced_domains_empty_when_tools_array_is_empty() {
        let request = serde_json::json!({ "tools": [] });
        assert!(referenced_domains(&request).is_empty());
    }

    #[test]
    fn referenced_domains_extracts_host_from_an_explicit_url_string() {
        let request = serde_json::json!({
            "tools": [{
                "name": "fetch_invoice",
                "url": "https://api.acme.example/v1/invoices"
            }]
        });
        assert_eq!(referenced_domains(&request), vec!["api.acme.example"]);
    }

    #[test]
    fn referenced_domains_walks_nested_input_schema() {
        // A URL a few levels deep under a JSON-schema-shaped tool
        // definition (array -> tool object -> input_schema -> properties ->
        // property object -> "default") must still be found: real tool
        // schemas nest a URL at exactly this kind of depth.
        let request = serde_json::json!({
            "tools": [{
                "name": "call_webhook",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "endpoint": {
                            "type": "string",
                            "default": "https://hooks.acme.example/deploy"
                        }
                    }
                }
            }]
        });
        assert_eq!(referenced_domains(&request), vec!["hooks.acme.example"]);
    }

    #[test]
    fn referenced_domains_lowercases_dedupes_and_sorts() {
        let request = serde_json::json!({
            "tools": [
                { "url": "HTTPS://API.acme.example/a" },
                { "url": "https://api.acme.example/b" },
                { "url": "http://other.example/c" }
            ]
        });
        assert_eq!(
            referenced_domains(&request),
            vec!["api.acme.example", "other.example"]
        );
    }

    #[test]
    fn referenced_domains_ignores_prose_that_merely_mentions_a_url() {
        // The task this serves is "what did the request explicitly
        // declare as a URL," not "find every URL-shaped substring in any
        // text anywhere" -- a description that mentions a URL in a
        // sentence must not be treated as a declared domain.
        let request = serde_json::json!({
            "tools": [{
                "name": "help",
                "description": "For details see https://sneaky.example.com/docs before calling."
            }]
        });
        assert!(referenced_domains(&request).is_empty());
    }

    #[test]
    fn referenced_domains_ignores_non_http_schemes() {
        let request = serde_json::json!({
            "tools": [{ "url": "ftp://files.acme.example/drop" }]
        });
        assert!(referenced_domains(&request).is_empty());
    }

    #[test]
    fn referenced_domains_ignores_tools_outside_the_tools_field() {
        // A URL living in "system" or "messages" is out of scope: only
        // strings nested under "tools" are ever scanned.
        let request = serde_json::json!({
            "system": "reach https://unrelated.example.com if needed",
            "tools": [{ "name": "noop" }]
        });
        assert!(referenced_domains(&request).is_empty());
    }

    // --- system_text (semantic cache partition key) ---

    #[test]
    fn system_text_extracts_a_plain_string() {
        let request = serde_json::json!({ "system": "You are a helpful assistant." });
        assert_eq!(system_text(&request), "You are a helpful assistant.");
    }

    #[test]
    fn system_text_extracts_an_array_shaped_system_prompt() {
        // Anthropic's API also accepts `system` as an array of content
        // blocks (the shape used with `cache_control` for prompt caching).
        // This must not collapse to "" the way it used to -- see
        // `system_text_different_array_systems_land_in_different_partitions`
        // for why that was a cross-tenant isolation bug.
        let request = serde_json::json!({
            "system": [{"type": "text", "text": "prompt A"}]
        });
        assert_eq!(system_text(&request), "prompt A");
    }

    #[test]
    fn system_text_concatenates_multiple_text_blocks() {
        let request = serde_json::json!({
            "system": [
                {"type": "text", "text": "block one"},
                {"type": "text", "text": "block two"}
            ]
        });
        assert_eq!(system_text(&request), "block one block two");
    }

    #[test]
    fn system_text_array_and_string_shapes_of_the_same_prompt_agree() {
        // The same prompt text, encoded either way, must land in the same
        // partition -- a client switching to the array shape (e.g. to add
        // `cache_control`) must not silently fragment its cache.
        let string_shaped = serde_json::json!({ "system": "X" });
        let array_shaped = serde_json::json!({ "system": [{"type": "text", "text": "X"}] });
        assert_eq!(system_text(&string_shaped), system_text(&array_shaped));
    }

    #[test]
    fn system_text_is_empty_when_system_field_is_absent() {
        let request = serde_json::json!({ "model": "m" });
        assert_eq!(system_text(&request), "");
    }

    #[test]
    fn system_text_different_array_systems_land_in_different_partitions() {
        // The core regression: two requests with DIFFERENT array-shaped
        // `system` fields must never collapse to the same partition key --
        // that would let one tenant/agent be served another's cached
        // response generated under a different system prompt, violating
        // the cache's hard-partition guarantee (crates/core/src/cache.rs
        // doc: "Similarity is only compared within an identical (model,
        // system prompt, tools, task_type, tenant) partition").
        let request_a = serde_json::json!({
            "system": [{"type": "text", "text": "prompt A"}]
        });
        let request_b = serde_json::json!({
            "system": [{"type": "text", "text": "prompt B"}]
        });
        let text_a = system_text(&request_a);
        let text_b = system_text(&request_b);
        assert_ne!(
            text_a, text_b,
            "different array-shaped system prompts must produce different system_text"
        );

        let partition_a = SemanticCache::partition_key("m", &text_a, "", "qa", "default");
        let partition_b = SemanticCache::partition_key("m", &text_b, "", "qa", "default");
        assert_ne!(
            partition_a, partition_b,
            "different array-shaped system prompts must land in different cache partitions"
        );
    }

    // --- set_header_checked ---

    #[test]
    fn set_header_checked_adds_a_legal_header_value() {
        let builder = Response::builder().status(StatusCode::OK);
        let builder = set_header_checked(
            builder,
            "x-fuse-router",
            "claude-opus-4-5->claude-haiku-4-5",
        );
        let resp = builder.body(Body::empty()).expect("valid response");
        assert_eq!(
            resp.headers().get("x-fuse-router").unwrap(),
            "claude-opus-4-5->claude-haiku-4-5"
        );
    }

    #[test]
    fn set_header_checked_drops_a_value_with_an_illegal_byte_instead_of_panicking() {
        // A newline is illegal in an HTTP header value, so `HeaderValue::from_str`
        // rejects it. The helper must fail open (skip the header) rather than let
        // a malformed value reach `.expect("valid response")` downstream, where it
        // would panic the request's task.
        let builder = Response::builder().status(StatusCode::OK);
        let builder = set_header_checked(
            builder,
            "x-fuse-router",
            "claude-opus-4-5\nX-Injected: evil",
        );
        let resp = builder.body(Body::empty()).expect("valid response");
        assert!(resp.headers().get("x-fuse-router").is_none());
    }

    #[test]
    fn set_header_checked_drops_a_value_containing_a_carriage_return() {
        // CR alone (not just CRLF) is also illegal in a header value.
        let builder = Response::builder().status(StatusCode::OK);
        let builder = set_header_checked(builder, "x-fuse-router", "foo\rbar");
        let resp = builder.body(Body::empty()).expect("valid response");
        assert!(resp.headers().get("x-fuse-router").is_none());
    }

    // -- identity map: mismatch gate + unit budgets (docs/20) ----------------

    /// The docs/20 example map, scaled down for tests: `treasury` capped at
    /// $1/month and bound to one key; `lending` uncapped, prefix-only.
    const TEST_IDENTITY_MAP: &str = r#"{
        "units": [
            { "id": "treasury", "budget_usd_month": 1.0 },
            { "id": "lending" }
        ],
        "keys": [
            { "key_id": "treasury-bots", "unit": "treasury",
              "agents": ["agent://bank.example/treasury/*"] }
        ],
        "prefixes": [
            { "match": "agent://bank.example/lending/*", "unit": "lending" }
        ]
    }"#;

    fn identity_state(mode: Mode, strict: crate::identitymap::StrictMode) -> AppState {
        static NEXT_MAP: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "tokenfuse-idmap-test-{}-{}.json",
            std::process::id(),
            NEXT_MAP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, TEST_IDENTITY_MAP).unwrap();
        let map = crate::identitymap::IdentityMap::from_path(&path).unwrap();
        let units = Arc::new(crate::unitledger::UnitLedger::new(map.unit_budgets()));
        state(mode, StubProvider::default())
            .with_client_keys(Arc::new(
                crate::clientkeys::ClientKeys::from_spec("sk-t:treasury-bots").unwrap(),
            ))
            .with_identity(Arc::new(map), strict, units)
    }

    #[tokio::test]
    async fn identity_enforce_blocks_a_foreign_agent_id_with_403() {
        let sink = RecordingSink::default();
        let st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Enforce)
            .with_sink(Arc::new(sink.clone()));
        let req = Request::post("/v1/messages")
            .header("x-fuse-key", "sk-t")
            .header("x-fuse-run-id", "id-enforce")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-agent-id", "agent://bank.example/fraud/bot1")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get("x-fuse-identity").unwrap(),
            "blocked=agent_id_not_allowed"
        );
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "identity_mismatch");
        assert!(json["error"].get("budget_usd").is_none());
        let records = sink.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, "identity_mismatch");
        assert_eq!(records[0].cost_microusd, 0);
        // The mismatch still attributes the BINDING's unit on the trace.
        assert_eq!(records[0].unit, "treasury");
    }

    #[tokio::test]
    async fn identity_warn_allows_and_sets_the_would_block_header() {
        let sink = RecordingSink::default();
        let st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Warn)
            .with_sink(Arc::new(sink.clone()));
        let req = Request::post("/v1/messages")
            .header("x-fuse-key", "sk-t")
            .header("x-fuse-run-id", "id-warn")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-agent-id", "agent://bank.example/fraud/bot1")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-fuse-identity").unwrap(),
            "would-block=agent_id_not_allowed"
        );
        let records = sink.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, "allow");
        assert_eq!(records[0].unit, "treasury");
    }

    #[tokio::test]
    async fn identity_off_still_attributes_the_unit_via_prefix() {
        // No client key presented at all: the prefix fallback attributes the
        // unit, no mismatch is possible, nothing blocks.
        let sink = RecordingSink::default();
        let mut st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Off)
            .with_sink(Arc::new(sink.clone()));
        st.client_keys = Arc::new(crate::clientkeys::ClientKeys::default());
        let req = Request::post("/v1/messages")
            .header("x-fuse-run-id", "id-prefix")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-agent-id", "agent://bank.example/lending/scorer")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("x-fuse-identity").is_none());
        let records = sink.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, "allow");
        assert_eq!(records[0].unit, "lending");
    }

    // -- identity map: keystats wiring (docs/22-key-lifecycle.md) ------------

    #[tokio::test]
    async fn identity_mismatch_in_warn_mode_still_increments_keystats() {
        // "warn also counts" is a documented, deliberate choice (docs/22):
        // the mismatch genuinely happened even though the call is allowed
        // through.
        let st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Warn);
        let keystats = st.keystats.clone();
        let req = Request::post("/v1/messages")
            .header("x-fuse-key", "sk-t")
            .header("x-fuse-run-id", "id-warn-stats")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-agent-id", "agent://bank.example/fraud/bot1")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::OK);

        let snap = keystats.snapshot();
        let k = snap.per_key.get("treasury-bots").unwrap();
        assert_eq!(k.identity_mismatches, 1);
        assert_eq!(k.calls, 1, "the call itself is still counted once too");
    }

    #[tokio::test]
    async fn identity_mismatch_in_enforce_mode_increments_keystats() {
        let st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Enforce);
        let keystats = st.keystats.clone();
        let req = Request::post("/v1/messages")
            .header("x-fuse-key", "sk-t")
            .header("x-fuse-run-id", "id-enforce-stats")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-agent-id", "agent://bank.example/fraud/bot1")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::FORBIDDEN);

        let snap = keystats.snapshot();
        let k = snap.per_key.get("treasury-bots").unwrap();
        assert_eq!(k.identity_mismatches, 1);
        assert_eq!(k.calls, 1);
    }

    #[tokio::test]
    async fn identity_mismatch_in_off_mode_is_not_counted() {
        // Off mode never consults the mismatch operationally, so docs/22
        // scopes keystats counting to warn/enforce only - this locks that
        // scoping decision in.
        let st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Off);
        let keystats = st.keystats.clone();
        let req = Request::post("/v1/messages")
            .header("x-fuse-key", "sk-t")
            .header("x-fuse-run-id", "id-off-stats")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-agent-id", "agent://bank.example/fraud/bot1")
            .body(Body::from(body(100)))
            .unwrap();
        assert_eq!(call(st, req).await.status(), StatusCode::OK);

        let snap = keystats.snapshot();
        let k = snap.per_key.get("treasury-bots").unwrap();
        assert_eq!(k.calls, 1);
        assert_eq!(
            k.identity_mismatches, 0,
            "off mode does not count a mismatch, only warn/enforce do"
        );
    }

    #[tokio::test]
    async fn unit_budget_exceeded_blocks_at_402_with_the_units_numbers() {
        // Estimate for max_tokens=100000 at $15/Mtok output is ~$1.5, past
        // treasury's $1 monthly cap, while the run budget ($100) has room:
        // the trip must name the UNIT's cap, not the run's.
        let sink = RecordingSink::default();
        let st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Enforce)
            .with_sink(Arc::new(sink.clone()));
        let req = Request::post("/v1/messages")
            .header("x-fuse-key", "sk-t")
            .header("x-fuse-run-id", "unit-402")
            .header("x-fuse-budget-usd", "100.0")
            .header("x-fuse-agent-id", "agent://bank.example/treasury/recon")
            .body(Body::from(body(100_000)))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "unit_budget_exceeded");
        assert_eq!(json["error"]["budget_usd"], 1.0);
        let records = sink.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, "unit_budget_exceeded");
        assert_eq!(records[0].unit, "treasury");
        // Blocked spend stays visible: the avoided estimate rides the row.
        assert!(records[0].cost_microusd > 0);
    }

    #[tokio::test]
    async fn unit_spend_settles_into_the_unit_ledger() {
        let st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Enforce);
        let units = Arc::clone(&st.units);
        let req = Request::post("/v1/messages")
            .header("x-fuse-key", "sk-t")
            .header("x-fuse-run-id", "unit-settle")
            .header("x-fuse-budget-usd", "5.0")
            .header("x-fuse-agent-id", "agent://bank.example/treasury/recon")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let spent = units.spent("treasury", now_millis());
        assert!(
            spent > Microusd::ZERO,
            "the unit ledger must absorb the settled cost"
        );
    }

    #[tokio::test]
    async fn a_run_budget_refusal_releases_the_unit_reservation() {
        // The unit reserve is taken first; when the run-level reserve then
        // refuses, the unit reservation must be released, not leaked.
        let st = identity_state(Mode::Enforce, crate::identitymap::StrictMode::Enforce);
        let units = Arc::clone(&st.units);
        let req = Request::post("/v1/messages")
            .header("x-fuse-key", "sk-t")
            .header("x-fuse-run-id", "unit-release")
            // A run budget far below any estimate: the run gate refuses.
            .header("x-fuse-budget-usd", "0.000001")
            .header("x-fuse-agent-id", "agent://bank.example/treasury/recon")
            .body(Body::from(body(100)))
            .unwrap();
        let resp = call(st, req).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["type"], "budget_exceeded");
        assert_eq!(units.spent("treasury", now_millis()), Microusd::ZERO);
        // Nearly the whole cap must still be reservable: nothing leaked.
        assert!(units
            .try_reserve("treasury", Microusd::from_usd(0.99), now_millis())
            .is_ok());
    }
}
