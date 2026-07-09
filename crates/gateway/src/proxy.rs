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
use crate::provider::{ProviderError, ProviderResponse};
use crate::settle::SettleGuard;
use crate::sink::{now_millis, CallRecord};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use futures::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use tokenfuse_core::agent_event::EventType;
use tokenfuse_core::cache::{CacheMode, Lookup};
use tokenfuse_core::taint::{self, FirewallMode, Labels};
use tokenfuse_core::{
    dlp, evaluate, BreakerReason, BreakerVerdict, BudgetError, DlpMode, Microusd, Mode,
    Reservation, SemanticCache,
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
    let request: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let parsed = parse_request(&request);

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
        });
        let verdict = budget_verdict(
            BreakerReason::Killed,
            budget,
            spent,
            &st.policy_id,
            "run killed by operator",
        );
        emit_breaker_event(&st, &run_id, &agent_id, &on_behalf_of_chain, &verdict);
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
                        // The only non-zero `saved_microusd` site: a served cache
                        // hit avoided this much real spend.
                        saved_microusd: hit.saved_microusd,
                        parent_run_id: parent_run_id.clone(),
                        on_behalf_of: on_behalf_of.clone(),
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

    let snapshot = st.ledger.snapshot(&run_id).await.expect("run just opened");
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
            });
            let verdict = budget_verdict(
                BreakerReason::PolicyViolation,
                budget,
                snapshot.spent,
                &st.policy_id,
                &eval.violated.clone().unwrap_or_default(),
            );
            emit_breaker_event(&st, &run_id, &agent_id, &on_behalf_of_chain, &verdict);
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
            });
            let verdict = budget_verdict(
                BreakerReason::LoopDetected,
                budget,
                snapshot.spent,
                &st.policy_id,
                reason,
            );
            emit_breaker_event(&st, &run_id, &agent_id, &on_behalf_of_chain, &verdict);
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
            });
            let verdict = budget_verdict(
                BreakerReason::WasmPolicy,
                budget,
                snapshot.spent,
                &st.policy_id,
                "blocked by custom wasm policy",
            );
            emit_breaker_event(&st, &run_id, &agent_id, &on_behalf_of_chain, &verdict);
            return breaker_error_response(&run_id, &verdict);
        }
    }

    // For shadow/warn, surface whichever signal tripped in the response header.
    let would_block = eval.violated.clone().or(loop_reason);

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
                });
                let verdict = budget_verdict(
                    BreakerReason::BudgetExceeded,
                    budget,
                    spent,
                    &st.policy_id,
                    &reason,
                );
                emit_breaker_event(&st, &run_id, &agent_id, &on_behalf_of_chain, &verdict);
                return breaker_error_response(&run_id, &verdict);
            }
            Err(BudgetError::UnknownRun { .. }) => {
                st.ledger.reserve_unchecked(&run_id, estimate).await
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
            // Failed call cost us nothing — release the reservation.
            st.ledger.settle(&reservation, Microusd::ZERO);
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
        )
        .await
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
            return upstream_error(e);
        }
    };

    let usage = resp.usage.lock().unwrap().take();
    let actual = usage
        .as_ref()
        .and_then(|u| st.prices.cost(model, u))
        .unwrap_or(reservation.amount);
    st.ledger.settle(&reservation, actual);
    let spent = st
        .ledger
        .snapshot(&reservation.run_id)
        .await
        .map(|s| s.spent)
        .unwrap_or(actual);

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
        saved_microusd: 0,
        parent_run_id: parent_run_id.to_string(),
        on_behalf_of: on_behalf_of.to_string(),
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
    builder.body(Body::from(bytes)).expect("valid response")
}

/// DLP block: a secret was found in the outgoing prompt.
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
fn system_text(request: &serde_json::Value) -> String {
    request
        .get("system")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string()
}

/// A stable string for the tools schema, for the partition key.
fn tools_text(request: &serde_json::Value) -> String {
    request
        .get("tools")
        .map(|t| t.to_string())
        .unwrap_or_default()
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
                Some(serde_json::Value::Array(blocks)) => {
                    let mut buf = String::new();
                    for b in blocks {
                        if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                            buf.push_str(t);
                            buf.push(' ');
                        }
                    }
                    text = buf.trim().to_string();
                }
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
    use crate::provider::StubProvider;
    use crate::sink::EventSink;
    use axum::body::to_bytes;
    use axum::http::Request;
    use std::sync::{Arc, Mutex};
    use tokenfuse_core::{Ledger, ModelPrice, Policy, PriceBook};
    use tower::ServiceExt;

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
}
