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
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use futures::StreamExt;
use tokenfuse_core::{evaluate, BudgetError, Microusd, Mode, Reservation};

/// Default per-run budget when neither the request nor the policy sets one.
const DEFAULT_RUN_BUDGET: Microusd = Microusd(5_000_000); // $5.00

pub async fn healthz() -> &'static str {
    "ok"
}

/// Anthropic-style messages endpoint. Provider-agnostic: the body is forwarded
/// as-is once the budget check passes.
pub async fn messages(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
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

    let budget = header_f64(&headers, "x-fuse-budget-usd")
        .map(Microusd::from_usd)
        .or(st.policy.budget_per_run)
        .unwrap_or(DEFAULT_RUN_BUDGET);
    st.ledger.open_run(&run_id, budget);

    let estimate = estimate_cost(&st.prices, &parsed.model, body.len(), parsed.max_tokens)
        .unwrap_or(Microusd::ZERO);

    let snapshot = st.ledger.snapshot(&run_id).expect("run just opened");
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
            return budget_error(
                "policy_violation",
                &run_id,
                budget,
                snapshot.spent,
                &st.policy_id,
                &eval.violated.clone().unwrap_or_default(),
            );
        }
        if let Some(reason) = &loop_reason {
            return budget_error(
                "loop_detected",
                &run_id,
                budget,
                snapshot.spent,
                &st.policy_id,
                reason,
            );
        }
    }

    // For shadow/warn, surface whichever signal tripped in the response header.
    let would_block = eval.violated.clone().or(loop_reason);

    // Budget gate: enforce uses the atomic checked reserve; shadow/warn record
    // the reservation without blocking.
    let reservation = match st.policy.mode {
        Mode::Enforce => match st.ledger.reserve(&run_id, estimate) {
            Ok(r) => r,
            Err(BudgetError::Exceeded { budget, spent, .. }) => {
                return budget_error(
                    "budget_exceeded",
                    &run_id,
                    budget,
                    spent,
                    &st.policy_id,
                    "per-run budget exceeded",
                );
            }
            Err(BudgetError::UnknownRun { .. }) => st.ledger.reserve_unchecked(&run_id, estimate),
        },
        Mode::Shadow | Mode::Warn => st.ledger.reserve_unchecked(&run_id, estimate),
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
        stream_managed(resp, reservation, would_block, &parsed.model, &st)
    } else {
        buffered_managed(resp, reservation, would_block, &parsed.model, &st).await
    }
}

/// Streaming managed response: pass chunks through and settle at end-of-stream.
/// Cost headers are omitted because headers are sent before the body — the
/// settled figures go to the ledger (and, later, the event sink).
fn stream_managed(
    resp: ProviderResponse,
    reservation: Reservation,
    would_block: Option<String>,
    model: &str,
    st: &AppState,
) -> Response {
    let inner = resp.body;
    // Capture the header values before `reservation` is moved into the guard.
    let run_id = reservation.run_id.clone();
    let step = reservation.step;
    let guard = SettleGuard::new(
        st.ledger.clone(),
        st.prices.clone(),
        model.to_string(),
        resp.usage.clone(),
        reservation.amount,
        reservation,
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
    builder
        .body(Body::from_stream(wrapped))
        .expect("valid response")
}

/// Non-streaming managed response: buffer the body, settle with the exact cost,
/// and return full `x-fuse-*` accounting headers.
async fn buffered_managed(
    resp: ProviderResponse,
    reservation: Reservation,
    would_block: Option<String>,
    model: &str,
    st: &AppState,
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
        .and_then(|u| st.prices.cost(model, &u))
        .unwrap_or(reservation.amount);
    st.ledger.settle(&reservation, actual);
    let spent = st
        .ledger
        .snapshot(&reservation.run_id)
        .map(|s| s.spent)
        .unwrap_or(actual);

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
    builder.body(Body::from(bytes)).expect("valid response")
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

/// Build the stable 402 budget/policy error contract.
fn budget_error(
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
    use axum::body::to_bytes;
    use axum::http::Request;
    use std::sync::Arc;
    use tokenfuse_core::{Ledger, ModelPrice, Policy, PriceBook};
    use tower::ServiceExt;

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

        let snap = ledger.snapshot("run-1").unwrap();
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
            },
        );
        st.ledger.open_run("run-cancel", Microusd::from_usd(5.0));
        let reservation = st
            .ledger
            .reserve("run-cancel", Microusd::from_usd(0.5))
            .unwrap();
        let resp = st
            .provider
            .send(HeaderMap::new(), Bytes::new())
            .await
            .unwrap();

        let response = stream_managed(resp, reservation, None, "test-model", &st);
        {
            // Consume a single chunk, then drop the stream (simulated cancel).
            let mut data = response.into_body().into_data_stream();
            let _first = data.next().await;
        }

        let snap = st.ledger.snapshot("run-cancel").unwrap();
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

        let snap = ledger.snapshot("run-stream").unwrap();
        assert!(snap.spent > Microusd::ZERO);
        assert_eq!(snap.reserved, Microusd::ZERO); // reservation released on settle
    }
}
