//! The request path: parse → estimate → enforce → forward → settle.
//!
//! This is the heart of the gateway. The enforcement contract (ADR-4) is that we
//! decide *before* forwarding — a blocked call never reaches the provider — and
//! we settle the real cost *after*. A blocked call returns HTTP 402 with a
//! stable JSON error body so agent frameworks can catch it and stop cleanly.

use crate::estimate::estimate_cost;
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use tokenfuse_core::{evaluate, BudgetError, Microusd, Mode};

/// Default per-run budget when neither the request nor the policy sets one.
const DEFAULT_RUN_BUDGET: Microusd = Microusd(5_000_000); // $5.00

pub async fn healthz() -> &'static str {
    "ok"
}

/// Anthropic-style messages endpoint. Provider-agnostic: the body is forwarded
/// as-is once the budget check passes.
pub async fn messages(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let (model, max_tokens) = parse_request(&body);

    // No run id → unmanaged pass-through. Keeps the gateway drop-in safe: an
    // un-tagged caller is forwarded untouched rather than rejected.
    let Some(run_id) = header_str(&headers, "x-fuse-run-id") else {
        return forward(&st, &model, &body, None, "unmanaged", None).await;
    };

    let budget = header_f64(&headers, "x-fuse-budget-usd")
        .map(Microusd::from_usd)
        .or(st.policy.budget_per_run)
        .unwrap_or(DEFAULT_RUN_BUDGET);
    st.ledger.open_run(&run_id, budget);

    let estimate =
        estimate_cost(&st.prices, &model, body.len(), max_tokens).unwrap_or(Microusd::ZERO);

    let snapshot = st.ledger.snapshot(&run_id).expect("run just opened");
    let eval = evaluate(&st.policy, &snapshot, estimate);

    // Policy (step/max-steps) block, enforced only in enforce mode.
    if st.policy.mode == Mode::Enforce && eval.decision.is_blocking() {
        let reason = eval.violated.clone().unwrap_or_default();
        return budget_error(
            "policy_violation",
            &run_id,
            budget,
            snapshot.spent,
            &st.policy_id,
            &reason,
        );
    }

    // Budget gate. Enforce uses the atomic checked reserve; shadow/warn record
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

    forward(
        &st,
        &model,
        &body,
        Some(reservation),
        "managed",
        eval.violated,
    )
    .await
}

/// Forward to the provider and settle. `reservation` is `None` for unmanaged
/// pass-through (no accounting). `would_block` carries a shadow/warn reason.
async fn forward(
    st: &AppState,
    model: &str,
    body: &[u8],
    reservation: Option<tokenfuse_core::Reservation>,
    managed: &str,
    would_block: Option<String>,
) -> Response {
    let outcome = match st.provider.complete(model, body).await {
        Ok(o) => o,
        Err(e) => {
            if let Some(r) = &reservation {
                // Release the reservation; a failed call cost us nothing.
                st.ledger.settle(r, Microusd::ZERO);
            }
            return simple_error(StatusCode::BAD_GATEWAY, "upstream_error", &e.to_string());
        }
    };

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::OK))
        .header("content-type", "application/json")
        .header("x-fuse", managed);

    if let Some(r) = reservation {
        let actual = st.prices.cost(model, &outcome.usage).unwrap_or(r.amount);
        st.ledger.settle(&r, actual);
        let after = st.ledger.snapshot(&r.run_id);
        let spent = after.map(|s| s.spent).unwrap_or(actual);

        builder = builder
            .header("x-fuse-run-id", r.run_id)
            .header("x-fuse-step", r.step.to_string())
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
    }

    builder
        .body(Body::from(outcome.body.to_vec()))
        .expect("valid response")
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

fn simple_error(status: StatusCode, kind: &str, detail: &str) -> Response {
    let body = serde_json::json!({ "error": { "type": kind, "detail": detail } });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

fn parse_request(body: &[u8]) -> (String, Option<u64>) {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let model = value
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();
    let max_tokens = value.get("max_tokens").and_then(|m| m.as_u64());
    (model, max_tokens)
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
    use crate::state::AppState;
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

        // The run was actually charged.
        let snap = ledger.snapshot("run-1").unwrap();
        assert!(snap.spent > Microusd::ZERO);
        assert_eq!(snap.steps, 1);
    }

    #[tokio::test]
    async fn enforce_over_budget_returns_402_contract() {
        // Tiny budget + a big output => estimate exceeds budget before forwarding.
        let st = state(
            Mode::Enforce,
            StubProvider {
                input_tokens: 1_000,
                output_tokens: 100_000,
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
        // In shadow mode a step/steps violation must not block. Force a
        // max-steps violation via policy, but mode = shadow.
        let mut st = state(Mode::Shadow, StubProvider::default());
        st.policy = Arc::new(Policy {
            mode: Mode::Shadow,
            max_steps: Some(0), // any call violates
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
}
