//! HTTP-level tests for the P2 entitlements gate: a `:free` org is refused the
//! paid control-plane surface with `402 plan_required`, while a default
//! (plan-less → Paid) org is served normally, and telemetry ingest is never
//! blocked. Mirrors the harness in `reads.rs` / `mutations.rs`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, parse_keys, AppState, Store};

/// `freekey` → org `free-co` explicitly `:free`; `paidkey` → org `acme` with no
/// plan segment (defaults to Paid, exactly like every pre-entitlements key).
fn test_state() -> AppState {
    // allow_devkey=false: this spec has real entries, so the fallback is
    // never consulted either way, passed false to make that explicit.
    let keys = parse_keys("freekey:free-co:admin:free,paidkey:acme:admin", false);
    AppState::new(Arc::new(Store::new()), Arc::new(keys), 0.8)
}

async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    key: &str,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {key}"))
        .body(
            body.map(|b| Body::from(b.to_owned()))
                .unwrap_or(Body::empty()),
        )
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn free_key_gets_402_plan_required_on_paid_reads() {
    let state = test_state();
    for path in ["/v1/runs", "/v1/savings", "/v1/incidents", "/v1/compliance"] {
        let (status, v) = send(&state, "GET", path, "freekey", None).await;
        assert_eq!(
            status,
            StatusCode::PAYMENT_REQUIRED,
            "{path} should be gated"
        );
        // The plan_required contract: nested error object with the feature,
        // the org, and an upgrade URL.
        assert_eq!(v["error"]["type"], "plan_required", "{path}");
        assert_eq!(v["error"]["org"], "free-co", "{path}");
        assert_eq!(
            v["error"]["upgrade_url"], "https://tokenfuse.dev/pricing",
            "{path}"
        );
        assert!(
            v["error"]["feature"].is_string(),
            "{path} carries a feature id"
        );
    }
}

#[tokio::test]
async fn free_key_gets_402_on_kill_mutation() {
    let state = test_state();
    let (status, v) = send(&state, "POST", "/v1/runs/runaway/kill", "freekey", None).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(v["error"]["type"], "plan_required");
    assert_eq!(v["error"]["feature"], "cross_fleet_kill");
    assert_eq!(v["error"]["org"], "free-co");
}

#[tokio::test]
async fn free_key_gets_402_on_poll_endpoints() {
    let state = test_state();
    // The gateway pollers hit these every 3s; a free org gets 402 (handled
    // gracefully client-side).
    for path in ["/v1/kills", "/v1/budgets"] {
        let (status, v) = send(&state, "GET", path, "freekey", None).await;
        assert_eq!(
            status,
            StatusCode::PAYMENT_REQUIRED,
            "{path} should be gated"
        );
        assert_eq!(v["error"]["type"], "plan_required", "{path}");
    }
}

#[tokio::test]
async fn free_key_can_still_ingest_telemetry() {
    let state = test_state();
    // Data collection is fail-open: a free org's gateways must keep shipping.
    let payload = r#"{"records":[{"ts_millis":10,"run_id":"r1","decision":"allow","cost_microusd":1000,"step":1}]}"#;
    let (status, v) = send(&state, "POST", "/v1/ingest", "freekey", Some(payload)).await;
    assert_eq!(status, StatusCode::OK, "ingest must never be plan-gated");
    assert_eq!(v["accepted"], 1);
}

#[tokio::test]
async fn paid_key_is_served_normally() {
    let state = test_state();
    // Regression: a plan-less (→ Paid) key sees the pre-entitlements behavior.
    let (status, v) = send(&state, "GET", "/v1/runs", "paidkey", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.is_array(), "runs is an array");

    let (status, _) = send(&state, "POST", "/v1/runs/r1/kill", "paidkey", None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(&state, "GET", "/v1/kills", "paidkey", None).await;
    assert_eq!(status, StatusCode::OK);
}

/// Plan gating must key off the AUTHENTICATING PRINCIPAL'S OWN plan, not an
/// org-wide scan for any `:free` key. One org with both a `:free` and a paid
/// admin key: the paid key still sees 200 on a gated route, and the free key
/// still sees 402 on that SAME route — a sibling free key must never silently
/// downgrade a paid key's access (and vice versa).
#[tokio::test]
async fn plan_gate_keys_off_the_calling_principal_not_a_sibling_key() {
    let keys = parse_keys(
        "freekey:mixed-co:admin:free,paidkey:mixed-co:admin:paid",
        false,
    );
    let state = AppState::new(Arc::new(Store::new()), Arc::new(keys), 0.8);

    // The paid key on this org is served normally...
    let (status, v) = send(&state, "GET", "/v1/runs", "paidkey", None).await;
    assert_eq!(status, StatusCode::OK, "paid key should not be gated");
    assert!(v.is_array());
    let (status, _) = send(&state, "POST", "/v1/runs/r1/kill", "paidkey", None).await;
    assert_eq!(status, StatusCode::OK, "paid key should be able to mutate");

    // ...while the free key for the SAME org is still gated on the same route.
    let (status, v) = send(&state, "GET", "/v1/runs", "freekey", None).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "free key stays gated");
    assert_eq!(v["error"]["type"], "plan_required");
    let (status, v) = send(&state, "POST", "/v1/runs/r2/kill", "freekey", None).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "free key stays gated on mutations too"
    );
    assert_eq!(v["error"]["feature"], "cross_fleet_kill");
}
