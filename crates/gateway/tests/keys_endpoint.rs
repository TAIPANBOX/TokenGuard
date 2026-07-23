//! Integration test for `GET /v1/keys` (docs/22-key-lifecycle.md): hits the
//! real router built by `tokenfuse_gateway::app`, not `keysreport`'s
//! internal assembly function directly - this proves the HTTP wiring (route
//! registration, no-auth posture, JSON shape) and, most importantly, that a
//! configured secret never leaks into the response body.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tokenfuse_core::{Ledger, Mode, Policy, PriceBook};
use tokenfuse_gateway::clientkeys::ClientKeys;
use tokenfuse_gateway::identitymap::{IdentityMap, StrictMode};
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::unitledger::UnitLedger;
use tower::ServiceExt;

const CONFIGURED_SECRET: &str = "sk-live-abc-super-secret";
const OTHER_SECRET: &str = "sk-live-def-also-secret";

/// Per-call uniquifier for the temp map path below. The tests in this binary
/// run in parallel threads of ONE process, so a pid-only filename is shared
/// across them - one test's `remove_file` then races another's read (exactly
/// what CI hit: NotFound / a default map). Same fix `keysreport.rs`'s own
/// `map_from` helper already uses.
static NEXT_MAP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_identity_map(json: &str) -> IdentityMap {
    let path = std::env::temp_dir().join(format!(
        "tf-keys-endpoint-map-{}-{}.json",
        std::process::id(),
        NEXT_MAP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, json).unwrap();
    let map = IdentityMap::from_path(&path).expect("valid map");
    let _ = std::fs::remove_file(&path);
    map
}

/// A gateway with three key_ids across the union's three states:
/// `billing-agent` (configured AND bound, with `created`), `solo-agent`
/// (configured only, unbound), `dangling-key` (bound only, no matching
/// `TOKENFUSE_CLIENT_KEYS` entry). No `TOKENFUSE_DATA_DIR`, so history stays
/// unavailable throughout.
fn state() -> AppState {
    let keys = ClientKeys::from_spec(&format!(
        "{CONFIGURED_SECRET}:billing-agent,{OTHER_SECRET}:solo-agent"
    ))
    .expect("valid spec");
    let map = write_identity_map(
        r#"{
            "units": [{"id": "treasury", "budget_usd_month": 500.0}],
            "keys": [
                {"key_id": "billing-agent", "unit": "treasury",
                 "agents": ["agent://acme.example/billing/*"], "created": "2026-07-01"},
                {"key_id": "dangling-key", "unit": "treasury"}
            ]
        }"#,
    );
    let units = Arc::new(UnitLedger::new(map.unit_budgets()));

    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(PriceBook::new()),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "test-policy",
    )
    .with_client_keys(Arc::new(keys))
    .with_identity(Arc::new(map), StrictMode::Warn, units)
}

#[tokio::test]
async fn get_v1_keys_serves_the_union_sorted_with_no_secret_leakage() {
    let st = state();

    // Drive one authenticated call through first, so `since_startup` has
    // something real to report for "billing-agent" too.
    let authed_req = Request::post("/v1/messages")
        .header("x-fuse-key", CONFIGURED_SECRET)
        .header("x-fuse-run-id", "warm-up")
        .header("x-fuse-budget-usd", "5.0")
        .header("x-fuse-agent-id", "agent://acme.example/billing/bot-1")
        .body(Body::from(
            r#"{"model":"test-model","max_tokens":10}"#.to_string(),
        ))
        .unwrap();
    let warm_up = tokenfuse_gateway::app(st.clone())
        .oneshot(authed_req)
        .await
        .unwrap();
    // Not a correctness assertion for this test (no price book entry for
    // "test-model" here, so the exact status doesn't matter) - only that
    // the credential resolved and the request was actually handled.
    assert_ne!(warm_up.status(), StatusCode::UNAUTHORIZED);

    let req = Request::get("/v1/keys").body(Body::empty()).unwrap();
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );

    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();

    assert!(
        !text.contains(CONFIGURED_SECRET),
        "the configured secret must never appear in the response body"
    );
    assert!(
        !text.contains(OTHER_SECRET),
        "no configured secret substring may appear anywhere in the body"
    );

    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["strict_mode"], "warn");
    assert_eq!(json["identity_map_configured"], true);
    assert_eq!(json["history_available"], false);
    assert_eq!(json["unauthorized_since_startup"]["attempts"], 0);
    assert!(json["unauthorized_since_startup"]["last_millis"].is_null());

    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);
    let ids: Vec<&str> = keys.iter().map(|k| k["key_id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        vec!["billing-agent", "dangling-key", "solo-agent"],
        "sorted ascending by key_id"
    );

    let billing = keys
        .iter()
        .find(|k| k["key_id"] == "billing-agent")
        .unwrap();
    assert_eq!(billing["configured"], true);
    assert_eq!(billing["bound"], true);
    assert_eq!(billing["unit"], "treasury");
    assert_eq!(
        billing["agents"],
        serde_json::json!(["agent://acme.example/billing/*"])
    );
    assert_eq!(billing["created"], "2026-07-01");
    assert!(billing["history"].is_null());
    assert_eq!(billing["since_startup"]["calls"], 1);
    assert!(!billing["since_startup"]["last_seen_millis"].is_null());

    let dangling = keys.iter().find(|k| k["key_id"] == "dangling-key").unwrap();
    assert_eq!(dangling["configured"], false);
    assert_eq!(dangling["bound"], true);
    assert_eq!(dangling["unit"], "treasury");
    assert_eq!(dangling["since_startup"]["calls"], 0);

    let solo = keys.iter().find(|k| k["key_id"] == "solo-agent").unwrap();
    assert_eq!(solo["configured"], true);
    assert_eq!(solo["bound"], false);
    assert!(solo["unit"].is_null());
    assert_eq!(solo["agents"], serde_json::json!([]));
    assert!(solo["created"].is_null());
}

#[tokio::test]
async fn get_v1_keys_requires_no_credential() {
    // Same (absent) auth posture as GET /v1/runs: no `x-fuse-key` header at
    // all must still succeed.
    let st = state();
    let req = Request::get("/v1/keys").body(Body::empty()).unwrap();
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_v1_keys_on_a_default_gateway_reports_everything_off() {
    let st = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(PriceBook::new()),
        Arc::new(Policy::default()),
        Arc::new(StubProvider::default()),
        "test-policy",
    );
    let req = Request::get("/v1/keys").body(Body::empty()).unwrap();
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["strict_mode"], "off");
    assert_eq!(json["identity_map_configured"], false);
    assert_eq!(json["history_available"], false);
    assert_eq!(json["keys"], serde_json::json!([]));
}
