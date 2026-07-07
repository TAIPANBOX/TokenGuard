//! HTTP-level tests for the mutation endpoints (A4), ported from the Go plane's
//! main_test.go: kill flow, budget flow, RBAC (viewer → 403), and auth.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Plan, Principal, Store};

fn test_state() -> AppState {
    let store = Arc::new(Store::new());
    let mut keys = HashMap::new();
    keys.insert(
        "devkey".into(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            plan: Plan::Paid,
        },
    );
    keys.insert(
        "viewerkey".into(),
        Principal {
            org: "acme".into(),
            role: "viewer".into(),
            plan: Plan::Paid,
        },
    );
    AppState::new(store, Arc::new(keys), 0.8)
}

/// Send a request through a fresh router built from `state`; returns
/// (status, parsed JSON body).
async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let req = req
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
async fn kill_flow() {
    let state = test_state();

    let (status, v) = send(
        &state,
        "POST",
        "/v1/runs/runaway-1/kill",
        Some("devkey"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["killed"], "runaway-1");

    let (status, kills) = send(&state, "GET", "/v1/kills", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    let kills = kills.as_array().expect("kills is an array");
    assert_eq!(kills.len(), 1);
    assert_eq!(kills[0], "runaway-1");

    // Kill requires a key.
    let (status, _) = send(&state, "POST", "/v1/runs/x/kill", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn budget_flow() {
    let state = test_state();

    let (status, v) = send(
        &state,
        "POST",
        "/v1/runs/r9/budget",
        Some("devkey"),
        Some(r#"{"budget_usd":2.5}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["budget_micros"], 2_500_000);

    let (status, budgets) = send(&state, "GET", "/v1/budgets", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(budgets["r9"], 2_500_000);
}

#[tokio::test]
async fn viewer_can_read_but_not_mutate() {
    let state = test_state();

    // A viewer may read...
    let (status, _) = send(&state, "GET", "/v1/runs", Some("viewerkey"), None).await;
    assert_eq!(status, StatusCode::OK);

    // ...but cannot kill (403, not 401)...
    let (status, _) = send(&state, "POST", "/v1/runs/r1/kill", Some("viewerkey"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ...and cannot set a budget.
    let (status, _) = send(
        &state,
        "POST",
        "/v1/runs/r1/budget",
        Some("viewerkey"),
        Some(r#"{"budget_usd":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn incident_ack_flow_and_rbac() {
    let state = test_state();

    // Seed an incident: three budget-protection blocks on run r1.
    let payload = r#"{"records":[
        {"run_id":"r1","decision":"budget_exceeded","cost_microusd":1000},
        {"run_id":"r1","decision":"budget_exceeded","cost_microusd":1000},
        {"run_id":"r1","decision":"budget_exceeded","cost_microusd":1000}
    ]}"#;
    let (status, _) = send(&state, "POST", "/v1/ingest", Some("devkey"), Some(payload)).await;
    assert_eq!(status, StatusCode::OK);

    // A viewer cannot ack (403, before any existence check).
    let (status, _) = send(
        &state,
        "POST",
        "/v1/incidents/budget_exhausted:r1/ack",
        Some("viewerkey"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An admin acks it (200).
    let (status, v) = send(
        &state,
        "POST",
        "/v1/incidents/budget_exhausted:r1/ack",
        Some("devkey"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["acknowledged"], "budget_exhausted:r1");

    // Unknown incident → 404.
    let (status, _) = send(
        &state,
        "POST",
        "/v1/incidents/nope/ack",
        Some("devkey"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The acknowledged flag surfaces on the read.
    let (status, list) = send(&state, "GET", "/v1/incidents", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list[0]["acknowledged"], true);
}

#[tokio::test]
async fn unknown_key_is_unauthorized_on_mutation() {
    let state = test_state();
    let (status, _) = send(&state, "POST", "/v1/runs/r1/kill", Some("nope"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
