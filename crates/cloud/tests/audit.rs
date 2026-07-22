//! HTTP-level tests for the tamper-evident audit trail (WS2), mirroring
//! `tests/mutations.rs` and `tests/reads.rs`: control-plane mutations produce a
//! linked, verifiable chain; an org reads its own trail (viewer allowed, unauth
//! rejected).

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Principal, Store};

fn test_state() -> AppState {
    let store = Arc::new(Store::new());
    let mut keys = HashMap::new();
    keys.insert(
        "devkey".into(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
        },
    );
    keys.insert(
        "viewerkey".into(),
        Principal {
            org: "acme".into(),
            role: "viewer".into(),
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
async fn mutations_are_audited_and_chain_verifies() {
    let state = test_state();

    // A kill then a budget change — two authenticated control-plane mutations.
    let (status, _) = send(&state, "POST", "/v1/runs/run-1/kill", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &state,
        "POST",
        "/v1/runs/run-1/budget",
        Some("devkey"),
        Some(r#"{"budget_usd":2.5}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Both are on the chain, in order, with correct actions/subjects and seqs.
    let (status, v) = send(&state, "GET", "/v1/audit", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    let entries = v.as_array().expect("audit is an array");
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0]["seq"], 0);
    assert_eq!(entries[0]["action"], "control.kill");
    assert_eq!(entries[0]["subject"], "run-1");
    assert_eq!(entries[0]["prev_hash"], "");
    // The actor is the key fingerprint, never the raw bearer secret.
    let actor = entries[0]["actor"].as_str().unwrap();
    assert!(actor.starts_with("key:"), "actor was {actor}");
    assert_ne!(actor, "key:devkey");

    assert_eq!(entries[1]["seq"], 1);
    assert_eq!(entries[1]["action"], "control.set_budget");
    assert_eq!(entries[1]["subject"], "run-1");
    assert_eq!(entries[1]["detail"], "budget_micros=2500000");
    // Linked: entry 1's prev_hash is entry 0's entry_hash.
    assert_eq!(entries[1]["prev_hash"], entries[0]["entry_hash"]);

    // The chain verifies end-to-end.
    let (status, v) = send(&state, "GET", "/v1/audit/verify", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["ok"], true);
    assert!(v.get("break_index").is_none());
}

#[tokio::test]
async fn audit_readable_by_viewer_unauth_rejected() {
    let state = test_state();

    // Seed one mutation as admin.
    let (status, _) = send(&state, "POST", "/v1/runs/r1/kill", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);

    // A viewer of the org may read its own audit trail.
    let (status, v) = send(&state, "GET", "/v1/audit", Some("viewerkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v.as_array().expect("array").len(), 1);

    // Unauthenticated and unknown keys are rejected.
    let (no_key, _) = send(&state, "GET", "/v1/audit", None, None).await;
    assert_eq!(no_key, StatusCode::UNAUTHORIZED);
    let (wrong_key, _) = send(&state, "GET", "/v1/audit", Some("nope"), None).await;
    assert_eq!(wrong_key, StatusCode::UNAUTHORIZED);
}
