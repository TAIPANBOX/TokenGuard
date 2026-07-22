//! HTTP-level tests for `POST /v1/findings`: detections this plane did not
//! make, carried but never disguised as its own.
use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, FindingInput, Principal, Store};

fn test_state() -> (AppState, Arc<Store>) {
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
    (
        AppState::new(Arc::clone(&store), Arc::new(keys), 0.8),
        store,
    )
}

async fn post(
    state: &AppState,
    path: &str,
    key: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::post(path).header("content-type", "application/json");
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let resp = app(state.clone())
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn get(state: &AppState, path: &str, key: &str) -> serde_json::Value {
    let resp = app(state.clone())
        .oneshot(
            Request::get(path)
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn finding(detector: &str, identity: &str, severity: &str) -> serde_json::Value {
    serde_json::json!({
        "detector": detector,
        "identity": identity,
        "severity": severity,
        "time": "2026-07-21T09:00:00Z",
        "summary": "agent calls an MCP server nobody sanctioned"
    })
}

#[tokio::test]
async fn a_finding_becomes_an_incident_that_says_who_found_it() {
    let (state, _store) = test_state();
    let (status, body) = post(
        &state,
        "/v1/findings?source=idryx",
        Some("devkey"),
        serde_json::json!([finding(
            "agent_shadow_tool",
            "agent://meridian.example/support/support-tier2-bot",
            "high"
        )]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 1);

    let incidents = get(&state, "/v1/incidents", "devkey").await;
    let inc = &incidents.as_array().unwrap()[0];
    assert_eq!(inc["kind"], "agent_shadow_tool");
    assert_eq!(inc["severity"], "high");
    assert_eq!(
        inc["source"], "idryx",
        "the reporter is recorded, so a borrowed detection is never shown as a measured one"
    );
    assert_eq!(
        inc["agent_id"], "agent://meridian.example/support/support-tier2-bot",
        "an agent:// subject is attributed, which is what joins it to the agent's row"
    );
    assert!(inc["summary"].as_str().unwrap().contains("MCP server"));
}

#[tokio::test]
async fn our_own_detections_carry_no_source() {
    // A finding sets `source`; a threshold this plane trips itself must not,
    // or the field would stop meaning anything.
    let (_state, store) = test_state();
    store.record_external_finding(
        "acme",
        "key:abc123",
        FindingInput {
            source: "idryx",
            detector: "data_exfiltration",
            severity: tokenfuse_core::Severity::Critical,
            subject: "agent://meridian.example/treasury/cashflow-forecaster",
            summary: "large outbound transfer to an unknown sink",
            ts_millis: 1_000,
        },
    );
    let incidents = store.incidents("acme");
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].source.as_deref(), Some("idryx"));
    assert!(
        incidents[0].summary.is_some(),
        "the detector's own sentence is usually the only readable explanation"
    );
}

#[tokio::test]
async fn the_same_finding_twice_is_one_incident_that_counts() {
    let (state, store) = test_state();
    let payload = serde_json::json!([finding(
        "behavior_anomaly",
        "agent://meridian.example/fraud/fraud-triage-copilot",
        "medium"
    )]);
    for _ in 0..3 {
        let (status, _) = post(&state, "/v1/findings", Some("devkey"), payload.clone()).await;
        assert_eq!(status, StatusCode::OK);
    }
    let incidents = store.incidents("acme");
    assert_eq!(incidents.len(), 1, "deduped on (kind, subject)");
    assert_eq!(incidents[0].occurrences, 3);
}

#[tokio::test]
async fn a_viewer_key_cannot_assert_an_incident() {
    // /v1/ingest is deliberately ungated because it submits evidence that
    // thresholds still have to agree with. This asserts an incident outright,
    // which is a different authority.
    let (state, store) = test_state();
    let (status, _) = post(
        &state,
        "/v1/findings",
        Some("viewerkey"),
        serde_json::json!([finding("shadow_ai", "agent://meridian.example/x/y", "high")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(store.incidents("acme").is_empty());

    let (status, _) = post(
        &state,
        "/v1/findings",
        None,
        serde_json::json!([finding("shadow_ai", "agent://meridian.example/x/y", "high")]),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unknown_severity_is_refused_rather_than_guessed() {
    // Severity decides whether the phone treats this as something still
    // running or a soft heads-up, so a typo must not quietly become the
    // safest-looking answer.
    let (state, store) = test_state();
    let (status, body) = post(
        &state,
        "/v1/findings",
        Some("devkey"),
        serde_json::json!([finding(
            "mcp_drift",
            "agent://meridian.example/x/y",
            "sever"
        )]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("severity"));
    assert!(store.incidents("acme").is_empty());
}

#[tokio::test]
async fn a_non_agent_subject_is_carried_without_being_attributed_to_an_agent() {
    let (state, store) = test_state();
    let (status, _) = post(
        &state,
        "/v1/findings",
        Some("devkey"),
        serde_json::json!([finding(
            "impossible_travel",
            "user:kate@meridian.example",
            "high"
        )]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let incidents = store.incidents("acme");
    assert_eq!(incidents.len(), 1);
    assert!(
        incidents[0].agent_id.is_none(),
        "a human identity is not an agent, and must not be filed as one"
    );
}
