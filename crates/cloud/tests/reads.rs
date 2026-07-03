//! HTTP-level tests for the read endpoints (A3), ported from the Go plane's
//! main_test.go: ingest→query, alert thresholding, auth rejection, and CORS.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, CallRecord, Principal, Store};

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
    keys.insert(
        "otherorg".into(),
        Principal {
            org: "beta".into(),
            role: "admin".into(),
        },
    );
    (
        AppState::new(Arc::clone(&store), Arc::new(keys), 0.8),
        store,
    )
}

/// GET a path with an optional bearer key; returns (status, parsed JSON body).
async fn get(state: &AppState, path: &str, key: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::get(path);
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let resp = app(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn ingest_then_query_runs_and_summary() {
    let (state, _store) = test_state();

    // Ingest over HTTP (shared store), then read it back.
    let payload = r#"{"records":[{"ts_millis":10,"run_id":"run-x","model":"claude","decision":"allow","cost_microusd":2500,"step":1}]}"#;
    let resp = app(state.clone())
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer devkey")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, v) = get(&state, "/v1/runs", Some("devkey")).await;
    assert_eq!(status, StatusCode::OK);
    let runs = v.as_array().expect("runs is an array");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["run_id"], "run-x");
    assert_eq!(runs[0]["spent_microusd"], 2500);

    let (_, s) = get(&state, "/v1/summary", Some("devkey")).await;
    assert_eq!(s["runs"], 1);
    assert_eq!(s["calls"], 1);
    assert_eq!(s["spent_microusd"], 2500);
}

#[tokio::test]
async fn alerts_only_fire_over_threshold() {
    let (state, store) = test_state();
    // Budget r-hot at $1, r-cool at $10; spend $0.90 on each.
    store.set_budget("acme", "r-hot", 1_000_000);
    store.set_budget("acme", "r-cool", 10_000_000);
    store.ingest(
        "acme",
        &[
            CallRecord {
                run_id: "r-hot".into(),
                cost_microusd: 900_000,
                step: 1,
                ..Default::default()
            },
            CallRecord {
                run_id: "r-cool".into(),
                cost_microusd: 900_000,
                step: 1,
                ..Default::default()
            },
        ],
    );

    // A viewer may read alerts. Only r-hot (90% ≥ 80%) fires.
    let (status, v) = get(&state, "/v1/alerts", Some("viewerkey")).await;
    assert_eq!(status, StatusCode::OK);
    let alerts = v.as_array().expect("alerts is an array");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["run_id"], "r-hot");
}

#[tokio::test]
async fn reads_require_a_valid_key() {
    let (state, _) = test_state();
    let (no_key, _) = get(&state, "/v1/runs", None).await;
    assert_eq!(no_key, StatusCode::UNAUTHORIZED);
    let (wrong_key, _) = get(&state, "/v1/runs", Some("nope")).await;
    assert_eq!(wrong_key, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cors_preflight_is_answered() {
    let (state, _) = test_state();
    let resp = app(state)
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/runs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
}
