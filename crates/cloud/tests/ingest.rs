//! End-to-end test of the ingest path: a JSON batch shaped exactly like a
//! gateway `CloudSink` POST (`{"records":[…]}`) flows through `/v1/ingest`,
//! authorizes by bearer key, and lands in the store's per-org aggregates.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Principal, Store};

fn state_with(store: Arc<Store>) -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        "k".to_string(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
        },
    );
    AppState::new(store, Arc::new(keys), 0.8)
}

#[tokio::test]
async fn ingest_authorized_aggregates_into_store() {
    let store = Arc::new(Store::new());
    let router = app(state_with(Arc::clone(&store)));

    // Exactly the shape crates/gateway/src/cloudsink.rs POSTs.
    let payload = r#"{"records":[
        {"ts_millis":100,"run_id":"r1","model":"claude","decision":"allow","input_tokens":10,"output_tokens":5,"cost_microusd":1000,"step":1},
        {"ts_millis":200,"run_id":"r1","model":"claude","decision":"cache_hit","input_tokens":0,"output_tokens":0,"cost_microusd":0,"step":2}
    ]}"#;

    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["accepted"], 2);

    let runs = store.runs("acme");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].spent_microusd, 1000);
    assert_eq!(runs[0].calls, 2);
    assert_eq!(runs[0].cache_hits, 1);
    assert_eq!(runs[0].steps, 2);
}

#[tokio::test]
async fn ingest_without_a_key_is_unauthorized() {
    let router = app(state_with(Arc::new(Store::new())));
    let resp = router
        .oneshot(
            Request::post("/v1/ingest")
                .body(Body::from(r#"{"records":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn healthz_is_ok() {
    let router = app(state_with(Arc::new(Store::new())));
    let resp = router
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
