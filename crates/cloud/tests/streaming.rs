//! HTTP-level tests for the burn-rate series (A7). The SSE stream is exercised
//! by a live curl smoke (see the PR) and by the store-level broadcast tests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Principal, Store};

fn state() -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        "k".into(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
        },
    );
    AppState::new(Arc::new(Store::new()), Arc::new(keys), 0.8)
}

async fn get_json(state: &AppState, path: &str) -> serde_json::Value {
    let resp = app(state.clone())
        .oneshot(
            Request::get(path)
                .header("authorization", "Bearer k")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn series_sums_match_the_summary() {
    let state = state();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Ingest two calls stamped ~now, over HTTP.
    let payload = format!(
        r#"{{"records":[
            {{"run_id":"r1","cost_microusd":1000,"ts_millis":{now}}},
            {{"run_id":"r1","cost_microusd":500,"ts_millis":{ts2}}}
        ]}}"#,
        ts2 = now - 1000
    );
    let resp = app(state.clone())
        .oneshot(
            Request::post("/v1/ingest")
                .header("authorization", "Bearer k")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The series over a covering window sums to the org total.
    let buckets = get_json(&state, "/v1/series?window=24h&step=1h").await;
    let arr = buckets.as_array().expect("series is an array");
    let cost: i64 = arr
        .iter()
        .map(|b| b["cost_microusd"].as_i64().unwrap())
        .sum();
    let calls: i64 = arr.iter().map(|b| b["calls"].as_i64().unwrap()).sum();

    let summary = get_json(&state, "/v1/summary").await;
    assert_eq!(cost, summary["spent_microusd"].as_i64().unwrap());
    assert_eq!(cost, 1500);
    assert_eq!(calls, 2);
}
