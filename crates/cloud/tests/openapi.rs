//! The OpenAPI contract (A6): it generates, covers every documented endpoint,
//! and is served at `/openapi.json`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, openapi_spec, AppState, Plan, Principal, Store};

fn state() -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        "k".into(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            plan: Plan::Paid,
        },
    );
    AppState::new(Arc::new(Store::new()), Arc::new(keys), 0.8)
}

#[test]
fn spec_covers_every_endpoint() {
    let spec = openapi_spec();
    let json = serde_json::to_value(&spec).expect("spec serializes");

    assert!(json["openapi"].as_str().unwrap().starts_with("3."));
    let paths = json["paths"].as_object().expect("paths object");
    for p in [
        "/v1/ingest",
        "/v1/runs",
        "/v1/summary",
        "/v1/alerts",
        "/v1/runs/{run}/kill",
        "/v1/kills",
        "/v1/runs/{run}/budget",
        "/v1/budgets",
        "/v1/incidents",
        "/v1/incidents/{id}/ack",
    ] {
        assert!(paths.contains_key(p), "spec missing path {p}");
    }

    // Core response schemas are present for the generated clients.
    let schemas = json["components"]["schemas"]
        .as_object()
        .expect("component schemas");
    for s in ["RunAgg", "Summary", "Alert", "CallRecord", "Incident"] {
        assert!(schemas.contains_key(s), "spec missing schema {s}");
    }
}

#[tokio::test]
async fn openapi_json_is_served() {
    let resp = app(state())
        .oneshot(Request::get("/openapi.json").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
    assert!(v["paths"]["/v1/runs"].is_object());
}
