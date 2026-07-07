//! HTTP-level tests for the read endpoints (A3), ported from the Go plane's
//! main_test.go: ingest→query, alert thresholding, auth rejection, and CORS.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, CallRecord, Plan, Principal, Store};

fn test_state() -> (AppState, Arc<Store>) {
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
    keys.insert(
        "otherorg".into(),
        Principal {
            org: "beta".into(),
            role: "admin".into(),
            plan: Plan::Paid,
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
async fn ingest_excludes_blocked_spend_from_summary() {
    let (state, _store) = test_state();

    // A mix of one settled call and one blocked call (avoided-spend estimate)
    // for the same run. The blocked call must be stored and counted, but its
    // cost must not inflate spend.
    let payload = r#"{"records":[
        {"ts_millis":10,"run_id":"run-y","model":"claude","decision":"allow","cost_microusd":2000,"step":1},
        {"ts_millis":20,"run_id":"run-y","model":"claude","decision":"budget_exceeded","cost_microusd":500000,"step":2}
    ]}"#;
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
    assert_eq!(runs[0]["run_id"], "run-y");
    // Only the allow record's cost counts — the blocked one is excluded.
    assert_eq!(runs[0]["spent_microusd"], 2000);

    let (_, s) = get(&state, "/v1/summary", Some("devkey")).await;
    assert_eq!(s["runs"], 1);
    // Both calls are still counted.
    assert_eq!(s["calls"], 2);
    assert_eq!(s["spent_microusd"], 2000);
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
                decision: "allow".into(),
                cost_microusd: 900_000,
                step: 1,
                ..Default::default()
            },
            CallRecord {
                run_id: "r-cool".into(),
                decision: "allow".into(),
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
async fn agents_roll_up_and_sort_by_spend() {
    let (state, store) = test_state();
    store.ingest(
        "acme",
        &[
            CallRecord {
                run_id: "r1".into(),
                agent_id: "planner".into(),
                decision: "allow".into(),
                cost_microusd: 1000,
                ts_millis: 10,
                ..Default::default()
            },
            CallRecord {
                run_id: "r2".into(),
                agent_id: "planner".into(),
                decision: "allow".into(),
                cost_microusd: 2000,
                ts_millis: 20,
                ..Default::default()
            },
            // A budget-protection block: counted, but avoided cost is not spend.
            CallRecord {
                run_id: "r3".into(),
                agent_id: "coder".into(),
                decision: "allow".into(),
                cost_microusd: 500,
                ts_millis: 30,
                ..Default::default()
            },
            CallRecord {
                run_id: "r3".into(),
                agent_id: "coder".into(),
                decision: "budget_exceeded".into(),
                cost_microusd: 900_000,
                ts_millis: 40,
                ..Default::default()
            },
            // Unattributed run kept as its own ("") bucket.
            CallRecord {
                run_id: "r4".into(),
                decision: "allow".into(),
                cost_microusd: 250,
                ts_millis: 50,
                ..Default::default()
            },
        ],
    );

    // A viewer may read agents.
    let (status, v) = get(&state, "/v1/agents", Some("viewerkey")).await;
    assert_eq!(status, StatusCode::OK);
    let agents = v.as_array().expect("agents is an array");
    assert_eq!(agents.len(), 3);
    // Sorted by spend desc.
    assert_eq!(agents[0]["agent_id"], "planner");
    assert_eq!(agents[0]["spent_microusd"], 3000);
    assert_eq!(agents[0]["calls"], 2);
    assert_eq!(agents[0]["runs"], 2);
    assert_eq!(agents[1]["agent_id"], "coder");
    // Blocked row excluded from spend.
    assert_eq!(agents[1]["spent_microusd"], 500);
    assert_eq!(agents[2]["agent_id"], "");
    assert_eq!(agents[2]["spent_microusd"], 250);
}

#[tokio::test]
async fn savings_sum_blocked_cache_and_breaks() {
    let (state, _store) = test_state();
    // allow + budget_exceeded (avoided) + cache_hit (saved) + dlp (excluded),
    // over two distinct blocked runs.
    let payload = r#"{"records":[
        {"ts_millis":10,"run_id":"r1","decision":"allow","cost_microusd":1000},
        {"ts_millis":20,"run_id":"r1","decision":"budget_exceeded","cost_microusd":500000},
        {"ts_millis":30,"run_id":"r2","decision":"loop_detected","cost_microusd":200000},
        {"ts_millis":40,"run_id":"r1","decision":"cache_hit","saved_microusd":30000},
        {"ts_millis":50,"run_id":"r3","decision":"dlp_blocked","cost_microusd":9000000}
    ]}"#;
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

    // A viewer may read savings.
    let (status, s) = get(&state, "/v1/savings", Some("viewerkey")).await;
    assert_eq!(status, StatusCode::OK);
    // Only budget-protection cost; dlp excluded.
    assert_eq!(s["blocked_spend_microusd"], 700_000);
    assert_eq!(s["cache_saved_microusd"], 30_000);
    // Distinct blocked runs r1 + r2.
    assert_eq!(s["budget_breaks"], 2);
    assert_eq!(s["total_saved_microusd"], 730_000);
}

#[tokio::test]
async fn incidents_endpoint_lists_for_viewer_and_rejects_unauth() {
    let (state, store) = test_state();
    // Three budget-protection blocks on one run trip a `budget_exhausted`
    // incident (default threshold is 3).
    let block = || CallRecord {
        run_id: "r1".into(),
        decision: "budget_exceeded".into(),
        cost_microusd: 1000,
        ..Default::default()
    };
    store.ingest("acme", &[block(), block(), block()]);

    // A viewer may read incidents.
    let (status, v) = get(&state, "/v1/incidents", Some("viewerkey")).await;
    assert_eq!(status, StatusCode::OK);
    let incs = v.as_array().expect("incidents is an array");
    assert_eq!(incs.len(), 1);
    assert_eq!(incs[0]["kind"], "budget_exhausted");
    assert_eq!(incs[0]["severity"], "high");
    assert_eq!(incs[0]["run_id"], "r1");
    assert_eq!(incs[0]["acknowledged"], false);

    // Gated like the other reads.
    let (no_key, _) = get(&state, "/v1/incidents", None).await;
    assert_eq!(no_key, StatusCode::UNAUTHORIZED);
    let (wrong_key, _) = get(&state, "/v1/incidents", Some("nope")).await;
    assert_eq!(wrong_key, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reads_require_a_valid_key() {
    let (state, _) = test_state();
    let (no_key, _) = get(&state, "/v1/runs", None).await;
    assert_eq!(no_key, StatusCode::UNAUTHORIZED);
    let (wrong_key, _) = get(&state, "/v1/runs", Some("nope")).await;
    assert_eq!(wrong_key, StatusCode::UNAUTHORIZED);

    // The new read endpoints are gated too.
    for path in ["/v1/agents", "/v1/savings"] {
        let (no_key, _) = get(&state, path, None).await;
        assert_eq!(no_key, StatusCode::UNAUTHORIZED, "{path} unauth");
        let (wrong_key, _) = get(&state, path, Some("nope")).await;
        assert_eq!(wrong_key, StatusCode::UNAUTHORIZED, "{path} wrong key");
    }
}

#[tokio::test]
async fn dashboard_is_served_at_root() {
    let (state, _) = test_state();
    let resp = app(state)
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        html.contains("TokenFuse Cloud"),
        "dashboard HTML not served"
    );
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
