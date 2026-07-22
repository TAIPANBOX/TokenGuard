//! HTTP-level tests for incident replay (wave 2), mirroring `tests/audit.rs`
//! and `tests/reads.rs`: `GET /v1/replay/{run}` reads the agent-event NDJSON
//! export, scoped to one run and ts-ordered, joined with that run's incidents
//! and audit-chain entries; cross-org run ids 404 rather than leak.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Principal, Store};

fn keys() -> HashMap<String, Principal> {
    let mut keys = HashMap::new();
    keys.insert(
        "devkey".into(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
        },
    );
    keys.insert(
        "otherorg".into(),
        Principal {
            org: "beta".into(),
            role: "admin".into(),
        },
    );
    keys
}

/// A scratch NDJSON file under a per-test directory, so parallel test binaries
/// never collide (mirrors `crates/cloud/src/replay.rs`'s own test helper).
fn write_events(name: &str, lines: &[&str]) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("tf-replay-http-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.ndjson");
    let mut f = std::fs::File::create(&path).unwrap();
    for l in lines {
        writeln!(f, "{l}").unwrap();
    }
    path
}

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
async fn replay_returns_ordered_events_scoped_to_the_run_with_incidents_and_audit() {
    let events_path = write_events(
        "ok",
        &[
            // run-1, out of ts order in the file: replay must sort ascending.
            r#"{"schema":"taipanbox.dev/agent-event/v0.1","ts":"2026-07-09T03:12:44.300Z","source":"tokenfuse","type":"breaker_tripped","severity":"critical","agent_id":"a1","run_id":"run-1","data":{"n":2}}"#,
            r#"{"schema":"taipanbox.dev/agent-event/v0.1","ts":"2026-07-09T03:12:44.100Z","source":"tokenfuse","type":"budget_exhausted","severity":"critical","agent_id":"a1","run_id":"run-1","data":{"n":1}}"#,
            // A different run: must not leak into run-1's replay.
            r#"{"schema":"taipanbox.dev/agent-event/v0.1","ts":"2026-07-09T03:12:44.200Z","source":"tokenfuse","type":"taint_block","severity":"high","agent_id":"a1","run_id":"run-2","data":{}}"#,
            // A malformed line: must be skipped and counted, not crash the read.
            "{{{not valid json",
        ],
    );

    let store = Arc::new(Store::new());
    let state = AppState::new(store, Arc::new(keys()), 0.8)
        .with_replay_events_path(Some(events_path.to_str().unwrap().to_string()));

    // Trip the `budget_exhausted` incident detector for run-1 (default
    // threshold is 3 budget-protection blocks) so the run both belongs to the
    // org (proving org-scoping passes) and has a joinable incident.
    let payload = r#"{"records":[
        {"ts_millis":1,"run_id":"run-1","model":"claude","decision":"budget_exceeded","cost_microusd":100,"step":1},
        {"ts_millis":2,"run_id":"run-1","model":"claude","decision":"budget_exceeded","cost_microusd":100,"step":2},
        {"ts_millis":3,"run_id":"run-1","model":"claude","decision":"budget_exceeded","cost_microusd":100,"step":3}
    ]}"#;
    let (status, _) = send(&state, "POST", "/v1/ingest", Some("devkey"), Some(payload)).await;
    assert_eq!(status, StatusCode::OK);

    // A kill on run-1: an authenticated control-plane mutation whose audit
    // entry's subject is the run id, so it must be joined into the replay.
    let (status, _) = send(&state, "POST", "/v1/runs/run-1/kill", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, v) = send(&state, "GET", "/v1/replay/run-1", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(v["run_id"], "run-1");
    assert_eq!(v["configured"], true);

    let events = v["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2, "only run-1's events, run-2's excluded");
    assert_eq!(events[0]["ts"], "2026-07-09T03:12:44.100Z");
    assert_eq!(events[0]["type"], "budget_exhausted");
    assert_eq!(events[1]["ts"], "2026-07-09T03:12:44.300Z");
    assert_eq!(events[1]["type"], "breaker_tripped");
    assert_eq!(v["event_count"], 2);
    assert_eq!(v["malformed_skipped"], 1);

    let incidents = v["incidents"].as_array().expect("incidents array");
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0]["kind"], "budget_exhausted");
    assert_eq!(incidents[0]["run_id"], "run-1");

    let audit = v["audit"].as_array().expect("audit array");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["action"], "control.kill");
    assert_eq!(audit[0]["subject"], "run-1");

    std::fs::remove_dir_all(events_path.parent().unwrap()).ok();
}

#[tokio::test]
async fn replay_without_configured_path_still_returns_store_derived_parts() {
    let store = Arc::new(Store::new());
    let state = AppState::new(store, Arc::new(keys()), 0.8);

    let payload = r#"{"records":[{"ts_millis":1,"run_id":"run-9","model":"claude","decision":"allow","cost_microusd":100,"step":1}]}"#;
    let (status, _) = send(&state, "POST", "/v1/ingest", Some("devkey"), Some(payload)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, v) = send(&state, "GET", "/v1/replay/run-9", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["configured"], false);
    assert_eq!(v["events"].as_array().unwrap().len(), 0);
    assert_eq!(v["event_count"], 0);
    assert_eq!(v["malformed_skipped"], 0);
}

#[tokio::test]
async fn replay_404s_for_unknown_or_cross_org_run_without_leaking() {
    let store = Arc::new(Store::new());
    let state = AppState::new(Arc::clone(&store), Arc::new(keys()), 0.8);

    // beta ingests run-beta-1; acme must not be able to replay it.
    let payload = r#"{"records":[{"ts_millis":1,"run_id":"run-beta-1","model":"claude","decision":"allow","cost_microusd":100,"step":1}]}"#;
    let (status, _) = send(
        &state,
        "POST",
        "/v1/ingest",
        Some("otherorg"),
        Some(payload),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, v) = send(&state, "GET", "/v1/replay/run-beta-1", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error"], "unknown run");

    // A run id nobody has ever ingested also 404s, identically.
    let (status, v) = send(&state, "GET", "/v1/replay/never-seen", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error"], "unknown run");
}
