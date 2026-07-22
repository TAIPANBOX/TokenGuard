//! HTTP-level tests for the regulator evidence pack (wave 2),
//! `GET /v1/compliance/evidence`, mirroring `tests/audit.rs` / `tests/reads.rs`:
//! the three framework sections are present, a control with a real backing
//! signal in this org's data reads `Enforced`, an unbacked one reads
//! `Documented`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
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
    keys
}

async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, Value) {
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
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Find the one entry in a framework section array whose `control` string
/// contains `needle` (e.g. a TokenFuse control id).
fn find<'a>(section: &'a Value, needle: &str) -> &'a Value {
    section
        .as_array()
        .unwrap_or_else(|| panic!("section is not an array: {section:?}"))
        .iter()
        .find(|c| c["control"].as_str().unwrap_or_default().contains(needle))
        .unwrap_or_else(|| panic!("no control containing {needle:?} in {section:?}"))
}

#[tokio::test]
async fn fresh_org_has_all_three_sections_with_unbacked_controls_documented() {
    let store = Arc::new(Store::new());
    let state = AppState::new(store, Arc::new(keys()), 0.8);

    let (status, v) = send(
        &state,
        "GET",
        "/v1/compliance/evidence",
        Some("devkey"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(v["org"], "acme");
    for section in ["eu_ai_act", "sr_11_7", "soc2"] {
        let arr = v[section]
            .as_array()
            .unwrap_or_else(|| panic!("{section} missing"));
        assert!(!arr.is_empty(), "{section} should not be empty");
        for c in arr {
            assert!(c["control"].is_string());
            assert!(c["evidence"].is_string());
            let status = c["status"].as_str().unwrap();
            assert!(
                ["Enforced", "Partial", "Documented"].contains(&status),
                "unexpected status {status} in {section}"
            );
        }
    }

    // Nothing has happened in this org yet: a control this cloud path can
    // never show evidence for (MCP scan findings aren't ingested here) must
    // be honestly `Documented`, never `Enforced`.
    assert_eq!(find(&v["soc2"], "TF.MCP.EXPOSURE")["status"], "Documented");
    // The kill-switch was never used either.
    assert_eq!(find(&v["eu_ai_act"], "TF.KILL")["status"], "Documented");
    // No mutations yet: the audit-chain entry reads Documented, not Enforced.
    assert_eq!(find(&v["eu_ai_act"], "TF.AUDIT")["status"], "Documented");
    assert_eq!(v["audit_chain_verified"], true);
    assert_eq!(v["audit_entries"], 0);

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn backed_controls_read_enforced_after_real_signals() {
    let store = Arc::new(Store::new());
    let state = AppState::new(store, Arc::new(keys()), 0.8);

    // Trip the budget breaker 3x on one run (the default incident threshold),
    // producing both `decision_counts["budget_exceeded"]` and a
    // `budget_exhausted` incident.
    let payload = r#"{"records":[
        {"ts_millis":1,"run_id":"run-1","model":"claude","decision":"budget_exceeded","cost_microusd":100,"step":1},
        {"ts_millis":2,"run_id":"run-1","model":"claude","decision":"budget_exceeded","cost_microusd":100,"step":2},
        {"ts_millis":3,"run_id":"run-1","model":"claude","decision":"budget_exceeded","cost_microusd":100,"step":3}
    ]}"#;
    let (status, _) = send(&state, "POST", "/v1/ingest", Some("devkey"), Some(payload)).await;
    assert_eq!(status, StatusCode::OK);

    // One authenticated mutation, so the audit chain has real entries.
    let (status, _) = send(&state, "POST", "/v1/runs/run-1/kill", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, v) = send(
        &state,
        "GET",
        "/v1/compliance/evidence",
        Some("devkey"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A real backing signal: the budget breaker actually fired.
    assert_eq!(find(&v["eu_ai_act"], "TF.BUDGET")["status"], "Enforced");
    assert_eq!(find(&v["soc2"], "TF.BUDGET")["status"], "Enforced");
    let sr_budget = find(&v["sr_11_7"], "Model Development, Implementation, and Use");
    assert_eq!(sr_budget["status"], "Enforced");
    assert!(sr_budget["evidence"]
        .as_str()
        .unwrap()
        .contains("budget_exceeded=3"));

    // The incident detector actually fired, so ongoing monitoring is Enforced.
    let sr_monitoring = find(&v["sr_11_7"], "Model Validation");
    assert_eq!(sr_monitoring["status"], "Enforced");

    // Still-unbacked controls remain Documented even with other org activity.
    assert_eq!(find(&v["eu_ai_act"], "TF.KILL")["status"], "Documented");
    assert_eq!(find(&v["soc2"], "TF.MCP.EXPOSURE")["status"], "Documented");

    // The audit chain now has a real, verifying entry: Enforced, not just
    // Partial/Documented.
    assert_eq!(find(&v["eu_ai_act"], "TF.AUDIT")["status"], "Enforced");
    assert_eq!(find(&v["soc2"], "TF.AUDIT")["status"], "Enforced");
    let sr_governance = find(&v["sr_11_7"], "Governance, Policies, and Controls");
    assert_eq!(sr_governance["status"], "Enforced");

    assert_eq!(v["audit_chain_verified"], true);
    assert_eq!(v["audit_entries"], 1);
    assert!(v["decisions_total"].as_u64().unwrap() >= 3);
    assert!(v["incidents_total"].as_u64().unwrap() >= 1);
}
