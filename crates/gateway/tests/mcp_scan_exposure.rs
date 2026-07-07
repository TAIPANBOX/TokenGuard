//! Integration tests for the `mcp-scan --url` exposure checks (PR4):
//! `mcpexposure_probe::run_exposure_probe` against a hermetic axum stub,
//! fed through `tokenfuse_core::mcpexposure::exposure_findings`. Mirrors the
//! stub pattern in `mcp_scan_live.rs`.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

use tokenfuse_core::mcp::McpTool;
use tokenfuse_core::mcpexposure::{exposure_findings, CallAttempt};
use tokenfuse_core::mcpreport::Severity;
use tokenfuse_gateway::mcpcli::{run_live, OutputMode, ScanOptions};
use tokenfuse_gateway::mcpexposure_probe::run_exposure_probe;

/// Stub server config: whether it demands an `authorization` header (401s
/// without one), whether its `tools/list` response carries a wildcard CORS
/// header, and a hit-counter for `tools/call` so tests can assert a call was
/// (or wasn't) attempted.
#[derive(Clone, Default)]
struct StubConfig {
    require_auth: bool,
    cors_wildcard: bool,
    call_hits: Arc<Mutex<usize>>,
}

fn json_response(v: Value) -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(v.to_string()))
        .expect("valid response")
}

fn json_response_with_cors(v: Value) -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(Body::from(v.to_string()))
        .expect("valid response")
}

fn unauthorized() -> Response {
    Response::builder()
        .status(401)
        .body(Body::from("unauthorized"))
        .expect("valid response")
}

async fn stub(
    State(cfg): State<StubConfig>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Response {
    if cfg.require_auth && !headers.contains_key("authorization") {
        return unauthorized();
    }

    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    match method {
        "initialize" => json_response(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": { "name": "exposure-stub", "version": "0.0.1" }
            }
        })),
        "notifications/initialized" => json_response(json!({})),
        "tools/list" => {
            let result = json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": [
                    { "name": "search", "description": "search the web", "inputSchema": { "type": "object" } }
                ]}
            });
            if cfg.cors_wildcard {
                json_response_with_cors(result)
            } else {
                json_response(result)
            }
        }
        "tools/call" => {
            *cfg.call_hits.lock().unwrap() += 1;
            json_response(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "content": [] }
            }))
        }
        _ => json_response(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
    }
}

async fn spawn(cfg: StubConfig) -> String {
    let router = Router::new().route("/", post(stub)).with_state(cfg);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

/// (a) A no-auth stub on a loopback address → the unauth finding is **Info**
/// (local dev server, expected), not High. Proves the no-false-positive-on-
/// localhost behavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauth_list_on_loopback_is_info_not_high() {
    let url = spawn(StubConfig::default()).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let outcome = run_exposure_probe(&url, &[], false).await;
    assert!(outcome.unauth_list_returned);
    assert_eq!(outcome.unauth_tool_count, 1);

    let findings = exposure_findings(&outcome);
    let f = findings
        .iter()
        .find(|f| f.kind == "exposure_unauth_list")
        .expect("expected an exposure_unauth_list finding");
    assert_eq!(
        f.severity,
        Severity::Info,
        "loopback unauth server must be Info, not High"
    );
}

/// (b) A stub that 401s every request without an `authorization` header
/// (which the exposure probe never sends) → the probe must not be able to
/// enumerate tools, so NO `exposure_unauth_list` finding fires. Critical
/// negative test: proves the probe doesn't manufacture a finding just
/// because *a* request happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_unauth_list_finding_when_server_requires_auth() {
    let url = spawn(StubConfig {
        require_auth: true,
        ..Default::default()
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let outcome = run_exposure_probe(&url, &[], false).await;
    assert!(!outcome.unauth_list_returned);
    assert_eq!(outcome.unauth_tool_count, 0);

    let findings = exposure_findings(&outcome);
    assert!(
        findings.iter().all(|f| f.kind != "exposure_unauth_list"),
        "a 401'd probe must not produce an unauth_list finding: {findings:?}"
    );
}

/// (c) A stub whose `tools/list` response carries
/// `Access-Control-Allow-Origin: *` → the CORS finding fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cors_wildcard_response_header_flags_finding() {
    let url = spawn(StubConfig {
        cors_wildcard: true,
        ..Default::default()
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let outcome = run_exposure_probe(&url, &[], false).await;
    assert!(outcome.cors_wildcard);

    let findings = exposure_findings(&outcome);
    let f = findings
        .iter()
        .find(|f| f.kind == "exposure_cors_wildcard")
        .expect("expected an exposure_cors_wildcard finding");
    assert_eq!(f.severity, Severity::Medium);
}

/// (d1) `--attempt-call` (i.e. `attempt_call: true`) against a stub, with a
/// `get_*` tool advertised: the probe calls it unauthenticated, the stub
/// returns a non-error result, and `exposure_unauth_call` fires Critical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attempt_call_against_get_tool_succeeds_and_flags_critical() {
    let cfg = StubConfig::default();
    let call_hits = cfg.call_hits.clone();
    let url = spawn(cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let tools = vec![McpTool {
        name: "get_status".to_string(),
        description: "Get the current server status".to_string(),
        fingerprint: 0,
    }];

    let outcome = run_exposure_probe(&url, &tools, true).await;
    assert_eq!(
        outcome.call_attempt,
        CallAttempt::Succeeded {
            tool: "get_status".to_string()
        }
    );
    assert_eq!(
        *call_hits.lock().unwrap(),
        1,
        "the stub's tools/call must have been hit exactly once"
    );

    let findings = exposure_findings(&outcome);
    let f = findings
        .iter()
        .find(|f| f.kind == "exposure_unauth_call")
        .expect("expected an exposure_unauth_call finding");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.tool.as_deref(), Some("get_status"));
}

/// (d2) `--attempt-call` against a stub advertising only a `delete_*` tool:
/// no safe target exists, so the probe must skip the call entirely — the
/// stub's `tools/call` handler is never hit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attempt_call_skips_when_only_mutation_tool_is_advertised() {
    let cfg = StubConfig::default();
    let call_hits = cfg.call_hits.clone();
    let url = spawn(cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let tools = vec![McpTool {
        name: "delete_project".to_string(),
        description: "Deletes a project permanently".to_string(),
        fingerprint: 0,
    }];

    let outcome = run_exposure_probe(&url, &tools, true).await;
    match &outcome.call_attempt {
        CallAttempt::Skipped { .. } => {}
        other => panic!("expected Skipped, got {other:?}"),
    }
    assert_eq!(
        *call_hits.lock().unwrap(),
        0,
        "no tools/call should ever reach the server when nothing looks safe"
    );

    let findings = exposure_findings(&outcome);
    assert!(findings.iter().all(|f| f.kind != "exposure_unauth_call"));
    assert!(findings
        .iter()
        .any(|f| f.kind == "exposure_unauth_call_skipped"));
}

/// `attempt_call: false` (the default) never touches `tools/call`, even with
/// a perfectly safe tool advertised.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attempt_call_off_by_default_never_calls() {
    let cfg = StubConfig::default();
    let call_hits = cfg.call_hits.clone();
    let url = spawn(cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let tools = vec![McpTool {
        name: "get_status".to_string(),
        description: "Get the current server status".to_string(),
        fingerprint: 0,
    }];

    let outcome = run_exposure_probe(&url, &tools, false).await;
    assert_eq!(outcome.call_attempt, CallAttempt::NotRequested);
    assert_eq!(*call_hits.lock().unwrap(), 0);
}

/// End-to-end wiring: `mcpcli::run_live` (the full CLI path, not just the
/// probe) merges exposure findings into the same `ScanReport` as the
/// poisoning scan, and `--skip-exposure` (`skip_exposure: true`) omits them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_live_merges_exposure_findings_and_respects_skip_flag() {
    let url = spawn(StubConfig::default()).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let with_exposure = run_live(
        &url,
        &ScanOptions {
            mode: OutputMode::Human,
            ..Default::default()
        },
    )
    .await
    .expect("run_live failed");
    assert!(
        with_exposure
            .findings
            .iter()
            .any(|f| f.kind == "exposure_unauth_list"),
        "run_live should merge exposure findings by default: {:?}",
        with_exposure.findings
    );

    let without_exposure = run_live(
        &url,
        &ScanOptions {
            mode: OutputMode::Human,
            skip_exposure: true,
            ..Default::default()
        },
    )
    .await
    .expect("run_live failed");
    assert!(
        without_exposure
            .findings
            .iter()
            .all(|f| !f.kind.starts_with("exposure_")),
        "--skip-exposure must omit exposure_* findings: {:?}",
        without_exposure.findings
    );
}
