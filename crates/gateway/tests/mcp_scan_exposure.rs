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

use tokenfuse_core::mcpexposure::{exposure_findings, CallAttempt};
use tokenfuse_core::mcpreport::Severity;
use tokenfuse_gateway::mcpcli::{run_live, OutputMode, ScanOptions};
use tokenfuse_gateway::mcpexposure_probe::run_exposure_probe;

/// Stub server config: whether it demands an `authorization` header (401s
/// without one), whether its `tools/list` response carries a wildcard CORS
/// header, a hit-counter for `tools/call` so tests can assert a call was (or
/// wasn't) attempted, and the name of the last tool actually invoked (so S3
/// tests can assert *which* tool got called, not just that one did).
#[derive(Clone, Default)]
struct StubConfig {
    require_auth: bool,
    cors_wildcard: bool,
    call_hits: Arc<Mutex<usize>>,
    called_tool: Arc<Mutex<Option<String>>>,
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
            let name = req
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .map(|s| s.to_string());
            *cfg.called_tool.lock().unwrap() = name;
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

    let outcome = run_exposure_probe(&url, false, None).await;
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

    let outcome = run_exposure_probe(&url, false, None).await;
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

    let outcome = run_exposure_probe(&url, false, None).await;
    assert!(outcome.cors_wildcard);

    let findings = exposure_findings(&outcome);
    let f = findings
        .iter()
        .find(|f| f.kind == "exposure_cors_wildcard")
        .expect("expected an exposure_cors_wildcard finding");
    assert_eq!(f.severity, Severity::Medium);
}

/// (d1 / S3) `--attempt-call` with NO `--call-tool <name>` given: the probe
/// must refuse to guess a target and skip the call entirely — the stub's
/// `tools/call` handler is never hit. This is the core S3 regression: there
/// is no more advertised-tool-list auto-selection to defeat, because there
/// is no auto-selection at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attempt_call_without_call_tool_is_skipped_and_makes_no_call() {
    let cfg = StubConfig::default();
    let call_hits = cfg.call_hits.clone();
    let url = spawn(cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let outcome = run_exposure_probe(&url, true, None).await;
    match &outcome.call_attempt {
        CallAttempt::Skipped { reason } => {
            assert!(
                reason.contains("--call-tool"),
                "skip reason should point the operator at --call-tool: {reason:?}"
            );
        }
        other => panic!("expected Skipped, got {other:?}"),
    }
    assert_eq!(
        *call_hits.lock().unwrap(),
        0,
        "no tools/call should ever reach the server without an explicit --call-tool"
    );

    let findings = exposure_findings(&outcome);
    assert!(findings.iter().all(|f| f.kind != "exposure_unauth_call"));
    assert!(findings
        .iter()
        .any(|f| f.kind == "exposure_unauth_call_skipped"));
}

/// (d2 / S3) `--attempt-call --call-tool weather`: exactly the named tool is
/// invoked, unauthenticated, and `exposure_unauth_call` fires Critical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attempt_call_with_named_tool_calls_exactly_that_tool() {
    let cfg = StubConfig::default();
    let call_hits = cfg.call_hits.clone();
    let called_tool = cfg.called_tool.clone();
    let url = spawn(cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let outcome = run_exposure_probe(&url, true, Some("weather")).await;
    assert_eq!(
        outcome.call_attempt,
        CallAttempt::Succeeded {
            tool: "weather".to_string()
        }
    );
    assert_eq!(
        *call_hits.lock().unwrap(),
        1,
        "the stub's tools/call must have been hit exactly once"
    );
    assert_eq!(
        called_tool.lock().unwrap().as_deref(),
        Some("weather"),
        "the operator-named tool, and only it, must be the one invoked"
    );

    let findings = exposure_findings(&outcome);
    let f = findings
        .iter()
        .find(|f| f.kind == "exposure_unauth_call")
        .expect("expected an exposure_unauth_call finding");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.tool.as_deref(), Some("weather"));
}

/// (S3) A server whose advertised `tools/list` describes a destructive tool
/// with an innocuous-sounding name/description (the exact adversarial shape
/// the old keyword-blocklist auto-picker was vulnerable to) can no longer get
/// it auto-invoked: `--attempt-call` without `--call-tool` skips regardless
/// of what the server advertises, because nothing is ever chosen from
/// server-supplied metadata anymore.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malicious_tool_description_cannot_get_itself_auto_invoked() {
    let cfg = StubConfig::default();
    let call_hits = cfg.call_hits.clone();
    let url = spawn(cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // The stub always advertises a "search" tool (see `stub()` above); what
    // matters here is that `run_exposure_probe` never looks at the tool list
    // at all when picking a call target — it only obeys `call_tool`.
    let outcome = run_exposure_probe(&url, true, None).await;
    assert!(matches!(outcome.call_attempt, CallAttempt::Skipped { .. }));
    assert_eq!(
        *call_hits.lock().unwrap(),
        0,
        "a server's advertised tools must never get auto-invoked, no matter \
         how their name/description reads"
    );
}

/// `attempt_call: false` (the default) never touches `tools/call`, even with
/// `call_tool` set — the flag gate is checked first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attempt_call_off_by_default_never_calls() {
    let cfg = StubConfig::default();
    let call_hits = cfg.call_hits.clone();
    let url = spawn(cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let outcome = run_exposure_probe(&url, false, Some("get_status")).await;
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
