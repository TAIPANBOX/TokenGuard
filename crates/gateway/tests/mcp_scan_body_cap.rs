//! Integration test for the MCP scan client's response-body size cap (the DoS
//! guard): a body larger than `McpClientConfig::max_body_bytes` must abort with
//! `McpClientError::BodyTooLarge` instead of buffering unboundedly, while a
//! normal small body still fetches unchanged.

use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokenfuse_gateway::mcpclient::{fetch_tools_list, McpClientConfig, McpClientError};

/// How big a `description` string the stub pads the `tools/list` response with.
#[derive(Clone)]
struct StubState {
    pad_bytes: usize,
}

fn json_response(v: Value) -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(v.to_string()))
        .expect("valid response")
}

async fn stub(State(st): State<StubState>, Json(req): Json<Value>) -> Response {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    match method {
        "initialize" => json_response(json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "protocolVersion": "2025-06-18", "capabilities": {},
                        "serverInfo": { "name": "stub", "version": "0.0.1" } }
        })),
        "notifications/initialized" => json_response(json!({})),
        "tools/list" => {
            // Pad the description so the whole response body's size is driven by
            // `pad_bytes`.
            let desc = "x".repeat(st.pad_bytes);
            json_response(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": [
                    { "name": "search", "description": desc, "inputSchema": { "type": "object" } }
                ]}
            }))
        }
        _ => json_response(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
    }
}

async fn spawn(pad_bytes: usize) -> String {
    let router = Router::new()
        .route("/", post(stub))
        .with_state(StubState { pad_bytes });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

fn cfg(url: String, max_body_bytes: usize) -> McpClientConfig {
    McpClientConfig {
        url,
        connect_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(15),
        extra_headers: Vec::new(),
        max_body_bytes,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_body_aborts_with_body_too_large() {
    // A ~64 KiB `tools/list` body against a 4 KiB cap must fail with
    // BodyTooLarge rather than buffering the whole thing (an OOM in the limit).
    let url = spawn(64 * 1024).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let err = fetch_tools_list(&cfg(url, 4 * 1024))
        .await
        .expect_err("oversized body must be rejected");
    assert!(
        matches!(err, McpClientError::BodyTooLarge { limit } if limit == 4 * 1024),
        "expected BodyTooLarge, got: {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn normal_small_body_fetches_unchanged() {
    // A tiny body well under the same cap fetches normally.
    let url = spawn(16).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let value = fetch_tools_list(&cfg(url, 4 * 1024))
        .await
        .expect("small body must fetch fine");
    let tools = tokenfuse_core::mcp::parse_tools(&value);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "search");
}
