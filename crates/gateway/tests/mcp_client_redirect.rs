//! S2 regression: the live MCP scan client must never follow HTTP redirects.
//!
//! `crates/gateway/src/mcpclient.rs::build_client` used to hand reqwest a
//! `ClientBuilder` with no redirect policy at all, so reqwest's default (follow
//! up to 10 redirects, to ANY host) applied. A hostile server scanned via
//! `tokenfuse mcp-scan --url <endpoint>` could 302 the scanner onto an internal
//! address (`http://169.254.169.254/...`, an RFC1918 address, etc.) and read
//! back whatever the probe got from there — SSRF via redirect, from the CLI.
//!
//! This test spins up two hermetic stub servers: `redirect_origin` (the URL
//! the operator actually points the scanner at) answers every request with a
//! 3xx pointing at `other_host` (a stand-in for an internal/attacker-chosen
//! target). If the client follows the redirect, `other_host`'s hit counter
//! goes above zero; the fix must keep it at exactly zero.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use serde_json::json;

use tokenfuse_gateway::mcpclient::{fetch_tools_list_probe, McpClientConfig, McpClientError};

#[derive(Clone, Default)]
struct HitCounter(Arc<Mutex<usize>>);

async fn other_host_stub(State(hits): State<HitCounter>) -> Response {
    *hits.0.lock().unwrap() += 1;
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"jsonrpc":"2.0","id":1,"result":{"tools":[]}}).to_string(),
        ))
        .expect("valid response")
}

async fn spawn_other_host() -> (String, Arc<Mutex<usize>>) {
    let hits = HitCounter::default();
    let handle = hits.0.clone();
    let router = Router::new()
        .route("/", post(other_host_stub))
        .with_state(hits);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    (format!("http://{addr}"), handle)
}

async fn redirect_stub(State(location): State<Arc<String>>) -> Response {
    // Every request — regardless of which JSON-RPC method it carries — gets
    // redirected. A real attacker doesn't need to cooperate with the scan's
    // handshake; a 3xx on the very first request is enough to test whether
    // the client follows it.
    Response::builder()
        .status(302)
        .header("location", location.as_str())
        .body(Body::empty())
        .expect("valid response")
}

async fn spawn_redirect_origin(location: String) -> String {
    let router = Router::new()
        .route("/", post(redirect_stub))
        .with_state(Arc::new(location));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_does_not_follow_cross_host_redirect() {
    let (other_url, other_hits) = spawn_other_host().await;
    let redirect_url = spawn_redirect_origin(other_url.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let cfg = McpClientConfig::new(&redirect_url);
    let result = fetch_tools_list_probe(&cfg).await;

    match result {
        Ok(_) => panic!("a 3xx from the scanned server must not resolve to a successful probe"),
        Err(McpClientError::Status { status, .. }) => {
            assert_eq!(
                status, 302,
                "the 3xx must surface as-is (not silently followed/swallowed)"
            );
        }
        Err(other) => panic!("expected McpClientError::Status(302), got {other:?}"),
    }

    assert_eq!(
        *other_hits.lock().unwrap(),
        0,
        "the client must never have issued a request to the redirect target — \
         following it would be SSRF from the CLI scanner"
    );
}
