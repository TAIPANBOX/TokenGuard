//! Integration test for the Wardryx enforcement hook (a PEP) wired into
//! `proxy::messages`.
//!
//! `crates/gateway/src/wardryx.rs` has unit tests for the decision cache and
//! the fail-open/closed fallback in isolation. This file proves the HTTP
//! wiring end to end: a tiny stub Wardryx server stands in for the PDP, and
//! a real (offline) gateway request is driven through `tokenfuse_gateway::app`
//! against the in-process `StubProvider` upstream, mirroring the pattern
//! `tests/router.rs` and `tests/mcp_broker.rs` already use.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokenfuse_core::{Ledger, Mode, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tokenfuse_gateway::wardryx::{FailMode, Wardryx, WardryxMode};
use tower::ServiceExt;

/// A stub Wardryx PDP: always answers with whatever `response` it was
/// configured with, and records every request body and call count so tests
/// can assert on what the gateway actually sent (and how often).
#[derive(Clone)]
struct WardryxStub {
    response: Arc<Mutex<Value>>,
    last_request: Arc<Mutex<Option<Value>>>,
    calls: Arc<AtomicUsize>,
}

impl WardryxStub {
    fn new(response: Value) -> Self {
        WardryxStub {
            response: Arc::new(Mutex::new(response)),
            last_request: Arc::new(Mutex::new(None)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

async fn decide(State(stub): State<WardryxStub>, Json(body): Json<Value>) -> Json<Value> {
    stub.calls.fetch_add(1, Ordering::SeqCst);
    *stub.last_request.lock().unwrap() = Some(body);
    Json(stub.response.lock().unwrap().clone())
}

fn wardryx_router(stub: WardryxStub) -> Router {
    Router::new()
        .route("/v1/decide", post(decide))
        .with_state(stub)
}

async fn spawn_server(router: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

/// `AppState` wired to an offline (in-process) `StubProvider` upstream, so
/// the "allow" path never makes a real network call either, and the given
/// `Wardryx` hook.
fn state(wardryx: Wardryx) -> AppState {
    let prices = PriceBook::new().with(
        "test-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    );
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(StubProvider::default()),
        "wardryx-test-policy",
    )
    .with_wardryx(Arc::new(wardryx))
}

fn body() -> String {
    r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}"#
        .to_string()
}

fn request_with_headers(body: &str, extra: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::post("/v1/messages")
        .header("x-fuse-run-id", "wardryx-test-run")
        .header("x-fuse-budget-usd", "5.0");
    for (k, v) in extra {
        builder = builder.header(*k, *v);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn request(body: &str) -> Request<Body> {
    request_with_headers(body, &[])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforce_blocks_on_deny() {
    let stub = WardryxStub::new(json!({
        "decision": "deny",
        "reason": "policy says no",
        "policy_version": "v1"
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "deny");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforce_hold_returns_403_with_approval_id() {
    let stub = WardryxStub::new(json!({
        "decision": "hold",
        "approval_id": "appr-42",
        "reason": "needs a human"
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "hold");
    assert_eq!(resp.headers().get("x-fuse-approval-id").unwrap(), "appr-42");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_mode_never_blocks() {
    // The PDP says deny, but shadow mode must never act on it.
    let stub = WardryxStub::new(json!({ "decision": "deny", "reason": "would deny" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Shadow,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "would-deny");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_mode_makes_no_decide_call() {
    let stub = WardryxStub::new(json!({ "decision": "deny" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A real, reachable URL is configured, so a stray call would succeed
    // (and be counted) if the `Off` gate in `proxy::messages` were broken.
    let wardryx = Wardryx::new(
        WardryxMode::Off,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-fuse-wardryx").is_none());
    assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failmode_open_allows_when_pdp_unreachable() {
    // Nothing listens on this address: connections fail fast (refused), no
    // real server needed to prove the fail-open fallback.
    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        "http://127.0.0.1:1",
        None,
        Duration::from_millis(300),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "allow");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failmode_closed_denies_when_pdp_unreachable() {
    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Closed,
        "http://127.0.0.1:1",
        None,
        Duration::from_millis(300),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "deny");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_token_header_is_forwarded_to_decide_call() {
    let stub = WardryxStub::new(json!({ "decision": "allow" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));
    let req = request_with_headers(&body(), &[("x-fuse-approval-token", "tok-abc123")]);

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "allow");

    let sent = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("the decide endpoint was called");
    assert_eq!(sent["approval_token"], json!("tok-abc123"));
}

/// A request whose `tools` array declares one URL-bearing tool, so
/// `referenced_domains` has something to extract.
fn body_with_tool_url() -> String {
    r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"hi"}],
        "tools":[{"name":"fetch","description":"fetch a resource","server_url":"https://api.acme.example/v1/data"}]}"#
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn steps_and_domains_are_sent_to_decide_call() {
    let stub = WardryxStub::new(json!({ "decision": "allow" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        // Zero TTL: both calls below share the same (agent_id, tool_names)
        // cache key, and a real cache hit on the second call would serve
        // the cached decision without ever reaching the stub again -- which
        // would hide the very thing this test exists to prove (that the
        // second call's "steps" reflects the first call's completed
        // reservation). Keep caching out of the way entirely.
        Duration::from_millis(0),
    );
    let app = tokenfuse_gateway::app(state(wardryx));
    let tool_body = body_with_tool_url();

    // First call on a fresh run: no prior action has been reserved yet, so
    // the run's accumulated step count is zero.
    let resp1 = app.clone().oneshot(request(&tool_body)).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let sent1 = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("first decide call was made");
    assert_eq!(sent1["steps"], json!(0));
    assert_eq!(sent1["domains"], json!(["api.acme.example"]));

    // Second call, same run: the first call's reserve() already bumped the
    // ledger's step count by one, so this call's "steps" must reflect it.
    let resp2 = app.oneshot(request(&tool_body)).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let sent2 = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("second decide call was made");
    assert_eq!(sent2["steps"], json!(1));
    assert_eq!(sent2["domains"], json!(["api.acme.example"]));

    assert_eq!(stub.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_from_a_step_or_domain_rule_still_maps_to_403() {
    // Wardryx's own max_steps/allow_domains rules are exercised by the
    // wardryx repo's decision-table test; this only proves the gateway's
    // enforcement mapping doesn't need to know or care *why* Wardryx
    // denied. A deny is a deny -- whether it came from a step-budget rule,
    // a domain rule, deny_tool, or anything else -- and it maps to the same
    // 403 path `enforce_blocks_on_deny` already covers generically. This
    // uses a step/domain-flavored `reason` to make that connection explicit
    // for this feature, and doubles as one more check that the request this
    // hook actually sends carries the "steps"/"domains" a real PDP would
    // have decided against.
    let stub = WardryxStub::new(json!({
        "decision": "deny",
        "reason": "policy \"finance-guardrail\" step budget exhausted: 5 >= max_steps 5",
        "policy_version": "v1"
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let resp = app.oneshot(request(&body_with_tool_url())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "deny");

    let sent = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("the decide endpoint was called");
    assert_eq!(sent["domains"], json!(["api.acme.example"]));
    assert_eq!(sent["steps"], json!(0));
}

/// Proves the actual bug this feature closes: a decision cache keyed only
/// on `(agent_id, tool_set_hash)` used to reuse a cached `allow` across
/// calls whose `steps`/`domains`/`est_cost_usd` had since changed the
/// answer Wardryx would give. `cacheable: false` on the wire is how Wardryx
/// now tells the gateway a decision depends on exactly that kind of
/// per-request state -- so it must reach the PDP on every call, never
/// served from cache, even well inside the TTL and even for the identical
/// (agent_id, tool_names) pair every call below uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cacheable_false_is_never_reused_from_cache() {
    let stub = WardryxStub::new(json!({
        "decision": "allow",
        "policy_version": "v1",
        "cacheable": false
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        // Generous TTL: every call below falls inside the same window, so
        // a wrongly-cached decision would be served instead of reaching
        // the stub -- exactly the bug this test exists to catch.
        Duration::from_secs(30),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    const REQUESTS: usize = 3;
    for _ in 0..REQUESTS {
        let resp = app.clone().oneshot(request(&body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "allow");
    }

    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        REQUESTS,
        "cacheable: false must reach Wardryx on every request; the decision cache must never reuse it"
    );
}

/// The mirror image of `cacheable_false_is_never_reused_from_cache`: when
/// Wardryx marks a decision `cacheable: true` (no matched policy is
/// request-specific), the gateway's existing repeat-call cache still
/// applies -- only the first call within the TTL reaches the stub, the
/// rest are served from cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cacheable_true_is_served_from_cache_within_ttl() {
    let stub = WardryxStub::new(json!({
        "decision": "allow",
        "policy_version": "v1",
        "cacheable": true
    }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(30),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    const REQUESTS: usize = 3;
    for _ in 0..REQUESTS {
        let resp = app.clone().oneshot(request(&body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-fuse-wardryx").unwrap(), "allow");
    }

    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        1,
        "cacheable: true should be cached after the first call: only one upstream hit for {REQUESTS} requests"
    );
}

/// Regression: a request that only DECLARES a tool (Anthropic `tools[]`, no
/// `tool_use` block yet) must still surface that tool name to the PDP, so a
/// `deny_tool` policy fires before the model is ever given the chance to invoke
/// it. Previously the PEP consulted only *invoked* tools, so `tool_names` here
/// was empty and a first-turn `deny_tool` could be bypassed by declaring the
/// forbidden tool without calling it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn declared_tool_is_forwarded_to_pdp() {
    let stub = WardryxStub::new(json!({ "decision": "allow" }));
    let url = spawn_server(wardryx_router(stub.clone())).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let wardryx = Wardryx::new(
        WardryxMode::Enforce,
        FailMode::Open,
        url,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    );
    let app = tokenfuse_gateway::app(state(wardryx));

    let body = r#"{"model":"test-model","max_tokens":100,"messages":[{"role":"user","content":"refund by wire"}],"tools":[{"name":"wire_transfer","description":"move money","input_schema":{"type":"object"}}]}"#;
    let resp = app.oneshot(request(body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK); // the stub allows; we assert on what was sent

    let sent = stub
        .last_request
        .lock()
        .unwrap()
        .clone()
        .expect("PDP received a decide request");
    let tools = sent
        .get("tool_names")
        .and_then(|t| t.as_array())
        .expect("decide request carries tool_names");
    assert!(
        tools.iter().any(|t| t.as_str() == Some("wire_transfer")),
        "a declared-but-not-invoked tool must be forwarded to the PDP, got {tools:?}"
    );
}
