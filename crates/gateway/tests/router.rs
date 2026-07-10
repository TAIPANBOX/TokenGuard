//! Integration test for the model router wired into `proxy::messages`.
//!
//! `crates/gateway/src/router.rs` has the exhaustive table-driven unit tests
//! for the routing algorithm itself. This file proves the HTTP wiring: the
//! outgoing body's `"model"` field is actually rewritten in `on` mode and
//! left alone in `shadow`, the real settle path (`estimate_cost`/pricing)
//! sees whichever model was actually chosen, the `x-fuse-router` header is
//! always present once the router is not Off, and the router never routes a
//! model up unless a rule explicitly requires it.

use async_trait::async_trait;
use axum::body::{to_bytes, Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use std::sync::{Arc, Mutex};
use tokenfuse_core::{Ledger, Mode, Policy, PriceBook};
use tokenfuse_gateway::pricebook::default_price_book;
use tokenfuse_gateway::provider::{Provider, ProviderError, ProviderResponse, UsageSlot};
use tokenfuse_gateway::router::{default_rules, Router, RouterMode};
use tokenfuse_gateway::sink::{CallRecord, EventSink};
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

/// A provider stub that records the exact body it was asked to forward
/// upstream (so the test can inspect whether the router actually rewrote the
/// `"model"` field) and reports a fixed token usage, mirroring
/// `tokenfuse_gateway::provider::StubProvider` but capturing its input.
#[derive(Clone, Default)]
struct CapturedBody(Arc<Mutex<Option<Bytes>>>);

struct CapturingProvider {
    captured: CapturedBody,
    input_tokens: u64,
    output_tokens: u64,
}

#[async_trait]
impl Provider for CapturingProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        *self.captured.0.lock().unwrap() = Some(body);
        let usage = tokenfuse_core::Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            ..Default::default()
        };
        let slot: UsageSlot = Arc::new(Mutex::new(Some(usage)));
        let chunk = Bytes::from_static(br#"{"stub":true}"#);
        let stream = futures::stream::once(async move { Ok(chunk) });
        Ok(ProviderResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: Box::pin(stream),
            usage: slot,
        })
    }
}

/// An in-memory `EventSink` test double, so tests can assert on the recorded
/// `saved_microusd`/`decision` without standing up Parquet.
#[derive(Clone, Default)]
struct RecordingSink {
    records: Arc<Mutex<Vec<CallRecord>>>,
}

impl RecordingSink {
    fn snapshot(&self) -> Vec<CallRecord> {
        self.records.lock().unwrap().clone()
    }
}

impl EventSink for RecordingSink {
    fn record(&self, rec: CallRecord) {
        self.records.lock().unwrap().push(rec);
    }
    fn flush(&self) {}
}

/// Stub usage: 1000 input / 500 output tokens, matching
/// `StubProvider`'s defaults elsewhere in this crate so the sample math below
/// stays easy to hand-check against `default_price_book()`'s published rates.
const INPUT_TOKENS: u64 = 1_000;
const OUTPUT_TOKENS: u64 = 500;

fn state(mode: RouterMode, captured: CapturedBody, sink: RecordingSink) -> AppState {
    let prices: PriceBook = default_price_book();
    let provider = CapturingProvider {
        captured,
        input_tokens: INPUT_TOKENS,
        output_tokens: OUTPUT_TOKENS,
    };
    let router = Router::new(mode, default_rules());
    AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy {
            mode: Mode::Enforce,
            ..Default::default()
        }),
        Arc::new(provider),
        "test-policy",
    )
    .with_router(Arc::new(router))
    .with_sink(Arc::new(sink))
}

fn request(body: &str, task_type: &str) -> Request<Body> {
    Request::post("/v1/messages")
        .header("x-fuse-run-id", "router-test-run")
        .header("x-fuse-budget-usd", "5.0")
        .header("x-fuse-task-type", task_type)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn body_with_model(model: &str) -> String {
    format!(
        r#"{{"model":"{model}","max_tokens":1000,"messages":[{{"role":"user","content":"hi"}}]}}"#
    )
}

async fn captured_model(captured: &CapturedBody) -> String {
    let bytes = captured
        .0
        .lock()
        .unwrap()
        .clone()
        .expect("provider was called");
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["model"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn on_mode_rewrites_the_forwarded_body_and_prices_the_chosen_model() {
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());
    let prices = default_price_book();

    let req = request(&body_with_model("claude-opus-4-5"), "cheap");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let router_hdr = resp
        .headers()
        .get("x-fuse-router")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(router_hdr, "claude-opus-4-5->claude-haiku-4-5");

    // The exact `x-fuse-cost-usd` figure only matches haiku's rate if the
    // real settle path priced the rewritten model, not the originally
    // requested one.
    let usage = tokenfuse_core::Usage {
        input_tokens: INPUT_TOKENS,
        output_tokens: OUTPUT_TOKENS,
        ..Default::default()
    };
    let expected_cost = prices.cost("claude-haiku-4-5", &usage).unwrap();
    let cost_hdr = resp
        .headers()
        .get("x-fuse-cost-usd")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(cost_hdr, format!("{:.6}", expected_cost.as_usd()));

    // The body actually sent upstream must carry the new model.
    assert_eq!(captured_model(&captured).await, "claude-haiku-4-5");

    // Savings settle onto the "allow" row, distinguishable from a cache hit
    // (which would use `decision == "cache_hit"` and never reaches here).
    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, "allow");
    assert_eq!(records[0].model, "claude-haiku-4-5");
    let expected_original_cost = prices.cost("claude-opus-4-5", &usage).unwrap();
    let expected_saved = expected_original_cost.saturating_sub(expected_cost);
    assert_eq!(records[0].saved_microusd, expected_saved.0);
    assert!(records[0].saved_microusd > 0);
}

#[tokio::test]
async fn shadow_mode_reports_without_rewriting_body_or_price() {
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::Shadow, captured.clone(), sink.clone());
    let prices = default_price_book();

    let req = request(&body_with_model("claude-opus-4-5"), "cheap");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Still reports what WOULD have happened.
    let router_hdr = resp
        .headers()
        .get("x-fuse-router")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    // Shadow observed the cheaper route but did not apply it: the header is
    // prefixed `would-` so it is never mistaken for an applied rewrite.
    assert_eq!(router_hdr, "would-claude-opus-4-5->claude-haiku-4-5");

    // But the forwarded body and the settled price are untouched.
    assert_eq!(captured_model(&captured).await, "claude-opus-4-5");
    let usage = tokenfuse_core::Usage {
        input_tokens: INPUT_TOKENS,
        output_tokens: OUTPUT_TOKENS,
        ..Default::default()
    };
    let expected_cost = prices.cost("claude-opus-4-5", &usage).unwrap();
    let cost_hdr = resp
        .headers()
        .get("x-fuse-cost-usd")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(cost_hdr, format!("{:.6}", expected_cost.as_usd()));

    // Shadow mode never applies the router, so there is nothing to fold into
    // saved_microusd even though the header advertises a would-route.
    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].saved_microusd, 0);
}

#[tokio::test]
async fn off_mode_adds_no_router_header_and_never_rewrites() {
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::Off, captured.clone(), sink.clone());

    let req = request(&body_with_model("claude-opus-4-5"), "cheap");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(resp.headers().get("x-fuse-router").is_none());
    assert_eq!(captured_model(&captured).await, "claude-opus-4-5");
}

#[tokio::test]
async fn never_routes_up_end_to_end_for_a_cheap_task() {
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());

    // Already the cheapest model for a "cheap" task: nothing to route to.
    let req = request(&body_with_model("claude-haiku-4-5"), "cheap");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let router_hdr = resp
        .headers()
        .get("x-fuse-router")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(router_hdr, "claude-haiku-4-5=kept");
    assert_eq!(captured_model(&captured).await, "claude-haiku-4-5");
}

#[tokio::test]
async fn explicit_higher_tier_requirement_routes_up_end_to_end() {
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());
    let prices = default_price_book();

    // haiku requested for a "hard" task: the class requires sonnet-or-above,
    // so the router pays more than what was asked for.
    let req = request(&body_with_model("claude-haiku-4-5"), "hard");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let router_hdr = resp
        .headers()
        .get("x-fuse-router")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(router_hdr, "claude-haiku-4-5->claude-sonnet-4-5");
    assert_eq!(captured_model(&captured).await, "claude-sonnet-4-5");

    let usage = tokenfuse_core::Usage {
        input_tokens: INPUT_TOKENS,
        output_tokens: OUTPUT_TOKENS,
        ..Default::default()
    };
    let expected_cost = prices.cost("claude-sonnet-4-5", &usage).unwrap();
    let cost_hdr = resp
        .headers()
        .get("x-fuse-cost-usd")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(cost_hdr, format!("{:.6}", expected_cost.as_usd()));

    // An upgrade is not a savings event: saturating_sub clamps the negative
    // delta to zero rather than reporting nonsense "negative savings".
    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].saved_microusd, 0);
}

#[tokio::test]
async fn absent_task_type_falls_back_to_the_default_class() {
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());

    // No `x-fuse-task-type` header at all (as opposed to an empty one).
    let req = Request::post("/v1/messages")
        .header("x-fuse-run-id", "router-test-run")
        .header("x-fuse-budget-usd", "5.0")
        .body(Body::from(body_with_model("claude-opus-4-5")))
        .unwrap();
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let router_hdr = resp
        .headers()
        .get("x-fuse-router")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(router_hdr, "claude-opus-4-5->claude-haiku-4-5");
}

#[tokio::test]
async fn unmanaged_passthrough_without_run_id_is_never_routed() {
    // No `x-fuse-run-id` header: the router must not engage at all, matching
    // DLP/cache/kill, which are all also gated on having a managed run.
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());

    let req = Request::post("/v1/messages")
        .body(Body::from(body_with_model("claude-opus-4-5")))
        .unwrap();
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse").unwrap(), "unmanaged");
    assert!(resp.headers().get("x-fuse-router").is_none());
    assert_eq!(captured_model(&captured).await, "claude-opus-4-5");
}

#[tokio::test]
async fn malformed_json_body_is_never_rewritten_and_stays_kept() {
    // A body the router can't safely parse/rewrite must fail safe: no
    // rewrite, no model/estimate mismatch, and the header reflects that
    // nothing actually changed rather than claiming a route that didn't
    // happen.
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());

    let req = request("not valid json", "cheap");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let router_hdr = resp
        .headers()
        .get("x-fuse-router")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(router_hdr, "unknown=kept");
    assert_eq!(
        captured.0.lock().unwrap().clone().unwrap(),
        Bytes::from_static(b"not valid json")
    );
}

#[tokio::test]
async fn streaming_request_carries_the_router_header_too() {
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());

    let body = r#"{"model":"claude-opus-4-5","max_tokens":1000,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let req = request(body, "cheap");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-stream").unwrap(), "passthrough");
    let router_hdr = resp
        .headers()
        .get("x-fuse-router")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(router_hdr, "claude-opus-4-5->claude-haiku-4-5");

    // Draining the body is what triggers the streaming settle path; the
    // CapturingProvider used here always responds non-streaming (a single
    // chunk), which is enough to prove the header reached the client.
    let _ = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(captured_model(&captured).await, "claude-haiku-4-5");
}

#[tokio::test]
async fn model_with_header_illegal_byte_drops_router_header_instead_of_panicking() {
    // `x-fuse-router`'s value embeds the client-supplied `model` field
    // verbatim (see `RouteDecision::header_value`). A model string
    // containing a byte illegal in an HTTP header value (here, a newline via
    // the JSON escape `\n`) must not panic the request's task when that
    // value reaches the response builder's `.expect("valid response")` in
    // `buffered_managed` -- it must simply drop the header and otherwise
    // serve a completely normal response.
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());

    let body = r#"{"model":"claude-opus-4-5\nX-Injected: evil","max_tokens":1000,"messages":[{"role":"user","content":"hi"}]}"#;
    let req = request(body, "cheap");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();

    // No panic: the request completes normally, with the fallback price
    // making the malformed original model expensive enough that the router
    // still finds a cheaper candidate and rewrites the body (the same
    // `->` path as `on_mode_rewrites_the_forwarded_body_and_prices_the_chosen_model`).
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse").unwrap(), "managed");

    // The router header is dropped rather than crashing the task -- the
    // illegal byte lived in the *original* model name embedded in the
    // `->` value, not in the rewritten one.
    assert!(resp.headers().get("x-fuse-router").is_none());

    // Everything else about the managed response is unaffected: the guard
    // only touches this one header.
    assert!(resp.headers().get("x-fuse-cost-usd").is_some());
    assert_eq!(captured_model(&captured).await, "claude-haiku-4-5");
}

#[tokio::test]
async fn streaming_model_with_header_illegal_byte_drops_router_header_instead_of_panicking() {
    // Same vector as `model_with_header_illegal_byte_drops_router_header_instead_of_panicking`,
    // but through `stream_managed`'s separate response-builder chain (the
    // streaming path builds headers before the body, in a different
    // function than the buffered path, and needed its own guarded call site).
    let captured = CapturedBody::default();
    let sink = RecordingSink::default();
    let st = state(RouterMode::On, captured.clone(), sink.clone());

    let body = r#"{"model":"claude-opus-4-5\nX-Injected: evil","max_tokens":1000,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let req = request(body, "cheap");
    let resp = tokenfuse_gateway::app(st).oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-fuse-stream").unwrap(), "passthrough");
    assert!(resp.headers().get("x-fuse-router").is_none());

    // Draining the body proves the streaming settle path also completes
    // without a panic.
    let _ = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(captured_model(&captured).await, "claude-haiku-4-5");
}
