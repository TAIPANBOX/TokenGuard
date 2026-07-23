//! The upstream LLM provider abstraction and its real HTTP implementation.
//!
//! A provider forwards a request and returns a **streaming** body plus a slot
//! that is filled with the token [`Usage`] once the stream is fully consumed.
//! Streaming is essential: the gateway passes bytes through to the caller as
//! they arrive (SSE passthrough) and only settles the real cost at end-of-stream
//! (Phase 0 spike #1). Usage is parsed out of the same bytes as they flow by.

use async_trait::async_trait;
use axum::http::HeaderMap;
use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use std::sync::{Arc, Mutex};
use tokenfuse_core::Usage;

/// Shared slot filled with the final usage once a provider stream ends.
pub type UsageSlot = Arc<Mutex<Option<Usage>>>;

/// A streaming response from the upstream.
pub struct ProviderResponse {
    pub status: u16,
    pub content_type: Option<String>,
    /// Body chunks to pass through to the caller.
    pub body: BoxStream<'static, Result<Bytes, ProviderError>>,
    /// Filled with the parsed usage once `body` is fully consumed.
    pub usage: UsageSlot,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("upstream request failed: {0}")]
    Upstream(String),
}

/// An upstream that can forward a request. Implemented by the real HTTP client
/// and by test stubs.
#[async_trait]
pub trait Provider: Send + Sync {
    async fn send(
        &self,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<ProviderResponse, ProviderError>;
}

// ---------------------------------------------------------------------------
// Usage parsing (provider-format-aware, but unified)
// ---------------------------------------------------------------------------

/// Extracts token usage from a response body, whether SSE (streaming) or a
/// single JSON object (non-streaming). It recognizes both Anthropic
/// (`message_start` / `message_delta`) and OpenAI (`usage` with
/// `prompt_tokens`) shapes.
///
/// Current implementation buffers the body up to a cap and parses at the end.
/// TODO: make SSE parsing fully incremental to avoid holding a copy of large
/// streamed responses (tracked in PROGRESS.md).
#[derive(Default)]
pub struct UsageParser {
    buf: Vec<u8>,
}

impl UsageParser {
    /// Upper bound on buffered bytes; beyond this we stop accumulating and may
    /// fall back to the pre-flight estimate at settle time.
    const CAP: usize = 8 * 1024 * 1024;

    pub fn new() -> Self {
        UsageParser::default()
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        if self.buf.len() >= Self::CAP {
            return;
        }
        let take = (Self::CAP - self.buf.len()).min(chunk.len());
        self.buf.extend_from_slice(&chunk[..take]);
    }

    pub fn finish(&self) -> Usage {
        let text = String::from_utf8_lossy(&self.buf);
        let mut usage = Usage::default();
        let mut saw_sse = false;
        let mut tool_calls = ToolCallCounter::default();

        for line in text.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("data:") {
                saw_sse = true;
                let rest = rest.trim();
                if rest.is_empty() || rest == "[DONE]" {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(rest) {
                    merge_usage(&mut usage, &v);
                    tool_calls.observe_streaming(&v);
                }
            }
        }

        // Non-streaming response: the whole body is one JSON object.
        if !saw_sse {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) {
                merge_usage(&mut usage, &v);
                tool_calls.observe_non_streaming(&v);
            }
        }

        usage.tool_calls = tool_calls.finish();
        usage
    }
}

/// Accumulates the model-emitted tool-call count across a response body (I1,
/// docs/21-tool-runs.md), for both Anthropic and OpenAI shapes, streaming or
/// not - the same "inspect the JSON shape, not the endpoint" approach
/// [`merge_usage`] already uses, since this gateway is provider-agnostic.
///
/// `finish()` returns `None` only when nothing in the body ever parsed as
/// JSON at all; any response we could actually look into resolves to at
/// least `Some(0)` - "no tool calls" is a real observation, never a guess.
#[derive(Default)]
struct ToolCallCounter {
    /// At least one JSON value from the body was successfully parsed.
    seen: bool,
    /// Anthropic: `content_block_start` events announcing a `tool_use` block
    /// (streaming), or `content[]` blocks of type `tool_use` (non-streaming) -
    /// counted the same way, since each occurrence is one tool call either way.
    anthropic: u32,
    /// OpenAI non-streaming: `choices[].message.tool_calls` length, summed
    /// across choices (a request can ask for more than one).
    openai_nonstream: u32,
    /// OpenAI streaming: distinct `(choice_index, tool_call_index)` pairs
    /// seen across `choices[].delta.tool_calls[]`. Deltas repeat per
    /// tool_call index as a call's arguments stream in, so only the count of
    /// *unique* indexes is the number of tool calls - counting deltas
    /// directly would overcount. The pairing with `choice_index` matters
    /// because `n > 1` (multiple choices) is legal on this endpoint: each
    /// choice's own `tool_calls[].index` restarts from 0 independently, so
    /// two different choices both streaming a tool call at index 0 are two
    /// distinct tool calls, not one - a bare `HashSet<u64>` keyed on the
    /// tool_call index alone would collapse them into one and undercount.
    /// The choice's own `"index"` defaults to 0 when the key is absent
    /// (which is every request that didn't ask for `n > 1`), so the common
    /// single-choice case is unaffected.
    openai_stream_idx: std::collections::HashSet<(u64, u64)>,
}

impl ToolCallCounter {
    /// Anthropic's `content_block_start` events don't have a fixed shape
    /// contract, we look for the two keys we need and ignore everything else.
    fn observe_streaming(&mut self, v: &serde_json::Value) {
        self.seen = true;
        if v.get("type").and_then(|t| t.as_str()) == Some("content_block_start") {
            let is_tool_use = v
                .get("content_block")
                .and_then(|b| b.get("type"))
                .and_then(|t| t.as_str())
                == Some("tool_use");
            if is_tool_use {
                self.anthropic += 1;
            }
        }
        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                // Absent (no `n>1` requested) defaults to 0, the same
                // implicit single-choice index every OpenAI response without
                // `n` carries.
                let choice_idx = choice.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                let Some(deltas) = choice
                    .get("delta")
                    .and_then(|d| d.get("tool_calls"))
                    .and_then(|t| t.as_array())
                else {
                    continue;
                };
                for tc in deltas {
                    if let Some(idx) = tc.get("index").and_then(|i| i.as_u64()) {
                        self.openai_stream_idx.insert((choice_idx, idx));
                    }
                }
            }
        }
    }

    fn observe_non_streaming(&mut self, v: &serde_json::Value) {
        self.seen = true;
        if let Some(content) = v.get("content").and_then(|c| c.as_array()) {
            self.anthropic += content
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                .count() as u32;
        }
        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                if let Some(tc) = choice
                    .get("message")
                    .and_then(|m| m.get("tool_calls"))
                    .and_then(|t| t.as_array())
                {
                    self.openai_nonstream += tc.len() as u32;
                }
            }
        }
    }

    fn finish(self) -> Option<u32> {
        if !self.seen {
            return None;
        }
        Some(self.anthropic + self.openai_nonstream + self.openai_stream_idx.len() as u32)
    }
}

fn merge_usage(usage: &mut Usage, v: &serde_json::Value) {
    // Anthropic message_start: { "message": { "usage": { ... } } }
    if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
        apply_anthropic(usage, u);
    }
    // Anthropic message_delta / non-stream, or OpenAI: top-level "usage".
    if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
        if u.get("prompt_tokens").is_some() || u.get("completion_tokens").is_some() {
            apply_openai(usage, u);
        } else {
            apply_anthropic(usage, u);
        }
    }
}

/// Last-non-zero-wins: streamed events arrive oldest-first, and the final
/// `message_delta` carries the cumulative output-token total.
fn set_if_positive(field: &mut u64, v: &serde_json::Value, key: &str) {
    if let Some(n) = v.get(key).and_then(|x| x.as_u64()) {
        if n > 0 {
            *field = n;
        }
    }
}

fn apply_anthropic(usage: &mut Usage, u: &serde_json::Value) {
    set_if_positive(&mut usage.input_tokens, u, "input_tokens");
    set_if_positive(&mut usage.output_tokens, u, "output_tokens");
    set_if_positive(&mut usage.cache_read_tokens, u, "cache_read_input_tokens");
    set_if_positive(
        &mut usage.cache_write_tokens,
        u,
        "cache_creation_input_tokens",
    );
}

fn apply_openai(usage: &mut Usage, u: &serde_json::Value) {
    set_if_positive(&mut usage.input_tokens, u, "prompt_tokens");
    set_if_positive(&mut usage.output_tokens, u, "completion_tokens");
    if let Some(cached) = u
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|x| x.as_u64())
    {
        if cached > 0 {
            usage.cache_read_tokens = cached;
        }
    }
}

// ---------------------------------------------------------------------------
// Real HTTP provider
// ---------------------------------------------------------------------------

/// Headers we forward upstream. The provider API key is passed through and
/// never stored or logged (privacy by design) — either as `Authorization`
/// (OpenAI-style bearer auth) or as `x-api-key` (Anthropic's native auth
/// header; without it Anthropic rejects the request with 401 "x-api-key
/// header is required" even though `anthropic-version` made it through).
const FORWARD_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "anthropic-version",
    "anthropic-beta",
    "openai-organization",
    "openai-beta",
    "content-type",
    "accept",
];

/// Forwards requests to a real upstream endpoint and streams the response back,
/// parsing usage out of the bytes as they flow.
pub struct HttpProvider {
    client: reqwest::Client,
    endpoint: String,
}

impl HttpProvider {
    pub fn new(endpoint: impl Into<String>) -> Self {
        // A connect timeout bounds how long a stalled upstream can tie up a
        // request during the TCP+TLS handshake. We deliberately set *no* overall
        // request timeout: responses stream (SSE) and may legitimately stay open
        // for minutes, so a whole-request deadline would cut long generations.
        let connect_secs = std::env::var("TOKENFUSE_UPSTREAM_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(connect_secs))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        HttpProvider {
            client,
            endpoint: endpoint.into(),
        }
    }
}

#[async_trait]
impl Provider for HttpProvider {
    async fn send(
        &self,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        let mut req = self.client.post(&self.endpoint).body(body.to_vec());
        for name in FORWARD_HEADERS {
            if let Some(v) = headers.get(*name) {
                req = req.header(*name, v);
            }
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ProviderError::Upstream(e.to_string()))?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let usage: UsageSlot = Arc::new(Mutex::new(None));
        let usage_writer = Arc::clone(&usage);
        let upstream = resp.bytes_stream();

        // Pass each chunk through unchanged while tapping it for usage. On end
        // of stream, publish the parsed usage into the shared slot.
        let body = async_stream::try_stream! {
            let mut parser = UsageParser::new();
            futures::pin_mut!(upstream);
            while let Some(chunk) = upstream.next().await {
                let chunk = chunk.map_err(|e| ProviderError::Upstream(e.to_string()))?;
                parser.feed(&chunk);
                yield chunk;
            }
            *usage_writer.lock().unwrap() = Some(parser.finish());
        };

        Ok(ProviderResponse {
            status,
            content_type,
            body: Box::pin(body),
            usage,
        })
    }
}

// ---------------------------------------------------------------------------
// Deterministic stub (offline dev + tests)
// ---------------------------------------------------------------------------

/// A deterministic stand-in used for offline runs and tests. Emits a small JSON
/// body and reports fixed usage.
#[derive(Debug, Clone)]
pub struct StubProvider {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// When true, emit the body as a couple of SSE `data:` frames to exercise
    /// the streaming passthrough path.
    pub sse: bool,
    /// Override the non-streaming JSON body (e.g. to inject a tool_use for
    /// firewall tests). Ignored in SSE mode.
    pub body_override: Option<String>,
}

impl Default for StubProvider {
    fn default() -> Self {
        StubProvider {
            input_tokens: 1_000,
            output_tokens: 500,
            sse: false,
            body_override: None,
        }
    }
}

#[async_trait]
impl Provider for StubProvider {
    async fn send(
        &self,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> Result<ProviderResponse, ProviderError> {
        let usage = Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            ..Default::default()
        };

        let (content_type, chunks): (Option<String>, Vec<Bytes>) = if self.sse {
            (
                Some("text/event-stream".to_string()),
                vec![
                    Bytes::from(format!(
                        "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"usage\":{{\"input_tokens\":{}}}}}}}\n\n",
                        self.input_tokens
                    )),
                    Bytes::from(format!(
                        "event: message_delta\ndata: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":{}}}}}\n\n",
                        self.output_tokens
                    )),
                    Bytes::from_static(b"data: [DONE]\n\n"),
                ],
            )
        } else {
            let body = self.body_override.clone().unwrap_or_else(|| {
                format!(
                    r#"{{"stub":true,"usage":{{"input_tokens":{},"output_tokens":{}}}}}"#,
                    self.input_tokens, self.output_tokens
                )
            });
            (
                Some("application/json".to_string()),
                vec![Bytes::from(body)],
            )
        };

        let slot: UsageSlot = Arc::new(Mutex::new(None));
        let writer = Arc::clone(&slot);
        let body = async_stream::try_stream! {
            let mut parser = UsageParser::new();
            for chunk in chunks {
                parser.feed(&chunk);
                yield chunk;
            }
            // Prefer the declared usage; fall back to what the parser saw.
            let parsed = parser.finish();
            *writer.lock().unwrap() = Some(if parsed == Usage::default() { usage } else { parsed });
        };

        Ok(ProviderResponse {
            status: 200,
            content_type,
            body: Box::pin(body),
            usage: slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_anthropic_sse_usage() {
        let mut p = UsageParser::new();
        p.feed(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1200,\"cache_read_input_tokens\":300}}}\n\n");
        p.feed(b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":8}}\n\n");
        p.feed(b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":842}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish();
        assert_eq!(u.input_tokens, 1200);
        assert_eq!(u.cache_read_tokens, 300);
        // Final cumulative delta wins.
        assert_eq!(u.output_tokens, 842);
    }

    #[test]
    fn parses_openai_sse_usage() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n");
        p.feed(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":950,\"completion_tokens\":120,\"prompt_tokens_details\":{\"cached_tokens\":128}}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish();
        assert_eq!(u.input_tokens, 950);
        assert_eq!(u.output_tokens, 120);
        assert_eq!(u.cache_read_tokens, 128);
    }

    #[test]
    fn parses_non_streaming_json_usage() {
        let mut p = UsageParser::new();
        p.feed(br#"{"id":"msg_1","usage":{"input_tokens":40,"output_tokens":15}}"#);
        let u = p.finish();
        assert_eq!(u.input_tokens, 40);
        assert_eq!(u.output_tokens, 15);
    }

    // -- I1: tool_calls counting (docs/21-tool-runs.md) ---------------------

    #[test]
    fn counts_anthropic_non_streaming_tool_use_blocks() {
        let mut p = UsageParser::new();
        p.feed(
            br#"{"type":"message","content":[
            {"type":"text","text":"let me check"},
            {"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}},
            {"type":"tool_use","id":"toolu_2","name":"get_time","input":{}}
        ],"usage":{"input_tokens":10,"output_tokens":5}}"#,
        );
        let u = p.finish();
        assert_eq!(u.tool_calls, Some(2));
    }

    #[test]
    fn counts_anthropic_streaming_content_block_start_tool_use_events() {
        let mut p = UsageParser::new();
        p.feed(
            b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n",
        );
        p.feed(b"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n");
        p.feed(b"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\"}}\n\n");
        p.feed(b"data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"get_time\"}}\n\n");
        p.feed(b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":20}}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish();
        assert_eq!(u.tool_calls, Some(2));
    }

    #[test]
    fn counts_openai_non_streaming_tool_calls_summed_across_choices() {
        let mut p = UsageParser::new();
        p.feed(br#"{"choices":[
            {"index":0,"message":{"role":"assistant","tool_calls":[
                {"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{}"}},
                {"id":"call_2","type":"function","function":{"name":"get_time","arguments":"{}"}}
            ]},"finish_reason":"tool_calls"},
            {"index":1,"message":{"role":"assistant","tool_calls":[
                {"id":"call_3","type":"function","function":{"name":"get_weather","arguments":"{}"}}
            ]},"finish_reason":"tool_calls"}
        ],"usage":{"prompt_tokens":30,"completion_tokens":12}}"#);
        let u = p.finish();
        // 2 tool calls on choice 0 + 1 on choice 1 = 3, summed across choices.
        assert_eq!(u.tool_calls, Some(3));
    }

    #[test]
    fn counts_openai_streaming_distinct_delta_indexes_not_delta_count() {
        let mut p = UsageParser::new();
        // Index 0's arguments stream across three deltas (same tool call);
        // index 1 is a second, distinct tool call. Five deltas total, two
        // distinct indexes - the count must be 2, not 5.
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"lat\\\"\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":1}\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_2\",\"type\":\"function\",\"function\":{\"name\":\"get_time\",\"arguments\":\"\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n");
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish();
        assert_eq!(u.tool_calls, Some(2));
    }

    /// Regression: `n>1` (multiple choices) each stream their OWN tool_calls
    /// index restarting from 0, so index alone is not a globally unique key.
    /// Two different choices both emitting a tool call at index 0 are two
    /// distinct tool calls - counting must not collapse them into one.
    #[test]
    fn counts_openai_streaming_tool_calls_across_multiple_choices_by_choice_and_index() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}},{\"index\":1,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_2\",\"type\":\"function\",\"function\":{\"name\":\"get_time\",\"arguments\":\"\"}}]}}]}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish();
        assert_eq!(u.tool_calls, Some(2));
    }

    #[test]
    fn no_tool_calls_in_a_valid_body_is_zero_not_none() {
        let mut p = UsageParser::new();
        p.feed(br#"{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":5,"output_tokens":2}}"#);
        let u = p.finish();
        assert_eq!(u.tool_calls, Some(0));
    }

    #[test]
    fn no_tool_calls_in_a_text_only_stream_is_zero_not_none() {
        let mut p = UsageParser::new();
        p.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n");
        p.feed(b"data: [DONE]\n\n");
        let u = p.finish();
        assert_eq!(u.tool_calls, Some(0));
    }

    #[test]
    fn unparseable_body_leaves_tool_calls_none() {
        let mut p = UsageParser::new();
        p.feed(b"not json at all, an upstream error page or a truncated body");
        let u = p.finish();
        assert_eq!(u.tool_calls, None);
    }

    #[test]
    fn empty_body_leaves_tool_calls_none() {
        let p = UsageParser::new();
        let u = p.finish();
        assert_eq!(u.tool_calls, None);
    }

    #[tokio::test]
    async fn stub_sse_stream_yields_frames_and_usage() {
        let stub = StubProvider {
            input_tokens: 100,
            output_tokens: 50,
            sse: true,
            body_override: None,
        };
        let resp = stub.send(HeaderMap::new(), Bytes::new()).await.unwrap();
        let collected: Vec<u8> = {
            let mut acc = Vec::new();
            let mut body = resp.body;
            while let Some(chunk) = body.next().await {
                acc.extend_from_slice(&chunk.unwrap());
            }
            acc
        };
        let text = String::from_utf8(collected).unwrap();
        assert!(text.contains("message_start"));
        assert!(text.contains("[DONE]"));
        // Usage slot is populated after the stream is drained.
        let u = resp.usage.lock().unwrap().unwrap();
        assert_eq!(u.input_tokens, 100);
        assert_eq!(u.output_tokens, 50);
    }

    #[test]
    fn forward_headers_allowlist_includes_x_api_key() {
        // Anthropic's native auth header. Without this, the OpenAI-style
        // `authorization` header is stripped through fine but Anthropic never
        // sees a key and answers 401 "x-api-key header is required" — this
        // pins the regression at the allowlist-definition level.
        assert!(FORWARD_HEADERS.contains(&"x-api-key"));
    }

    /// End-to-end proof: spin up a real HTTP upstream, send `HttpProvider` a
    /// request carrying `x-api-key`, and assert the upstream actually
    /// received it. This exercises the real header-copy loop in `send`
    /// (not just the allowlist constant), so it can't pass while the loop
    /// itself is broken.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_provider_forwards_x_api_key_to_upstream() {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};

        // Upstream stub: echoes back whichever auth-shaped headers it saw, so
        // the test can assert on what actually crossed the wire.
        async fn echo_auth_headers(headers: HeaderMap) -> Json<Value> {
            let get = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string()
            };
            Json(json!({
                "x_api_key": get("x-api-key"),
                "authorization": get("authorization"),
            }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route("/", post(echo_auth_headers));
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let provider = HttpProvider::new(format!("http://{addr}"));

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "sk-ant-test-key".parse().unwrap());
        headers.insert("anthropic-version", "2023-06-01".parse().unwrap());

        let resp = provider
            .send(headers, Bytes::from_static(b"{}"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);

        let mut body = resp.body;
        let mut collected = Vec::new();
        while let Some(chunk) = body.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        let received: Value = serde_json::from_slice(&collected).unwrap();

        // The whole point of this fix: the upstream must see the key.
        assert_eq!(received["x_api_key"], "sk-ant-test-key");
        // No Authorization header was sent in this request, and none should
        // be fabricated.
        assert_eq!(received["authorization"], "");
    }
}
