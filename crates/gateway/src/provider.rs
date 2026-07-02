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

        for line in text.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("data:") {
                saw_sse = true;
                let rest = rest.trim();
                if rest.is_empty() || rest == "[DONE]" {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(rest) {
                    merge_usage(&mut usage, &v);
                }
            }
        }

        // Non-streaming response: the whole body is one JSON object.
        if !saw_sse {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) {
                merge_usage(&mut usage, &v);
            }
        }

        usage
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

/// Headers we forward upstream. The `Authorization` header (the provider API
/// key) is passed through and never stored or logged (privacy by design).
const FORWARD_HEADERS: &[&str] = &[
    "authorization",
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
        HttpProvider {
            client: reqwest::Client::new(),
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
}

impl Default for StubProvider {
    fn default() -> Self {
        StubProvider {
            input_tokens: 1_000,
            output_tokens: 500,
            sse: false,
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
            (
                Some("application/json".to_string()),
                vec![Bytes::from(format!(
                    r#"{{"stub":true,"usage":{{"input_tokens":{},"output_tokens":{}}}}}"#,
                    self.input_tokens, self.output_tokens
                ))],
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

    #[tokio::test]
    async fn stub_sse_stream_yields_frames_and_usage() {
        let stub = StubProvider {
            input_tokens: 100,
            output_tokens: 50,
            sse: true,
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
}
