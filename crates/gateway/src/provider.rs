//! The upstream LLM provider abstraction.
//!
//! The gateway is provider-agnostic: it forwards a request and gets back a body
//! plus a token [`Usage`] record. Real HTTP forwarding with SSE passthrough is
//! the next milestone (Phase 0 spike #1); [`StubProvider`] lets us build and
//! test the enforcement path end-to-end in the meantime.

use async_trait::async_trait;
use tokenfuse_core::Usage;

/// What the upstream returned for one call.
#[derive(Debug, Clone)]
pub struct ProviderOutcome {
    /// HTTP status the upstream returned.
    pub status: u16,
    /// Raw response body to pass back to the caller.
    pub body: Vec<u8>,
    /// Token usage extracted from the response (the basis for settling cost).
    pub usage: Usage,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("upstream request failed: {0}")]
    Upstream(String),
}

/// An upstream that can complete a request. Implemented by real provider clients
/// and by test stubs.
#[async_trait]
pub trait Provider: Send + Sync {
    async fn complete(&self, model: &str, body: &[u8]) -> Result<ProviderOutcome, ProviderError>;
}

/// A deterministic stand-in used until real forwarding lands. It reports a fixed
/// input-token count plus whatever `output_tokens` it was configured with, so
/// tests can assert on settled cost.
#[derive(Debug, Clone)]
pub struct StubProvider {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl Default for StubProvider {
    fn default() -> Self {
        StubProvider {
            input_tokens: 1_000,
            output_tokens: 500,
        }
    }
}

#[async_trait]
impl Provider for StubProvider {
    async fn complete(&self, model: &str, _body: &[u8]) -> Result<ProviderOutcome, ProviderError> {
        let usage = Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            ..Default::default()
        };
        let body = format!(
            r#"{{"model":"{model}","stub":true,"usage":{{"input_tokens":{},"output_tokens":{}}}}}"#,
            self.input_tokens, self.output_tokens
        )
        .into_bytes();
        Ok(ProviderOutcome {
            status: 200,
            body,
            usage,
        })
    }
}
