//! # TokenFuse
//!
//! **Runtime cost control & security for AI agents** — a drop-in proxy between
//! your agent and its LLM/tool providers that enforces per-run budgets, detects
//! runaway loops, offers a kill-switch, and keeps secrets out of the model's
//! context.
//!
//! This is the project's **umbrella crate**. TokenFuse runs as a service, not a
//! library dependency: the gateway ships as the `tokenfuse` binary and as Docker
//! images on GHCR.
//!
//! ```text
//! docker run -p 4100:4100 -e TOKENFUSE_MODE=enforce ghcr.io/taipanbox/tokenfuse
//! ```
//!
//! Point your provider client at `http://127.0.0.1:4100` and attach a few
//! `X-Fuse-*` headers. See the [repository] for the full documentation, the HA
//! cluster, the hosted Cloud, and the MCP credential-broker.
//!
//! [repository]: https://github.com/TAIPANBOX/tokenfuse

/// The released TokenFuse version this crate documents.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default gateway address the proxy listens on.
pub const DEFAULT_GATEWAY: &str = "http://127.0.0.1:4100";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
        assert!(DEFAULT_GATEWAY.starts_with("http"));
    }
}
