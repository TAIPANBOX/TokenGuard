//! MCP credential-broker: a JSON-RPC proxy an agent points its MCP client at.
//!
//! Two jobs at the boundary between the agent and a real MCP server:
//!
//! 1. **Credential brokering** — on `tools/call`, replace `{{secret:NAME}}`
//!    handles in the params with real secrets from the vault *just before*
//!    forwarding. The agent (and the LLM prompt, trace, and memory) only ever
//!    holds handles; the secret appears only on the wire to the MCP server.
//! 2. **Live poisoning scan** — on `tools/list`, run the tool-description
//!    scanner (`tokenfuse_core::mcp`); `warn` logs, `block` refuses the list.
//!
//! Config: `TOKENFUSE_MCP_UPSTREAM` (real server), `TOKENFUSE_MCP_SECRETS`
//! (`name=val,…`), `TOKENFUSE_MCP_SCAN` (`off|warn|block`, default `warn`),
//! `TOKENFUSE_MCP_ADDR` (listen; default `127.0.0.1:4200`). Run:
//! `tokenfuse mcp-broker`.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokenfuse_core::mcp::{self, Lock};
use tokenfuse_core::{dlp, inject_secrets, DlpMode, SecretVault};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Off,
    Warn,
    Block,
}

pub struct BrokerState {
    pub upstream: String,
    pub vault: SecretVault,
    pub scan: ScanMode,
    /// Scan outgoing tool-call args for raw secrets the agent pasted directly
    /// (not via a `{{secret:}}` handle). Off｜Shadow(=warn)｜Block.
    pub dlp: DlpMode,
    /// Baseline of pinned tool fingerprints; a changed description on
    /// `tools/list` is a rug-pull. `None` disables the check.
    pub lock: Option<Lock>,
    pub client: reqwest::Client,
}

pub fn app(state: Arc<BrokerState>) -> Router {
    Router::new()
        .route("/", post(handle))
        .route("/mcp", post(handle))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

/// JSON-RPC error response with the same id as the request.
fn rpc_error(id: &Value, code: i64, message: &str) -> Json<Value> {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    }))
}

async fn handle(
    State(st): State<Arc<BrokerState>>,
    Json(mut req): Json<Value>,
) -> impl IntoResponse {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();

    // 1. Credential brokering: inject secret handles on tool calls.
    if method == "tools/call" {
        // DLP: catch raw secrets the agent pasted directly into the args (before
        // injection, so vault-injected secrets aren't flagged).
        if st.dlp != DlpMode::Off {
            if let Some(params) = req.get("params") {
                let findings = dlp::scan(&params.to_string());
                if !findings.is_empty() {
                    tracing::warn!(secrets = %dlp::summary(&findings), "mcp broker: raw secret in tool args");
                    if st.dlp == DlpMode::Block {
                        return rpc_error(
                            &id,
                            -32002,
                            &format!(
                                "blocked: raw secret in tool arguments ({})",
                                dlp::summary(&findings)
                            ),
                        )
                        .into_response();
                    }
                }
            }
        }
        if let Some(params) = req.get_mut("params") {
            let inj = inject_secrets(params, &st.vault);
            if inj.replaced > 0 {
                tracing::info!(count = inj.replaced, "mcp broker: injected secrets");
            }
            if !inj.missing.is_empty() {
                tracing::warn!(missing = ?inj.missing, "mcp broker: unknown secret handles");
            }
        }
    }

    // Forward to the real MCP server (serialize by hand — reqwest's json feature
    // isn't enabled in this crate).
    let payload = match serde_json::to_vec(&req) {
        Ok(p) => p,
        Err(e) => return rpc_error(&id, -32000, &format!("encode error: {e}")).into_response(),
    };
    let upstream = match st
        .client
        .post(&st.upstream)
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .and_then(|r| r.error_for_status())
    {
        Ok(r) => r,
        Err(e) => return rpc_error(&id, -32000, &format!("upstream error: {e}")).into_response(),
    };
    let bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => return rpc_error(&id, -32000, &format!("upstream read: {e}")).into_response(),
    };
    let mut out: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return rpc_error(&id, -32000, &format!("bad upstream json: {e}")).into_response()
        }
    };

    // 2. Poisoning + rug-pull checks on tool listings.
    if method == "tools/list" && st.scan != ScanMode::Off {
        let tools = mcp::parse_tools(&out);

        // Rug-pull: a tool's description/schema changed vs. the pinned lock.
        if let Some(lock) = &st.lock {
            let changed: Vec<String> = mcp::diff(&tools, lock)
                .into_iter()
                .filter_map(|d| match d {
                    mcp::Drift::Changed(name) => Some(name),
                    _ => None,
                })
                .collect();
            if !changed.is_empty() {
                tracing::warn!(tools = ?changed, "mcp broker: rug-pull (tool definition changed)");
                if st.scan == ScanMode::Block {
                    return rpc_error(
                        &id,
                        -32003,
                        &format!(
                            "blocked: tool definition changed (rug-pull): {}",
                            changed.join(", ")
                        ),
                    )
                    .into_response();
                }
            }
        }

        let findings = mcp::scan_injection(&tools);
        if !findings.is_empty() {
            tracing::warn!(count = findings.len(), findings = ?findings, "mcp broker: tool poisoning");
            if st.scan == ScanMode::Block {
                return rpc_error(
                    &id,
                    -32001,
                    &format!("blocked: {} poisoned tool description(s)", findings.len()),
                )
                .into_response();
            }
            // In warn mode, annotate the response without breaking the client.
            if let Some(obj) = out.as_object_mut() {
                obj.insert(
                    "_tokenfuse".into(),
                    json!({ "mcp_findings": findings.len() }),
                );
            }
        }
    }

    Json(out).into_response()
}
