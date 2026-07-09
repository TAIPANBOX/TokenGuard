//! MCP credential-broker: a JSON-RPC proxy an agent points its MCP client at.
//!
//! Two jobs at the boundary between the agent and a real MCP server:
//!
//! 1. **Credential brokering** — on `tools/call`, replace `{{secret:NAME}}`
//!    handles in the params with real secrets from the vault *just before*
//!    forwarding. The agent (and the LLM prompt, trace, and memory) only ever
//!    holds handles; the secret appears only on the wire to the MCP server.
//! 2. **Live poisoning + rug-pull scan** — on `tools/list`, run the
//!    tool-description scanner and diff against a pinned lockfile.
//! 3. **DLP** — block raw secrets in outgoing args and **redact** secrets in tool
//!    responses so a result can't leak a credential into the model's context.
//!
//! Two transports share [`process`]: HTTP (`app`, default `127.0.0.1:4200`) and
//! **stdio** (`run_stdio`, for MCP clients that launch a server as a subprocess).
//! Config: `TOKENFUSE_MCP_UPSTREAM`, `_SECRETS` (`name=val,…`), `_SCAN`
//! (`off|warn|block`), `_DLP` (`off|warn|block`), `_LOCK` (rug-pull baseline),
//! `_ADDR`, `_STDIO`. Run: `tokenfuse mcp-broker` (or `mcp-broker --stdio`).

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokenfuse_core::agent_event::{EventType, Exporter as EventExporter};
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
    /// Agent-event NDJSON exporter (agent-passport SPEC.md §6). Disabled by
    /// default; see `crate::events::from_env`. `mcp_drift` is the only event
    /// this broker emits — see [`process`].
    pub events: Arc<EventExporter>,
}

pub fn app(state: Arc<BrokerState>) -> Router {
    // Bound the JSON-RPC body a client can force the broker to buffer.
    let max_body = std::env::var("TOKENFUSE_MAX_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16 * 1024 * 1024);
    Router::new()
        .route("/", post(handle))
        .route("/mcp", post(handle))
        .route("/healthz", get(|| async { "ok" }))
        .layer(axum::extract::DefaultBodyLimit::max(max_body))
        .with_state(state)
}

/// JSON-RPC error response with the same id as the request.
fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/// HTTP handler — delegates to the transport-agnostic [`process`]. Extracts
/// `X-Fuse-Agent-Id` (agent-passport SPEC.md §3.2) so a `mcp_drift` event
/// raised for this request can carry the required `agent_id` (see
/// `process`'s doc — without this header the event is skipped, not
/// fabricated).
async fn handle(
    State(st): State<Arc<BrokerState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<Value>,
) -> Json<Value> {
    let agent_id = headers.get("x-fuse-agent-id").and_then(|v| v.to_str().ok());
    Json(process(&st, req, agent_id).await)
}

/// Broker a single JSON-RPC request and return the response — shared by the HTTP
/// and stdio transports. Injects secrets, scans, forwards, and redacts.
///
/// `agent_id`: the caller's `X-Fuse-Agent-Id`, when known — the HTTP
/// transport ([`handle`]) reads it off the request headers; the stdio
/// transport ([`run_stdio`]) has no per-message header channel and always
/// passes `None`, so a stdio-transport rug-pull is detected and logged
/// (`tracing::warn!`, unchanged) but its `mcp_drift` agent-event is skipped
/// (agent-passport SPEC.md §6.1 requires `agent_id`; see
/// `tokenfuse_core::agent_event::build`) and counted — a known, documented
/// gap rather than a fabricated identity.
pub async fn process(st: &BrokerState, mut req: Value, agent_id: Option<&str>) -> Value {
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
                        );
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
        Err(e) => return rpc_error(&id, -32000, &format!("encode error: {e}")),
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
        Err(e) => return rpc_error(&id, -32000, &format!("upstream error: {e}")),
    };
    let bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => return rpc_error(&id, -32000, &format!("upstream read: {e}")),
    };
    let mut out: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => return rpc_error(&id, -32000, &format!("bad upstream json: {e}")),
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
                let outcome = st.events.emit(
                    EventType::McpDrift,
                    crate::sink::now_millis(),
                    agent_id,
                    None,
                    None,
                    json!({ "tools_changed": changed }),
                    None,
                );
                crate::events::log_outcome(EventType::McpDrift, outcome);
                if st.scan == ScanMode::Block {
                    return rpc_error(
                        &id,
                        -32003,
                        &format!(
                            "blocked: tool definition changed (rug-pull): {}",
                            changed.join(", ")
                        ),
                    );
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
                );
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

    // 3. Redact secrets in the response body so a tool result can't leak a
    //    credential into the model's context.
    if st.dlp != DlpMode::Off {
        let text = out.to_string();
        let findings = dlp::scan(&text);
        if !findings.is_empty() {
            tracing::warn!(secrets = %dlp::summary(&findings), "mcp broker: redacted secrets in tool response");
            if let Ok(redacted) = serde_json::from_str(&dlp::redact(&text, &findings)) {
                out = redacted;
            }
        }
    }

    out
}

/// Run the broker over **stdio** — newline-delimited JSON-RPC on stdin/stdout,
/// for MCP clients that launch a server as a subprocess. Each request is brokered
/// via [`process`] and forwarded to the configured HTTP upstream. Logs must go to
/// stderr (stdout is the protocol channel).
pub async fn run_stdio(state: Arc<BrokerState>) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(line) {
            // stdio has no per-message header channel, so no agent_id is
            // available here — see `process`'s doc for what that means for
            // `mcp_drift` on this transport.
            Ok(req) => process(&state, req, None).await,
            Err(e) => rpc_error(&Value::Null, -32700, &format!("parse error: {e}")),
        };
        let mut buf = serde_json::to_vec(&resp).unwrap_or_default();
        buf.push(b'\n');
        stdout.write_all(&buf).await?;
        stdout.flush().await?;
    }
    Ok(())
}
