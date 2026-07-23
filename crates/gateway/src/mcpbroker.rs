//! MCP credential-broker: a JSON-RPC proxy an agent points its MCP client at.
//!
//! Jobs at the boundary between the agent and a real MCP server:
//!
//! 1. **Credential brokering** — on `tools/call`, replace `{{secret:NAME}}`
//!    handles in the params with real secrets from the vault *just before*
//!    forwarding. The agent (and the LLM prompt, trace, and memory) only ever
//!    holds handles; the secret appears only on the wire to the MCP server.
//! 2. **Policy gate (the second PEP, docs/23)** — on `tools/call`, put the call
//!    to the same Wardryx PDP the LLM path uses, BEFORE injecting secrets or
//!    forwarding, so a `deny_tool` (or `deny_if_unattested`, or an approval
//!    `hold`) policy enforces at the MCP layer too. Off unless Wardryx is
//!    configured. The broker holds no signer and mutates nothing: a deny/hold
//!    is a JSON-RPC refusal. Each gated call emits one `tool_call` audit event.
//! 3. **Live poisoning + rug-pull scan** — on `tools/list`, run the
//!    tool-description scanner and diff against a pinned lockfile.
//! 4. **DLP** — block raw secrets in outgoing args and **redact** secrets in tool
//!    responses so a result can't leak a credential into the model's context.
//!
//! A request selects one of several **named upstreams** with `X-Fuse-Mcp-Upstream`
//! (`TOKENFUSE_MCP_UPSTREAMS="name=url,…"`); no header uses the default
//! `TOKENFUSE_MCP_UPSTREAM`. An unknown name is refused, never re-routed.
//!
//! Two transports share [`process`]: HTTP (`app`, default `127.0.0.1:4200`) and
//! **stdio** (`run_stdio`, for MCP clients that launch a server as a subprocess).
//! Config: `TOKENFUSE_MCP_UPSTREAM`(S), `_SECRETS` (`name=val,…`), `_SCAN`
//! (`off|warn|block`), `_DLP` (`off|warn|block`), `_LOCK` (rug-pull baseline),
//! `_ADDR`, `_STDIO`, plus the shared `TOKENFUSE_WARDRYX_*` for the policy gate.
//! Run: `tokenfuse mcp-broker` (or `mcp-broker --stdio`).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokenfuse_core::agent_event::{EventType, Exporter as EventExporter};
use tokenfuse_core::mcp::{self, Lock};
use tokenfuse_core::{dlp, inject_secrets, DlpMode, SecretVault};

use crate::wardryx::{DecideContext, Wardryx, WardryxDecision, WardryxMode};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Off,
    Warn,
    Block,
}

pub struct BrokerState {
    /// The default upstream MCP server: used when a request names no upstream
    /// (via `X-Fuse-Mcp-Upstream`), and the only upstream on the stdio
    /// transport (which has no per-message header channel). Kept as its own
    /// field, distinct from [`named_upstreams`](Self::named_upstreams), so the
    /// existing single-upstream config (`TOKENFUSE_MCP_UPSTREAM`) keeps working
    /// unchanged.
    pub upstream: String,
    /// Additional named upstreams (`TOKENFUSE_MCP_UPSTREAMS="name=url,..."`).
    /// A request selects one by its `X-Fuse-Mcp-Upstream` header. An unknown
    /// name is refused, never silently sent to the default: forwarding a
    /// request (and its injected secrets) to the wrong server is exactly the
    /// mistake this refusal prevents.
    pub named_upstreams: BTreeMap<String, String>,
    pub vault: SecretVault,
    pub scan: ScanMode,
    /// Scan outgoing tool-call args for raw secrets the agent pasted directly
    /// (not via a `{{secret:}}` handle). Off｜Shadow(=warn)｜Block.
    pub dlp: DlpMode,
    /// Baseline of pinned tool fingerprints; a changed description on
    /// `tools/list` is a rug-pull. `None` disables the check.
    pub lock: Option<Lock>,
    /// The second Policy Enforcement Point (docs/23): every `tools/call` is
    /// put to Wardryx's `decide()`, the same PDP the LLM path uses, so a
    /// `deny_tool` policy now enforces at the MCP layer too. `Wardryx::disabled`
    /// (mode Off) by default, in which case the broker forwards exactly as
    /// before. The broker holds no signer and never mutates a plane: a deny or
    /// hold is a refusal returned to the caller, nothing more.
    pub wardryx: Arc<Wardryx>,
    pub client: reqwest::Client,
    /// Agent-event NDJSON exporter (agent-passport SPEC.md §6). Disabled by
    /// default; see `crate::events::from_env`. Emits `mcp_drift` (rug-pull) and
    /// `tool_call` (one per Wardryx-gated `tools/call`) -- see [`process`].
    pub events: Arc<EventExporter>,
}

/// Per-request context the HTTP transport reads off headers and the stdio
/// transport leaves empty. Keeps [`process`] transport-agnostic: everything
/// header-shaped lives here, so stdio simply passes `CallContext::default()`.
#[derive(Default)]
pub struct CallContext {
    /// `X-Fuse-Agent-Id` (agent-passport SPEC.md §3.2). Required for the
    /// Wardryx gate to attribute a `tools/call` to an agent and for any event
    /// to carry a real `agent_id`; absent on stdio.
    pub agent_id: Option<String>,
    /// `X-Fuse-Mcp-Upstream`: selects a [`named_upstreams`](BrokerState::named_upstreams)
    /// entry. Absent -> the default upstream.
    pub upstream: Option<String>,
    /// `x-fuse-on-behalf-of` (comma-separated, root first), forwarded to the
    /// PDP so a delegation-scoped policy can match.
    pub on_behalf_of: Vec<String>,
    /// `x-fuse-attestation-method`, forwarded to the PDP for a
    /// `deny_if_unattested` policy.
    pub attestation_method: Option<String>,
    /// `x-fuse-approval-token`: an operator-granted token that lets a
    /// previously-held `tools/call` through, verified by the PDP exactly as on
    /// the LLM path.
    pub approval_token: Option<String>,
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

/// `" (reason)"` when the PDP gave a reason, else empty -- so a block message
/// reads cleanly whether or not Wardryx explained itself.
fn reason_suffix(reason: &Option<String>) -> String {
    match reason {
        Some(r) if !r.is_empty() => format!(" ({r})"),
        _ => String::new(),
    }
}

/// Emit one `tool_call` audit event for a Wardryx-gated `tools/call`. Skipped
/// when `agent_id` is absent (agent-passport SPEC.md §6.1 forbids a fabricated
/// `agent_id`; [`tokenfuse_core::agent_event::build`] enforces this and the
/// event is counted-and-skipped, never faked). In shadow mode the recorded
/// `decision` is `would-<decision>`, matching the `x-fuse-wardryx` header
/// convention, so a shadow rollout's audit trail never reads as if a call was
/// actually enforced.
fn emit_tool_call(
    st: &BrokerState,
    agent_id: Option<&str>,
    tool: &str,
    upstream: &str,
    decision: WardryxDecision,
    mode: WardryxMode,
) {
    let decision_str = if mode == WardryxMode::Shadow {
        format!("would-{}", decision.as_wire_str())
    } else {
        decision.as_wire_str().to_string()
    };
    let outcome = st.events.emit(
        EventType::ToolCall,
        crate::sink::now_millis(),
        agent_id,
        None,
        None,
        json!({ "tool": tool, "upstream": upstream, "decision": decision_str }),
        None,
    );
    crate::events::log_outcome(EventType::ToolCall, outcome);
}

/// HTTP handler — delegates to the transport-agnostic [`process`]. Reads the
/// `x-fuse-*` headers into a [`CallContext`]: `X-Fuse-Agent-Id`
/// (agent-passport SPEC.md §3.2) so an event raised for this request can carry
/// the required `agent_id` (without it, events are skipped, not fabricated),
/// `X-Fuse-Mcp-Upstream` to pick a named upstream, and the delegation /
/// attestation / approval headers the Wardryx gate forwards to the PDP.
async fn handle(
    State(st): State<Arc<BrokerState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<Value>,
) -> Json<Value> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let ctx = CallContext {
        agent_id: header("x-fuse-agent-id"),
        upstream: header("x-fuse-mcp-upstream"),
        on_behalf_of: header("x-fuse-on-behalf-of")
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        attestation_method: header("x-fuse-attestation-method"),
        approval_token: header("x-fuse-approval-token"),
    };
    Json(process(&st, req, &ctx).await)
}

/// Resolve which upstream URL this request forwards to. A named upstream
/// (`X-Fuse-Mcp-Upstream`) must exist in [`BrokerState::named_upstreams`];
/// an unknown name is refused (returned as `Err(rpc_error)`) rather than
/// falling back to the default, so a request and its injected secrets can
/// never be forwarded to a server the operator did not configure. No header
/// -> the default upstream.
fn resolve_upstream<'a>(
    st: &'a BrokerState,
    ctx: &CallContext,
    id: &Value,
) -> Result<&'a str, Value> {
    match ctx.upstream.as_deref() {
        None => Ok(&st.upstream),
        Some(name) => st
            .named_upstreams
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| {
                rpc_error(
                    id,
                    -32005,
                    &format!("unknown mcp upstream {name:?} (X-Fuse-Mcp-Upstream)"),
                )
            }),
    }
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
pub async fn process(st: &BrokerState, mut req: Value, ctx: &CallContext) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let agent_id = ctx.agent_id.as_deref();

    // Which real MCP server this request forwards to. Resolved up front so an
    // unknown named upstream is refused before any secret is injected.
    let upstream_url = match resolve_upstream(st, ctx, &id) {
        Ok(u) => u.to_string(),
        Err(e) => return e,
    };

    // In shadow mode the Wardryx gate records what it WOULD have done and lets
    // the call through; this carries that verdict to the response annotation.
    let mut wardryx_shadow: Option<&'static str> = None;

    // 1. Credential brokering + the Wardryx policy gate on tool calls.
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

        // The second PEP: put this tools/call to the same Wardryx PDP the LLM
        // path uses (proxy::messages), so a `deny_tool` (or `deny_if_unattested`,
        // or an approval `hold`) policy enforces at the MCP layer too. Runs
        // BEFORE secret injection and forwarding, so a denied tool never gets a
        // real secret and never reaches the upstream. The broker holds no
        // signer and mutates nothing: a deny/hold is a JSON-RPC refusal, the
        // same shape every other block here uses.
        if st.wardryx.mode != WardryxMode::Off {
            match agent_id {
                Some(aid) => {
                    let tool = req
                        .get("params")
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    let dctx = DecideContext {
                        agent_id: aid.to_string(),
                        // The broker has no run/budget/step state; a stable
                        // per-agent id is enough for the tool/attestation rules,
                        // which key on the agent target and tool names, not the
                        // run. Cost/steps/model/domains have no broker-side
                        // equivalent and are sent empty (Wardryx reads empty as
                        // "nothing to restrict", never as a denial).
                        run_id: format!("mcp:{aid}"),
                        on_behalf_of: ctx.on_behalf_of.clone(),
                        tool_names: if tool.is_empty() {
                            Vec::new()
                        } else {
                            vec![tool.clone()]
                        },
                        steps: 0,
                        domains: Vec::new(),
                        model: String::new(),
                        est_cost_usd: 0.0,
                        attestation_method: ctx.attestation_method.clone(),
                        approval_token: ctx.approval_token.clone(),
                    };
                    let outcome = st.wardryx.decide(dctx).await;
                    emit_tool_call(
                        st,
                        agent_id,
                        &tool,
                        &upstream_url,
                        outcome.decision,
                        st.wardryx.mode,
                    );
                    if st.wardryx.mode == WardryxMode::Enforce {
                        match outcome.decision {
                            WardryxDecision::Deny => {
                                tracing::warn!(tool = %tool, "mcp broker: wardryx denied tool call");
                                return rpc_error(
                                    &id,
                                    -32004,
                                    &format!(
                                        "blocked: policy denied tool {tool:?}{}",
                                        reason_suffix(&outcome.reason)
                                    ),
                                );
                            }
                            WardryxDecision::Hold => {
                                // The broker can't run the approval ceremony, so
                                // a hold is a refusal-with-reason here; the
                                // approval row Wardryx created can be granted and
                                // the call retried with x-fuse-approval-token.
                                tracing::warn!(tool = %tool, "mcp broker: wardryx held tool call (approval required)");
                                let appr = outcome
                                    .approval_id
                                    .as_deref()
                                    .map(|a| format!(" (approval {a})"))
                                    .unwrap_or_default();
                                return rpc_error(
                                    &id,
                                    -32004,
                                    &format!("blocked: tool {tool:?} requires approval{appr}"),
                                );
                            }
                            WardryxDecision::Allow => {}
                        }
                    } else {
                        // Shadow: never block; carry the would-decision to the
                        // response so an operator can see what enforce would do.
                        wardryx_shadow = Some(outcome.decision.as_wire_str());
                    }
                }
                None => {
                    // No agent id (stdio has no per-message header channel):
                    // the call can't be attributed to an agent, so the
                    // agent-scoped gate is skipped and logged, never guessed.
                    // An empty agent id would match no policy anyway (allow), so
                    // this is the same result, made explicit. Same documented
                    // gap as mcp_drift on stdio.
                    tracing::warn!(
                        "mcp broker: wardryx gate skipped, no x-fuse-agent-id on this tools/call"
                    );
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
        .post(&upstream_url)
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

    // Shadow mode: surface what the Wardryx gate WOULD have done, having let
    // the call through. Never clobbers an existing `_tokenfuse` annotation.
    if let Some(would) = wardryx_shadow {
        if let Some(obj) = out.as_object_mut() {
            let entry = obj.entry("_tokenfuse").or_insert_with(|| json!({}));
            if let Some(t) = entry.as_object_mut() {
                t.insert("wardryx".into(), json!(format!("would-{would}")));
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
            // stdio has no per-message header channel, so the CallContext is
            // empty here: no agent_id (mcp_drift and the Wardryx gate are
            // skipped, see `process`) and no named upstream (the default one is
            // always used).
            Ok(req) => process(&state, req, &CallContext::default()).await,
            Err(e) => rpc_error(&Value::Null, -32700, &format!("parse error: {e}")),
        };
        let mut buf = serde_json::to_vec(&resp).unwrap_or_default();
        buf.push(b'\n');
        stdout.write_all(&buf).await?;
        stdout.flush().await?;
    }
    Ok(())
}
