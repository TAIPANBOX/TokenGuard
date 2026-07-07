//! Network probes for the `mcp-scan --url` exposure checks: an
//! unauthenticated `tools/list` (status + headers, for the CORS check) and,
//! opt-in, an unauthenticated `tools/call` against the least-destructive
//! advertised tool.
//!
//! All decision logic — severity, host classification, the
//! plaintext-escalation rule, least-destructive-tool selection — lives in
//! `tokenfuse_core::mcpexposure` and is pure/unit-tested there. This module
//! only performs the requests and packages the results into a
//! `ProbeOutcome` for that pure layer to interpret.

use serde_json::json;

use tokenfuse_core::mcp::McpTool;
use tokenfuse_core::mcpexposure::{pick_safe_call_target, CallAttempt, ProbeOutcome};

use crate::mcpclient::{fetch_tools_list_probe, probe_tools_call, McpClientConfig};

/// Run the exposure probe against `url`.
///
/// - Always performs a **no-auth** `tools/list` (regardless of any auth the
///   "normal" scan connection used) and records whether it returned tools,
///   plus whether the response carried a wildcard CORS header.
/// - If `attempt_call` is set, picks the least-destructive tool out of
///   `tools` (the tool list from the normal scan — see
///   `pick_safe_call_target`) and attempts one unauthenticated `tools/call`
///   against it.
///
/// Never panics or propagates a network error: a probe that fails (timeout,
/// connection refused, non-2xx status) just means "no finding from that
/// check," which is the correct behavior for e.g. a server that requires
/// auth and rejects the unauthenticated attempt outright.
pub async fn run_exposure_probe(url: &str, tools: &[McpTool], attempt_call: bool) -> ProbeOutcome {
    // Deliberately empty `extra_headers`: this probe exists to test the
    // unauthenticated path, independent of whatever the main scan sends.
    let cfg = McpClientConfig::new(url);

    let (unauth_list_returned, unauth_tool_count, cors_wildcard) =
        match fetch_tools_list_probe(&cfg).await {
            Ok(probe) => {
                let tool_count = tokenfuse_core::mcp::parse_tools(&probe.body).len();
                let cors = probe
                    .headers
                    .iter()
                    .any(|(k, v)| k == "access-control-allow-origin" && v.trim() == "*");
                (tool_count > 0, tool_count, cors)
            }
            Err(_) => (false, 0, false),
        };

    let call_attempt = if attempt_call {
        match pick_safe_call_target(tools) {
            None => CallAttempt::Skipped {
                reason: "no advertised tool looked safe to call (needs a list_/get_/read_ \
                         name and no write|delete|exec|run|deploy|send|create|update|remove \
                         match in its name or description)"
                    .to_string(),
            },
            Some(target) => match probe_tools_call(&cfg, &target.name, json!({})).await {
                Ok(resp) if resp.body.get("error").is_none() => CallAttempt::Succeeded {
                    tool: target.name.clone(),
                },
                // Either a JSON-RPC error body or a transport/status error
                // (e.g. HTTP 401) both mean the server did not honor the
                // unauthenticated call.
                _ => CallAttempt::Rejected {
                    tool: target.name.clone(),
                },
            },
        }
    } else {
        CallAttempt::NotRequested
    };

    ProbeOutcome {
        url: url.to_string(),
        unauth_list_returned,
        unauth_tool_count,
        cors_wildcard,
        call_attempt,
    }
}
