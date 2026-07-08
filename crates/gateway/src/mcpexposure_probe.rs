//! Network probes for the `mcp-scan --url` exposure checks: an
//! unauthenticated `tools/list` (status + headers, for the CORS check) and,
//! opt-in, an unauthenticated `tools/call` against an operator-named tool.
//!
//! All decision logic — severity, host classification, the
//! plaintext-escalation rule — lives in `tokenfuse_core::mcpexposure` and is
//! pure/unit-tested there. This module performs the requests, resolves the
//! (scheme, host) that the scan actually connects to, and packages the
//! results into a `ProbeOutcome` for that pure layer to interpret.

use serde_json::json;

use tokenfuse_core::mcpexposure::{CallAttempt, ProbeOutcome};

use crate::mcpclient::{fetch_tools_list_probe, probe_tools_call, McpClientConfig};

/// Run the exposure probe against `url`.
///
/// - Always performs a **no-auth** `tools/list` (regardless of any auth the
///   "normal" scan connection used) and records whether it returned tools,
///   plus whether the response carried a wildcard CORS header.
/// - If `attempt_call` is set, attempts one unauthenticated `tools/call`
///   against `call_tool` — the exact tool name the *operator* supplied via
///   `--call-tool`. There is deliberately no auto-selection from the
///   server's advertised tool list: the server controls both a tool's name
///   and its description, so a keyword filter over that text (e.g. "starts
///   with get_/list_, no 'delete' in the description") can be defeated by a
///   hostile server that simply describes a destructive tool as safe. If
///   `attempt_call` is set but `call_tool` is `None`, the probe is skipped
///   with an explicit reason instead of guessing.
///
/// Never panics or propagates a network error: a probe that fails (timeout,
/// connection refused, non-2xx status) just means "no finding from that
/// check," which is the correct behavior for e.g. a server that requires
/// auth and rejects the unauthenticated attempt outright.
pub async fn run_exposure_probe(
    url: &str,
    attempt_call: bool,
    call_tool: Option<&str>,
) -> ProbeOutcome {
    // Deliberately empty `extra_headers`: this probe exists to test the
    // unauthenticated path, independent of whatever the main scan sends.
    let cfg = McpClientConfig::new(url);

    // Classify against the SAME (scheme, host) reqwest will actually connect
    // to, not a hand-rolled re-parse of the raw string (S1): reqwest
    // re-exports the exact `url` crate it uses internally to pick a connect
    // host, so parsing with it here means classification can never diverge
    // from where the probe requests below actually go — e.g. a `\` smuggled
    // into the authority (`https://pub.example.com\@127.0.0.1/`) can no
    // longer make a public host classify as loopback.
    let (scheme, host) = match reqwest::Url::parse(url) {
        Ok(parsed) => (
            parsed.scheme().to_string(),
            parsed.host_str().unwrap_or_default().to_string(),
        ),
        // `reqwest` will fail to send a request against a URL it can't parse
        // itself (the probes below will error out too, so no finding fires
        // off these defaults); fall back to the core crate's best-effort
        // parser purely so this branch has *some* deterministic value.
        Err(_) => tokenfuse_core::mcpexposure::parse_url_host_scheme(url).unwrap_or_default(),
    };

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
        match call_tool {
            None => CallAttempt::Skipped {
                reason: "--attempt-call requires an explicit --call-tool <name>; refusing to \
                         auto-pick a tool from server-controlled descriptions"
                    .to_string(),
            },
            Some(name) => match probe_tools_call(&cfg, name, json!({})).await {
                Ok(resp) if resp.body.get("error").is_none() => CallAttempt::Succeeded {
                    tool: name.to_string(),
                },
                // Either a JSON-RPC error body or a transport/status error
                // (e.g. HTTP 401) both mean the server did not honor the
                // unauthenticated call.
                _ => CallAttempt::Rejected {
                    tool: name.to_string(),
                },
            },
        }
    } else {
        CallAttempt::NotRequested
    };

    ProbeOutcome {
        scheme,
        host,
        unauth_list_returned,
        unauth_tool_count,
        cors_wildcard,
        call_attempt,
    }
}
