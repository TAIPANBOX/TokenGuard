//! Server-exposure checks for the live scanner (`tokenfuse mcp-scan --url`).
//!
//! Pure decision logic only — host classification, severity, and the
//! escalation rules that combine multiple probe results into findings. The
//! actual network probes (an unauthenticated `tools/list`, optionally an
//! unauthenticated `tools/call`) live in the gateway crate
//! (`mcpexposure_probe.rs`), which fills in a [`ProbeOutcome`] and hands it
//! to [`exposure_findings`] here. No I/O, no DNS resolution.
//!
//! # SSRF safety (read before building anything on top of this)
//!
//! This scanner is **CLI-first**: it is meant to be run against a server you
//! own or control, from your own machine, by you typing a URL on your own
//! command line. In that shape there is no SSRF elevation — you already had
//! network access to whatever you point it at.
//!
//! That stops being true the moment anyone builds a **hosted** service on
//! top of this crate ("paste an MCP server URL, we scan it for you"). At
//! that point the scanner becomes an SSRF oracle: a stranger can hand your
//! server a URL and use its network position to poke internal services
//! (`169.254.169.254` cloud-metadata endpoints, RFC1918 ranges, other
//! tenants' infrastructure) that the stranger could never reach directly,
//! and read the (possibly revealing) probe results back out.
//!
//! This PR does **not** implement mitigations for that case, because CLI
//! self-scan doesn't need them and adding them here would be speculative.
//! If a hosted "scan my server" product is ever built on this, it MUST add,
//! at minimum:
//! - **resolve-then-pin**: resolve the hostname once, validate the resolved
//!   IP against a deny-list (loopback, RFC1918, link-local,
//!   `169.254.169.254` and other cloud-metadata addresses), then connect to
//!   that pinned IP directly — never let the HTTP client re-resolve DNS
//!   between the check and the connect (TOCTOU).
//! - **no cross-boundary redirect following**: a 3xx from the "public" URL
//!   the tenant supplied must not be followed onto an internal address.
//! - **per-tenant egress sandboxing**: run the actual probe from a network
//!   position (e.g. a sandboxed egress proxy/VPC) that cannot reach internal
//!   infrastructure at all, so a deny-list bug is not the only line of
//!   defense.

use crate::mcp::McpTool;
use crate::mcpreport::{Finding, Severity};

/// Keywords (case-insensitive substring match against name + description)
/// that flag a tool as capable of fetching an arbitrary URL — a pivot point
/// for SSRF if the tool (or the agent driving it) is abused. This is a
/// capability flag, not a poisoning finding: the tool doing this may be
/// completely legitimate (e.g. a `fetch_url` tool is often the point).
const SSRF_KEYWORDS: &[&str] = &["fetch", "http", "url", "webhook", "proxy", "download"];

/// Is `host` a loopback or private-range literal (`localhost`, `127.0.0.1`,
/// `::1`, RFC1918 `10.*` / `172.16-31.*` / `192.168.*`, link-local
/// `169.254.*` / `fe80::*`, or IPv6 unique-local `fc00::/7`)? Pure string/number
/// parsing — no DNS lookup, so a
/// hostname that merely *resolves* to a private address (which this PR
/// can't know without a lookup) is *not* classified as local here; see the
/// module doc and the follow-up "public bind" heuristic for that case.
pub fn host_is_local(host: &str) -> bool {
    let h = host.trim().trim_matches(['[', ']']).to_lowercase();
    if h.is_empty() {
        return false;
    }
    if h == "localhost" {
        return true;
    }
    if h == "::1" {
        return true;
    }
    if h.starts_with("fe80:") {
        return true;
    }
    // IPv6 unique-local (fc00::/7 → fc.. / fd..). Require a ':' so a hostname
    // like "fc-barcelona.com" is not misread as an IPv6 literal.
    if h.contains(':') && (h.starts_with("fc") || h.starts_with("fd")) {
        return true;
    }

    let octets: Vec<&str> = h.split('.').collect();
    if octets.len() == 4 {
        let parsed: Option<Vec<u8>> = octets.iter().map(|o| o.parse::<u8>().ok()).collect();
        if let Some(n) = parsed {
            let (a, b) = (n[0], n[1]);
            if a == 127 {
                return true; // 127.0.0.0/8 loopback
            }
            if a == 10 {
                return true; // 10.0.0.0/8
            }
            if a == 172 && (16..=31).contains(&b) {
                return true; // 172.16.0.0/12
            }
            if a == 192 && b == 168 {
                return true; // 192.168.0.0/16
            }
            if a == 169 && b == 254 {
                return true; // 169.254.0.0/16 link-local
            }
        }
    }
    false
}

/// Split a URL into `(scheme, host)`, stripping port/path/query/fragment and
/// unwrapping a bracketed IPv6 literal. Pure string parsing (no `url` crate
/// dependency in this pure-logic core crate) — good enough for the scheme
/// and host, which is all the exposure checks need.
///
/// This is a **best-effort fallback**, not the source of truth: the live scan
/// path (`mcpexposure_probe::run_exposure_probe` in the gateway crate) parses
/// the URL with `reqwest::Url` (the same WHATWG-compliant parser reqwest uses
/// to pick a connect host) and passes that authoritative `(scheme, host)`
/// into [`exposure_findings`] directly, so classification can never diverge
/// from where the scan actually connects. This function only exists for
/// callers without a `reqwest::Url` handy, and is hardened to track WHATWG
/// behavior as closely as a dependency-free parser reasonably can:
/// - a `\` inside the authority is treated as an authority terminator, same
///   as `/`/`?`/`#` — WHATWG (and therefore `url`/`reqwest`) treats `\`
///   exactly like `/` for "special" schemes (http/https/ws/wss/ftp/file), so
///   `scheme://host\@evil/x` must resolve to host `host`, not `evil`.
/// - excess `/`/`\` immediately after `://` are collapsed (ignored) before
///   authority parsing starts, mirroring WHATWG's "special authority ignore
///   slashes" state — so `https:///path` lands on host `path` (matching
///   `reqwest::Url::parse`) instead of an empty/bogus host.
pub fn parse_url_host_scheme(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.trim().to_lowercase();
    // Collapse any run of extra '/' or '\' right after "://" before isolating
    // the authority — see the WHATWG note above.
    let rest = rest.trim_start_matches(['/', '\\']);
    // Isolate the AUTHORITY first: everything up to the first '/', '?', '#',
    // or '\'. Splitting on '@' over the *whole* remainder is wrong — an '@'
    // in the path/query/fragment (e.g. `…/x?cb=a@b`) would be mistaken for a
    // userinfo separator and yield a bogus host. Confining the '@' split to
    // the authority prevents that.
    let authority_end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // Drop userinfo (`user:pass@host`) — now only within the authority.
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(after_bracket) = host_port.strip_prefix('[') {
        // Bracketed IPv6 literal: host is everything inside the brackets.
        let end = after_bracket.find(']')?;
        after_bracket[..end].to_string()
    } else {
        // host[:port] — the authority no longer contains '/', '?' or '#', so
        // only a ':' port separator can remain to strip.
        let end = host_port.find(':').unwrap_or(host_port.len());
        host_port[..end].to_string()
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host))
}

/// Is `scheme://host` plaintext-and-not-local (the base condition for
/// `exposure_plaintext`)? `scheme` is compared case-insensitively.
pub fn is_plaintext_exposure(scheme: &str, host: &str) -> bool {
    scheme.eq_ignore_ascii_case("http") && !host_is_local(host)
}

fn haystack(t: &McpTool) -> String {
    format!("{} {}", t.name.to_lowercase(), t.description.to_lowercase())
}

/// One `Low`-severity `ssrf_capable_tool` finding per tool whose name or
/// description matches an SSRF keyword (`fetch`, `http`, `url`, `webhook`,
/// `proxy`, `download`). Informational capability flag, not a poisoning
/// verdict — distinct from `scan_injection`.
pub fn ssrf_capable_findings(tools: &[McpTool]) -> Vec<Finding> {
    tools
        .iter()
        .filter(|t| {
            let hay = haystack(t);
            SSRF_KEYWORDS.iter().any(|k| hay.contains(k))
        })
        .map(|t| Finding {
            kind: "ssrf_capable_tool".to_string(),
            severity: Severity::Low,
            tool: Some(t.name.clone()),
            message: format!(
                "tool '{}' can fetch/proxy arbitrary URLs — a pivot point for SSRF if abused",
                t.name
            ),
        })
        .collect()
}

/// Outcome of the opt-in `--attempt-call` probe (a no-auth `tools/call`).
///
/// There is deliberately **no** "pick a tool automatically" variant: an
/// earlier version of this scanner picked the call target itself by matching
/// tool name/description against a keyword blocklist
/// (`list_`/`get_`/`read_` prefix, no mutation verb like `delete`/`exec`).
/// That heuristic runs over attacker-controlled strings — a malicious server
/// can name a destructive tool `get_status` and describe it as read-only, and
/// a substring filter over adversarial input can't be trusted to catch that.
/// The operator now MUST name the tool explicitly (`--call-tool <name>`);
/// see `mcpexposure_probe::run_exposure_probe` in the gateway crate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CallAttempt {
    /// `--attempt-call` was not passed; the probe never ran.
    #[default]
    NotRequested,
    /// `--attempt-call` was passed without an explicit `--call-tool <name>`,
    /// so nothing was called — the scanner refuses to guess a target from
    /// server-controlled tool metadata.
    Skipped { reason: String },
    /// The unauthenticated call was rejected (HTTP error status, or a
    /// JSON-RPC `error` response) — the server enforced auth as expected.
    Rejected { tool: String },
    /// The unauthenticated call returned a non-error result: the server
    /// accepts unauthenticated tool invocations.
    Succeeded { tool: String },
}

/// Captured result of the exposure network probes against a live MCP
/// server. Pure data — no I/O lives on this type; `mcpexposure_probe` (the
/// gateway crate) performs the actual requests and fills this in, then
/// passes it to [`exposure_findings`].
#[derive(Debug, Clone, Default)]
pub struct ProbeOutcome {
    /// The scanned server's scheme (`"http"`/`"https"`), used for the
    /// plaintext check. **Must** come from the same parser that actually
    /// connects (the gateway derives this from `reqwest::Url::parse`, not
    /// from re-parsing the raw URL string here) — see [`is_plaintext_exposure`]
    /// and the module doc's SSRF-safety note.
    pub scheme: String,
    /// The scanned server's host, used for the host-locality check. **Must**
    /// come from the same parser that actually connects — see `scheme` above
    /// and [`host_is_local`].
    pub host: String,
    /// A `tools/list` sent with **no** authentication got a 2xx response
    /// that parsed into at least one tool.
    pub unauth_list_returned: bool,
    /// How many tools that no-auth `tools/list` returned (0 if it wasn't
    /// attempted, failed, or returned an empty list).
    pub unauth_tool_count: usize,
    /// That no-auth `tools/list` response carried
    /// `Access-Control-Allow-Origin: *`.
    pub cors_wildcard: bool,
    /// Outcome of the opt-in unauthenticated `tools/call` probe.
    pub call_attempt: CallAttempt,
}

/// Turn a captured [`ProbeOutcome`] into the exposure [`Finding`]s (severity
/// and the plaintext-escalation rule live entirely here, so they're
/// unit-testable without a network). Does **not** include
/// `ssrf_capable_tool` findings — call [`ssrf_capable_findings`] separately
/// with the tool list.
///
/// Classification is driven entirely by `outcome.scheme`/`outcome.host` —
/// this function does **not** re-parse a raw URL string, so it can never
/// diverge from whatever parser the caller used to obtain them (see
/// [`ProbeOutcome`]'s field docs).
pub fn exposure_findings(outcome: &ProbeOutcome) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (scheme, host) = (outcome.scheme.as_str(), outcome.host.as_str());
    let local = host_is_local(host);

    let mut unauth_list_public = false;
    if outcome.unauth_list_returned && outcome.unauth_tool_count > 0 {
        let severity = if local {
            Severity::Info
        } else {
            Severity::High
        };
        unauth_list_public = !local;
        findings.push(Finding {
            kind: "exposure_unauth_list".to_string(),
            severity,
            tool: None,
            message: format!(
                "tools/list succeeded with no authentication ({} tool(s) returned){}",
                outcome.unauth_tool_count,
                if local {
                    " — local/dev host, expected"
                } else {
                    " — server is reachable and enumerable without credentials"
                },
            ),
        });
    }

    if is_plaintext_exposure(scheme, host) {
        // CVE-2025-49596 shape: internet-reachable + unauthenticated +
        // unencrypted escalates from Medium to High.
        let severity = if unauth_list_public {
            Severity::High
        } else {
            Severity::Medium
        };
        findings.push(Finding {
            kind: "exposure_plaintext".to_string(),
            severity,
            tool: None,
            message: "MCP endpoint is served over plaintext http:// (not https)".to_string(),
        });
    }

    if outcome.cors_wildcard {
        findings.push(Finding {
            kind: "exposure_cors_wildcard".to_string(),
            severity: Severity::Medium,
            tool: None,
            message: "server responded with Access-Control-Allow-Origin: *".to_string(),
        });
    }

    match &outcome.call_attempt {
        CallAttempt::NotRequested => {}
        CallAttempt::Skipped { reason } => findings.push(Finding {
            kind: "exposure_unauth_call_skipped".to_string(),
            severity: Severity::Info,
            tool: None,
            message: reason.clone(),
        }),
        CallAttempt::Rejected { tool } => findings.push(Finding {
            kind: "exposure_unauth_call_rejected".to_string(),
            severity: Severity::Info,
            tool: Some(tool.clone()),
            message: format!("unauthenticated tools/call to '{tool}' was rejected by the server"),
        }),
        CallAttempt::Succeeded { tool } => findings.push(Finding {
            kind: "exposure_unauth_call".to_string(),
            severity: Severity::Critical,
            tool: Some(tool.clone()),
            message: format!(
                "unauthenticated tools/call to '{tool}' succeeded — server accepts \
                 unauthenticated tool invocations"
            ),
        }),
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, description: &str) -> McpTool {
        McpTool {
            name: name.to_string(),
            description: description.to_string(),
            fingerprint: 0,
        }
    }

    #[test]
    fn host_is_local_loopback_and_hostnames() {
        assert!(host_is_local("localhost"));
        assert!(host_is_local("LOCALHOST"));
        assert!(host_is_local("127.0.0.1"));
        assert!(host_is_local("127.5.5.5"));
        assert!(host_is_local("::1"));
        assert!(!host_is_local("example.com"));
        assert!(!host_is_local("mcp.acmecorp.io"));
    }

    #[test]
    fn host_is_local_rfc1918_and_link_local() {
        assert!(host_is_local("10.0.0.5"));
        assert!(host_is_local("172.16.0.1"));
        assert!(host_is_local("172.31.255.255"));
        assert!(!host_is_local("172.32.0.1"));
        assert!(!host_is_local("172.15.255.255"));
        assert!(host_is_local("192.168.1.1"));
        assert!(!host_is_local("192.169.1.1"));
        assert!(host_is_local("169.254.1.1"));
        assert!(host_is_local("fe80::1"));
    }

    #[test]
    fn host_is_local_ipv6_unique_local() {
        // fc00::/7 (fc.. / fd..) unique-local addresses are local.
        assert!(host_is_local("fd00::1"));
        assert!(host_is_local("fc00::1"));
        // A hostname that merely starts with "fc"/"fd" but has no ':' is not
        // an IPv6 literal and must not be misclassified as local.
        assert!(!host_is_local("fc-barcelona.com"));
        assert!(!host_is_local("fdanythingnocolon.com"));
    }

    #[test]
    fn host_is_local_public_ip_literal_is_not_local() {
        assert!(!host_is_local("8.8.8.8"));
        assert!(!host_is_local("203.0.113.10"));
    }

    #[test]
    fn parse_url_host_scheme_handles_port_path_and_ipv6() {
        assert_eq!(
            parse_url_host_scheme("https://example.com:8443/mcp"),
            Some(("https".to_string(), "example.com".to_string()))
        );
        assert_eq!(
            parse_url_host_scheme("http://127.0.0.1:4200/"),
            Some(("http".to_string(), "127.0.0.1".to_string()))
        );
        assert_eq!(
            parse_url_host_scheme("http://[::1]:4200/rpc"),
            Some(("http".to_string(), "::1".to_string()))
        );
    }

    #[test]
    fn parse_url_host_scheme_ignores_at_in_path_query_fragment() {
        // An '@' anywhere after the authority (path, query, fragment) must not
        // be treated as a userinfo separator — the host is still the authority.
        assert_eq!(
            parse_url_host_scheme("https://mcp.example.com/x?cb=a@b"),
            Some(("https".to_string(), "mcp.example.com".to_string()))
        );
        assert_eq!(
            parse_url_host_scheme("https://mcp.example.com/path@segment"),
            Some(("https".to_string(), "mcp.example.com".to_string()))
        );
        assert_eq!(
            parse_url_host_scheme("https://mcp.example.com/#frag@ment"),
            Some(("https".to_string(), "mcp.example.com".to_string()))
        );
        // With a port too, so the port strip still runs after authority isolation.
        assert_eq!(
            parse_url_host_scheme("http://mcp.example.com:8443/x?cb=a@b"),
            Some(("http".to_string(), "mcp.example.com".to_string()))
        );
    }

    #[test]
    fn parse_url_host_scheme_strips_userinfo_in_authority() {
        // Genuine userinfo (`user:pass@host`) is still stripped.
        assert_eq!(
            parse_url_host_scheme("https://user:pass@mcp.example.com/rpc"),
            Some(("https".to_string(), "mcp.example.com".to_string()))
        );
        assert_eq!(
            parse_url_host_scheme("https://user@mcp.example.com:8443/rpc?x=1@2"),
            Some(("https".to_string(), "mcp.example.com".to_string()))
        );
        // Userinfo containing a bracketed IPv6 host with a port.
        assert_eq!(
            parse_url_host_scheme("http://user:pass@[fe80::1]:4200/rpc"),
            Some(("http".to_string(), "fe80::1".to_string()))
        );
    }

    #[test]
    fn parse_url_host_scheme_ipv6_with_port_and_no_port() {
        assert_eq!(
            parse_url_host_scheme("http://[::1]:4200/rpc"),
            Some(("http".to_string(), "::1".to_string()))
        );
        assert_eq!(
            parse_url_host_scheme("https://[2001:db8::1]/mcp"),
            Some(("https".to_string(), "2001:db8::1".to_string()))
        );
    }

    /// S1 hardening: a `\` inside the authority must terminate it, exactly
    /// like `/`/`?`/`#` — matching `reqwest`/`url`'s WHATWG behavior, where
    /// `\` is a path separator for "special" schemes (http/https/...).
    /// Before this fix, `\@127.0.0.1` after the real host was read as
    /// "everything up to the last `@`", so the *attacker-chosen* text after
    /// the backslash (`127.0.0.1`) was misread as the host instead of the
    /// host reqwest actually connects to (`target.example.com`).
    #[test]
    fn parse_url_host_scheme_treats_backslash_as_authority_terminator() {
        assert_eq!(
            parse_url_host_scheme(r"https://target.example.com\@127.0.0.1/rpc"),
            Some(("https".to_string(), "target.example.com".to_string())),
            "must match reqwest::Url::parse's connect host, not the text after '\\'"
        );
        assert_eq!(
            parse_url_host_scheme(r"https://a.com\b\c"),
            Some(("https".to_string(), "a.com".to_string()))
        );
    }

    /// S1 hardening (finding #7): excess `/`/`\` immediately after `://` are
    /// collapsed before authority parsing starts, mirroring
    /// `reqwest::Url::parse`'s "special authority ignore slashes" behavior —
    /// so `https:///path` lands on host `path` (matching reqwest) instead of
    /// an empty/bogus host that would silently disable classification.
    #[test]
    fn parse_url_host_scheme_collapses_excess_leading_slashes() {
        assert_eq!(
            parse_url_host_scheme("https:///path"),
            Some(("https".to_string(), "path".to_string()))
        );
        assert_eq!(
            parse_url_host_scheme("https://////evil.com/path"),
            Some(("https".to_string(), "evil.com".to_string()))
        );
    }

    #[test]
    fn plaintext_severity_medium_standalone_high_when_unauth_public() {
        let local_http = ProbeOutcome {
            scheme: "http".to_string(),
            host: "127.0.0.1".to_string(),
            unauth_list_returned: true,
            unauth_tool_count: 2,
            cors_wildcard: false,
            call_attempt: CallAttempt::NotRequested,
        };
        let local_findings = exposure_findings(&local_http);
        assert!(local_findings
            .iter()
            .all(|f| f.kind != "exposure_plaintext"));

        let public_http_authed = ProbeOutcome {
            scheme: "http".to_string(),
            host: "mcp.example.com".to_string(),
            unauth_list_returned: false,
            unauth_tool_count: 0,
            cors_wildcard: false,
            call_attempt: CallAttempt::NotRequested,
        };
        let f = exposure_findings(&public_http_authed);
        let plaintext = f.iter().find(|f| f.kind == "exposure_plaintext").unwrap();
        assert_eq!(plaintext.severity, Severity::Medium);

        let public_http_unauth = ProbeOutcome {
            scheme: "http".to_string(),
            host: "mcp.example.com".to_string(),
            unauth_list_returned: true,
            unauth_tool_count: 3,
            cors_wildcard: false,
            call_attempt: CallAttempt::NotRequested,
        };
        let f2 = exposure_findings(&public_http_unauth);
        let plaintext2 = f2.iter().find(|f| f.kind == "exposure_plaintext").unwrap();
        assert_eq!(plaintext2.severity, Severity::High);
        let unauth = f2
            .iter()
            .find(|f| f.kind == "exposure_unauth_list")
            .unwrap();
        assert_eq!(unauth.severity, Severity::High);
    }

    #[test]
    fn unauth_list_severity_info_on_local_high_on_public() {
        let local = ProbeOutcome {
            scheme: "https".to_string(),
            host: "localhost".to_string(),
            unauth_list_returned: true,
            unauth_tool_count: 1,
            cors_wildcard: false,
            call_attempt: CallAttempt::NotRequested,
        };
        let f = exposure_findings(&local);
        let finding = f.iter().find(|f| f.kind == "exposure_unauth_list").unwrap();
        assert_eq!(finding.severity, Severity::Info);

        let public = ProbeOutcome {
            scheme: "https".to_string(),
            host: "mcp.example.com".to_string(),
            unauth_list_returned: true,
            unauth_tool_count: 1,
            cors_wildcard: false,
            call_attempt: CallAttempt::NotRequested,
        };
        let f2 = exposure_findings(&public);
        let finding2 = f2
            .iter()
            .find(|f| f.kind == "exposure_unauth_list")
            .unwrap();
        assert_eq!(finding2.severity, Severity::High);
    }

    #[test]
    fn no_unauth_finding_when_list_not_returned() {
        let outcome = ProbeOutcome {
            scheme: "https".to_string(),
            host: "mcp.example.com".to_string(),
            unauth_list_returned: false,
            unauth_tool_count: 0,
            cors_wildcard: false,
            call_attempt: CallAttempt::NotRequested,
        };
        let findings = exposure_findings(&outcome);
        assert!(findings.iter().all(|f| f.kind != "exposure_unauth_list"));
    }

    #[test]
    fn cors_wildcard_finding() {
        let outcome = ProbeOutcome {
            scheme: "https".to_string(),
            host: "mcp.example.com".to_string(),
            unauth_list_returned: false,
            unauth_tool_count: 0,
            cors_wildcard: true,
            call_attempt: CallAttempt::NotRequested,
        };
        let findings = exposure_findings(&outcome);
        let f = findings
            .iter()
            .find(|f| f.kind == "exposure_cors_wildcard")
            .unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }

    /// S1 regression: `exposure_findings` classifies strictly off
    /// `outcome.scheme`/`outcome.host` — the fields the gateway fills from
    /// `reqwest::Url::parse`, i.e. the same parser that decides where the
    /// scan actually connects. A backslash-smuggled authority
    /// (`target.example.com\@127.0.0.1`) must classify against the host
    /// reqwest connects to (`target.example.com`, public), not the
    /// after-the-backslash text (`127.0.0.1`, which would wrongly suppress
    /// the finding as "local/dev, expected").
    #[test]
    fn exposure_findings_uses_authoritative_host_not_a_raw_url_reparse() {
        // Simulates what `run_exposure_probe` computes via
        // `reqwest::Url::parse("https://target.example.com\\@127.0.0.1/rpc")`
        // — scheme "https", host "target.example.com".
        let outcome = ProbeOutcome {
            scheme: "https".to_string(),
            host: "target.example.com".to_string(),
            unauth_list_returned: true,
            unauth_tool_count: 1,
            cors_wildcard: false,
            call_attempt: CallAttempt::NotRequested,
        };
        let findings = exposure_findings(&outcome);
        let f = findings
            .iter()
            .find(|f| f.kind == "exposure_unauth_list")
            .expect("expected an exposure_unauth_list finding");
        assert_eq!(
            f.severity,
            Severity::High,
            "a public host smuggled behind a backslash-prefixed userinfo-looking \
             segment must still classify as public/High, not local/Info"
        );

        // The http:// variant of the same authoritative host must also keep
        // (not drop) the plaintext finding.
        let http_outcome = ProbeOutcome {
            scheme: "http".to_string(),
            ..outcome
        };
        let http_findings = exposure_findings(&http_outcome);
        assert!(
            http_findings.iter().any(|f| f.kind == "exposure_plaintext"),
            "the plaintext finding must not be dropped for the authoritative \
             (public) host: {http_findings:?}"
        );
    }

    #[test]
    fn ssrf_keyword_detection_matches_and_excludes() {
        let tools = vec![
            tool("fetch_url", "Fetches an arbitrary URL and returns the body"),
            tool("webhook_notify", "Sends a POST to a configured webhook"),
            tool("list_files", "List files in the working directory"),
        ];
        let findings = ssrf_capable_findings(&tools);
        assert!(findings
            .iter()
            .any(|f| f.tool.as_deref() == Some("fetch_url")));
        assert!(findings
            .iter()
            .any(|f| f.tool.as_deref() == Some("webhook_notify")));
        assert!(!findings
            .iter()
            .any(|f| f.tool.as_deref() == Some("list_files")));
        assert!(findings.iter().all(|f| f.severity == Severity::Low));
    }

    #[test]
    fn call_attempt_outcomes_map_to_expected_findings() {
        let succeeded = ProbeOutcome {
            scheme: "https".to_string(),
            host: "mcp.example.com".to_string(),
            unauth_list_returned: false,
            unauth_tool_count: 0,
            cors_wildcard: false,
            call_attempt: CallAttempt::Succeeded {
                tool: "get_status".to_string(),
            },
        };
        let f = exposure_findings(&succeeded);
        let call = f.iter().find(|f| f.kind == "exposure_unauth_call").unwrap();
        assert_eq!(call.severity, Severity::Critical);
        assert_eq!(call.tool.as_deref(), Some("get_status"));

        let skipped = ProbeOutcome {
            call_attempt: CallAttempt::Skipped {
                reason: "no safe tool".to_string(),
            },
            ..succeeded_base()
        };
        let f2 = exposure_findings(&skipped);
        assert!(f2
            .iter()
            .any(|f| f.kind == "exposure_unauth_call_skipped" && f.severity == Severity::Info));

        let rejected = ProbeOutcome {
            call_attempt: CallAttempt::Rejected {
                tool: "get_status".to_string(),
            },
            ..succeeded_base()
        };
        let f3 = exposure_findings(&rejected);
        assert!(f3
            .iter()
            .any(|f| f.kind == "exposure_unauth_call_rejected" && f.severity == Severity::Info));

        assert!(exposure_findings(&ProbeOutcome {
            call_attempt: CallAttempt::NotRequested,
            ..succeeded_base()
        })
        .is_empty());
    }

    fn succeeded_base() -> ProbeOutcome {
        ProbeOutcome {
            scheme: "https".to_string(),
            host: "mcp.example.com".to_string(),
            unauth_list_returned: false,
            unauth_tool_count: 0,
            cors_wildcard: false,
            call_attempt: CallAttempt::NotRequested,
        }
    }
}
