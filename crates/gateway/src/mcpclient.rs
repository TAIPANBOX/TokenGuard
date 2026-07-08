//! Minimal MCP client for the live scanner (`tokenfuse mcp-scan --url`):
//! Streamable HTTP transport only. Speaks the three-message handshake
//! (`initialize` → `notifications/initialized` → `tools/list`) as single POSTs
//! against one endpoint, per the MCP Streamable HTTP transport spec.
//!
//! A server may reply to any of those POSTs with either a single JSON object
//! (`content-type: application/json`) or an SSE stream
//! (`content-type: text/event-stream`) carrying the JSON-RPC response inside
//! one of its `data:` events. This client is a bounded, one-shot RPC — it
//! buffers the SSE body in full within `total_timeout` rather than parsing it
//! incrementally — and exists to fetch a `tools/list` snapshot for scanning,
//! not to hold a long-lived session.

use std::time::Duration;

use futures::StreamExt;
use serde_json::{json, Value};

/// Default cap on a single response body the scanner will buffer, in bytes
/// (8 MiB). `total_timeout` bounds how *long* a fetch runs but not how *much*
/// it reads: a hostile/misbehaving MCP server can stream gigabytes within the
/// window and OOM the (CI-runner) scanning host. This caps the size too.
/// Overridable via `TOKENFUSE_MCP_SCAN_MAX_BODY_BYTES`.
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Config for a single live `tools/list` fetch.
pub struct McpClientConfig {
    pub url: String,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    /// Extra headers to send on every request (e.g. auth for the target MCP
    /// server). Sent as-is, in addition to `content-type` and `accept`.
    pub extra_headers: Vec<(String, String)>,
    /// Maximum response body (bytes) to buffer per request; reads beyond this
    /// abort with [`McpClientError::BodyTooLarge`] instead of growing the
    /// buffer unboundedly. See [`DEFAULT_MAX_BODY_BYTES`].
    pub max_body_bytes: usize,
}

impl McpClientConfig {
    /// Build a config for `url`, reading timeouts from
    /// `TOKENFUSE_MCP_SCAN_CONNECT_TIMEOUT_SECS` (default 5) and
    /// `TOKENFUSE_MCP_SCAN_TIMEOUT_SECS` (default 15).
    pub fn new(url: impl Into<String>) -> Self {
        let connect_secs = std::env::var("TOKENFUSE_MCP_SCAN_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let total_secs = std::env::var("TOKENFUSE_MCP_SCAN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);
        let max_body_bytes = std::env::var("TOKENFUSE_MCP_SCAN_MAX_BODY_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);
        McpClientConfig {
            url: url.into(),
            connect_timeout: Duration::from_secs(connect_secs),
            total_timeout: Duration::from_secs(total_secs),
            extra_headers: Vec::new(),
            max_body_bytes,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    #[error("request failed: {0}")]
    Transport(String),
    #[error("server returned HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("could not parse server response: {0}")]
    Parse(String),
    /// The server responded with a `content-type` this client doesn't speak
    /// (neither `application/json` nor `text/event-stream`).
    #[error("{0}")]
    UnsupportedTransport(String),
    /// The response body exceeded the configured size cap
    /// ([`McpClientConfig::max_body_bytes`]) — aborted before buffering it all,
    /// so a hostile/oversized body can't OOM the scanning host.
    #[error("response body exceeded the {limit}-byte scan cap (set TOKENFUSE_MCP_SCAN_MAX_BODY_BYTES to change)")]
    BodyTooLarge { limit: usize },
}

/// Does `content_type` (a raw `content-type` header value, possibly with a
/// `; charset=...` parameter) name `expected` as its media type? Splits on
/// `;` and trims before comparing, so e.g. `application/jsonx` or
/// `application/json-patch` don't falsely match `application/json` the way a
/// bare `starts_with` would.
fn content_type_matches(content_type: &str, expected: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case(expected)
}

/// Buffer a response body, aborting once it exceeds `max_bytes`. Streams the
/// body in chunks (rather than `resp.bytes()`, which buffers the whole thing
/// unconditionally) so an oversized/hostile body fails fast with
/// [`McpClientError::BodyTooLarge`] instead of growing the buffer without
/// bound. Applies to both the JSON and SSE response paths.
async fn read_body_capped(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, McpClientError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| McpClientError::Transport(e.to_string()))?;
        if buf.len() + chunk.len() > max_bytes {
            return Err(McpClientError::BodyTooLarge { limit: max_bytes });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Fetch a live `tools/list` snapshot over Streamable HTTP: `initialize`,
/// `notifications/initialized`, then `tools/list`, all as single POSTs to
/// `cfg.url`. Returns the raw `tools/list` JSON-RPC response value (the
/// `{"jsonrpc":..,"id":2,"result":{"tools":[...]}}` shape), which
/// `tokenfuse_core::mcp::parse_tools` accepts as-is.
pub async fn fetch_tools_list(cfg: &McpClientConfig) -> Result<Value, McpClientError> {
    let client = build_client(cfg)?;
    let mut session_id: Option<String> = None;

    // (a) initialize
    let (init_resp, sid) =
        post_rpc(&client, cfg, &initialize_request(), session_id.as_deref()).await?;
    let _ = init_resp; // handshake result body isn't needed beyond a successful round-trip
    if sid.is_some() {
        session_id = sid;
    }

    // (b) notifications/initialized — no id, no response body expected.
    send_notification(
        &client,
        cfg,
        &initialized_notification(),
        session_id.as_deref(),
    )
    .await?;

    // (c) tools/list
    let tools_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    });
    let (tools_resp, _) = post_rpc(&client, cfg, &tools_req, session_id.as_deref()).await?;
    Ok(tools_resp)
}

/// POST one JSON-RPC request expecting a JSON-RPC response, returning the
/// parsed body and any `Mcp-Session-Id` the server handed back. Thin wrapper
/// over [`post_rpc_full`] for callers (like [`fetch_tools_list`]) that don't
/// need the status/headers.
async fn post_rpc(
    client: &reqwest::Client,
    cfg: &McpClientConfig,
    req: &Value,
    session_id: Option<&str>,
) -> Result<(Value, Option<String>), McpClientError> {
    let (value, _status, _headers, sid) = post_rpc_full(client, cfg, req, session_id).await?;
    Ok((value, sid))
}

/// Like [`post_rpc`], but also returns the HTTP status and response headers
/// (lower-cased header names) of the final response — needed by the
/// exposure probe to inspect CORS headers and to distinguish "server
/// answered without auth" from "server rejected the unauthenticated
/// request" (an error `Status`/`Transport` variant vs. a 2xx body).
async fn post_rpc_full(
    client: &reqwest::Client,
    cfg: &McpClientConfig,
    req: &Value,
    session_id: Option<&str>,
) -> Result<(Value, u16, Vec<(String, String)>, Option<String>), McpClientError> {
    let resp = send(client, cfg, req, session_id).await?;
    let status = resp.status();
    let status_u16 = status.as_u16();
    let sid = resp
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_ascii_lowercase(), v.to_string()))
        })
        .collect();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = read_body_capped(resp, cfg.max_body_bytes).await?;

    if !status.is_success() {
        return Err(McpClientError::Status {
            status: status_u16,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    if content_type_matches(&content_type, "text/event-stream") {
        let text = String::from_utf8_lossy(&bytes);
        let want_id = req.get("id");
        for frame in parse_sse_frames(&text) {
            if frame.get("id") == want_id {
                return Ok((frame, status_u16, headers, sid));
            }
        }
        return Err(McpClientError::Parse(format!(
            "SSE stream ended without a response matching request id {:?}",
            want_id.unwrap_or(&Value::Null)
        )));
    }

    if !content_type_matches(&content_type, "application/json") {
        return Err(McpClientError::UnsupportedTransport(format!(
            "server responded with unsupported content-type {content_type:?}"
        )));
    }

    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| McpClientError::Parse(e.to_string()))?;
    Ok((value, status_u16, headers, sid))
}

/// Status, response headers, and parsed JSON-RPC body of a `tools/list`
/// probe — the pieces [`fetch_tools_list`] discards but the exposure checks
/// (CORS, "did it answer at all without auth") need.
pub struct ToolsListProbe {
    pub status: u16,
    /// Lower-cased header name -> value.
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

/// Run the same `initialize` → `notifications/initialized` → `tools/list`
/// handshake as [`fetch_tools_list`], but return the final response's
/// status/headers alongside its body. The exposure probe calls this with a
/// `cfg` whose `extra_headers` is empty, to test the unauthenticated path
/// regardless of whatever auth the "normal" scan connection might carry.
pub async fn fetch_tools_list_probe(
    cfg: &McpClientConfig,
) -> Result<ToolsListProbe, McpClientError> {
    let client = build_client(cfg)?;
    let mut session_id: Option<String> = None;

    let (_, sid) = post_rpc(&client, cfg, &initialize_request(), session_id.as_deref()).await?;
    if sid.is_some() {
        session_id = sid;
    }
    send_notification(
        &client,
        cfg,
        &initialized_notification(),
        session_id.as_deref(),
    )
    .await?;

    let tools_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    });
    let (body, status, headers, _) =
        post_rpc_full(&client, cfg, &tools_req, session_id.as_deref()).await?;
    Ok(ToolsListProbe {
        status,
        headers,
        body,
    })
}

/// Status and parsed JSON-RPC body of a `tools/call` probe.
pub struct ToolCallProbe {
    pub status: u16,
    pub body: Value,
}

/// Attempt a `tools/call` for `tool_name` with `arguments`, after the same
/// handshake as [`fetch_tools_list`]. Used only by the opt-in
/// `--attempt-call` exposure check — invoking a tool is inherently
/// side-effecting, so this must never run unless the operator explicitly
/// asked for it (see `mcpexposure_probe::run_exposure_probe`).
pub async fn probe_tools_call(
    cfg: &McpClientConfig,
    tool_name: &str,
    arguments: Value,
) -> Result<ToolCallProbe, McpClientError> {
    let client = build_client(cfg)?;
    let mut session_id: Option<String> = None;

    let (_, sid) = post_rpc(&client, cfg, &initialize_request(), session_id.as_deref()).await?;
    if sid.is_some() {
        session_id = sid;
    }
    send_notification(
        &client,
        cfg,
        &initialized_notification(),
        session_id.as_deref(),
    )
    .await?;

    let call_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": tool_name, "arguments": arguments },
    });
    let (body, status, _headers, _) =
        post_rpc_full(&client, cfg, &call_req, session_id.as_deref()).await?;
    Ok(ToolCallProbe { status, body })
}

fn build_client(cfg: &McpClientConfig) -> Result<reqwest::Client, McpClientError> {
    reqwest::Client::builder()
        .connect_timeout(cfg.connect_timeout)
        .timeout(cfg.total_timeout)
        // Never follow redirects (S2/SSRF): the scanned MCP server is
        // untrusted input, and reqwest's default policy follows up to 10
        // redirects to ANY host it's pointed at. A hostile server could 302
        // the scanner onto `http://169.254.169.254/...` (cloud metadata) or
        // another internal/RFC1918 address and read the probe's response
        // back out. `Policy::none()` is the safe default here — a redirect
        // from an MCP endpoint isn't something this scanner should silently
        // chase; a same-origin-only custom policy would also close the SSRF
        // hole, but "none" needs no origin-comparison logic to get right and
        // every call site already treats a 3xx as a normal error (see
        // below), so there's no behavior to preserve by allowing any
        // redirects at all.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| McpClientError::Transport(e.to_string()))
}

fn initialize_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "tokenfuse-mcp-scan",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    })
}

fn initialized_notification() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
}

/// Parse an SSE body into the JSON-RPC frames carried in its `data:` fields.
///
/// Mirrors the `data:`-line handling in `provider::UsageParser::finish`, but
/// honors the SSE spec's multi-line `data:` continuation: consecutive `data:`
/// lines within one event are joined with `\n` before parsing, and a blank
/// line ends the event. Non-`data:` fields (`event:`, `id:`, `retry:`,
/// comments) are ignored — this client only needs the JSON-RPC payload.
fn parse_sse_frames(text: &str) -> Vec<Value> {
    let mut frames = Vec::new();
    let mut data_lines: Vec<&str> = Vec::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            flush_sse_event(&mut data_lines, &mut frames);
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            // Per the SSE spec, a single leading space after the colon is
            // stripped; the rest of the line is taken verbatim.
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
        // Other fields (event:, id:, retry:, ": comment") don't carry the
        // JSON-RPC payload and are ignored.
    }
    // The body may end without a trailing blank line; flush whatever's left.
    flush_sse_event(&mut data_lines, &mut frames);

    frames
}

/// Join the buffered `data:` lines of one SSE event, parse them as a single
/// JSON value, and push the result. Malformed events (bytes that aren't
/// valid JSON — e.g. a keep-alive comment) are dropped rather than failing
/// the whole stream.
fn flush_sse_event(data_lines: &mut Vec<&str>, frames: &mut Vec<Value>) {
    if data_lines.is_empty() {
        return;
    }
    let data = data_lines.join("\n");
    data_lines.clear();
    if let Ok(v) = serde_json::from_str::<Value>(&data) {
        frames.push(v);
    }
}

/// Send a JSON-RPC notification (no `id`); the server may reply with an empty
/// 2xx body (e.g. 202 Accepted) — we don't parse it.
async fn send_notification(
    client: &reqwest::Client,
    cfg: &McpClientConfig,
    req: &Value,
    session_id: Option<&str>,
) -> Result<(), McpClientError> {
    let resp = send(client, cfg, req, session_id).await?;
    let status = resp.status();
    if !status.is_success() {
        // Cap the error body too — a hostile server could stream a huge one.
        let bytes = read_body_capped(resp, cfg.max_body_bytes)
            .await
            .unwrap_or_default();
        return Err(McpClientError::Status {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    Ok(())
}

/// Encode and POST a single JSON-RPC message. Manual encode (mirrors
/// `mcpbroker.rs`): the gateway crate does not enable reqwest's `json` feature.
async fn send(
    client: &reqwest::Client,
    cfg: &McpClientConfig,
    req: &Value,
    session_id: Option<&str>,
) -> Result<reqwest::Response, McpClientError> {
    let payload = serde_json::to_vec(req).map_err(|e| McpClientError::Parse(e.to_string()))?;
    let mut builder = client
        .post(&cfg.url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(sid) = session_id {
        builder = builder.header("Mcp-Session-Id", sid);
    }
    for (k, v) in &cfg.extra_headers {
        builder = builder.header(k, v);
    }
    builder
        .body(payload)
        .send()
        .await
        .map_err(|e| McpClientError::Transport(e.to_string()))
}
