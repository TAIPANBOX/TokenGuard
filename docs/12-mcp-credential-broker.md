# 12 · MCP credential-broker

> Status: **implemented** — `tokenfuse mcp-broker` (gateway) + the pure core in
> `tokenfuse-core::secretbroker`.

## Why

Agents call tools through **MCP** servers, and those calls often need secrets —
a GitHub token, a database password, an API key. The dangerous default is to put
the secret *in the agent's context*: it ends up in the LLM prompt, the trace, the
model's memory, and any logs. A single prompt-injection or a poisoned tool
description can then exfiltrate it.

The broker removes the secret from the agent entirely. The agent holds only a
**handle** — `{{secret:github_token}}` — which is safe to appear anywhere. The
broker swaps the handle for the real value **at the boundary**, in the last hop
before the MCP server. The secret is never in the prompt, the trace, or the
agent's memory.

## Shape

```
  agent ──JSON-RPC──▶  ┌──────────────────────────────┐ ──▶  real MCP server
  (holds handles)      │      mcp-broker (proxy)       │      (gets real secret)
                       │  tools/call → inject secrets  │
  agent ◀──────────────│  tools/list → poisoning scan  │ ◀──
                       └──────────────────────────────┘
```

It's a JSON-RPC proxy the agent points its MCP client at (`TOKENFUSE_MCP_ADDR`,
default `127.0.0.1:4200`), forwarding to `TOKENFUSE_MCP_UPSTREAM`:

- **`tools/call`** → `secretbroker::inject_secrets` replaces every
  `{{secret:NAME}}` handle in the params with the vault's value just before
  forwarding. Unknown handles are left verbatim and logged (never silently
  emptied). Secret *values* are never logged — only counts.
- **`tools/list`** → the existing scanner (`tokenfuse_core::mcp`) checks tool
  descriptions for injection phrases / hidden characters. `TOKENFUSE_MCP_SCAN`:
  `off` · `warn` (log + annotate the response, default) · `block` (refuse the
  list with a JSON-RPC error).
- everything else is passed through unchanged.

## The vault

`TOKENFUSE_MCP_SECRETS="github_token=ghp_…,db=…"` (`name=value` pairs). The pure
`SecretVault` / `inject_secrets` in `tokenfuse-core::secretbroker` have no I/O and
are unit-tested (nested objects/arrays, missing handles, plain values untouched);
a richer vault (files, a secrets manager) plugs in behind the same type.

## Run it

```bash
TOKENFUSE_MCP_UPSTREAM=https://mcp.example.com/rpc \
TOKENFUSE_MCP_SECRETS="github_token=ghp_REAL" \
TOKENFUSE_MCP_SCAN=block \
  tokenfuse mcp-broker            # listens on 127.0.0.1:4200
```

Point the agent's MCP client at `http://127.0.0.1:4200`, and have it pass
`{{secret:github_token}}` wherever the token would go.

## Tested

- `secretbroker` unit tests: nested handle injection, missing-handle reporting,
  plain values untouched.
- `tests/mcp_broker.rs`: a `tools/call` with `{{secret:gh}}` reaches a stub
  upstream as the **real** secret (the agent only ever sent the handle); a
  poisoned `tools/list` is **blocked**.

## Also enforced

- **DLP on outgoing args** (`TOKENFUSE_MCP_DLP=off｜warn｜block`) — catches raw
  secrets an agent pasted directly into tool arguments (not via a handle), before
  injection, reusing `tokenfuse-core::dlp`.
- **Rug-pull lockfile** (`TOKENFUSE_MCP_LOCK=<file>`) — pins tool fingerprints;
  a changed tool definition on `tools/list` is flagged/blocked (`mcp::diff`).

## Response redaction + stdio (implemented)

- **Response redaction** — with `TOKENFUSE_MCP_DLP` on, secrets in a tool's
  *response* are redacted (`[REDACTED:kind]`) before reaching the agent, so a
  tool result can't leak a credential into the model's context.
- **stdio transport** — `tokenfuse mcp-broker --stdio` (or `TOKENFUSE_MCP_STDIO`)
  speaks newline-delimited JSON-RPC on stdin/stdout for MCP clients that launch a
  server as a subprocess; logs go to stderr. Both transports share `process()`.

## Related: `mcp-scan --url` exposure checks

`tokenfuse mcp-scan --url <endpoint>` (separate from the broker above) adds
server-exposure checks on top of the poisoning/rug-pull scan: unauthenticated
`tools/list`/`tools/call` reachability, plaintext transport, wildcard CORS,
and SSRF-capable tool detection (`tokenfuse-core::mcpexposure`). **This
scanner is CLI-first** — built to run against a server you own, from your own
machine. If a hosted "paste a URL, we'll scan it" service is ever built on
top of it, the scanner becomes an SSRF oracle and MUST add resolve-then-pin
IP validation (deny-list loopback/RFC1918/link-local/cloud-metadata
addresses), no cross-boundary redirect following, and per-tenant egress
sandboxing — none of which is implemented today because CLI self-scan has no
SSRF elevation. See the doc comment at the top of
`crates/core/src/mcpexposure.rs` for the full writeup.

### CI: scan your MCP server on every PR

The repo root ships a composite GitHub Action (`action.yml`) that runs
`tokenfuse mcp-scan --url <endpoint>` in CI and fails the build when a
finding meets or exceeds `--fail-on` (default `high`). It always uploads the
`ScanReport` JSON as a build artifact, even when the scan fails, so a poisoned
tool or a rug-pull diff is easy to inspect from the failed run.

```yaml
- uses: TAIPANBOX/tokenfuse@main   # pin to a tag/SHA in production
  with:
    url: https://mcp.example.com/rpc
    fail-on: high                  # critical|high|medium|low|none
    # lock-path: .mcp-scan.lock.json   # rug-pull baseline, if you keep one
    # attempt-call: "true"             # only for a server you own
```

`attempt-call` makes the scanner issue a live `tools/call`, not just
`tools/list` — only set it against a server you own, for the same reason the
CLI itself is self-scan-only (see above). See
`.github/workflows/mcp-scan-example.yml` in this repo for a full,
copy-pasteable `workflow_dispatch` template.

## Demo: see a rug pull caught live

[docs/17 · Rug-pull demo](17-rugpull-demo.md) — `cargo run --example
rugpull_demo -p tokenfuse-gateway` runs the pin-then-diff rug-pull check
above against a self-contained in-process stub server, end to end, printing
the `⛔ RUG PULL` / `Critical` output described in this doc.

## Not yet (follow-ups)

- Spawning a **child stdio MCP server** (today the broker forwards to an HTTP
  upstream from either transport).
