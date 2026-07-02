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

## Not yet (follow-ups)

- **Response redaction** and **stdio MCP transport** (today: HTTP JSON-RPC).
