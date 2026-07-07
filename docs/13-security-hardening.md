# 13 · Security model & hardening

> Status: **engineering hardening pass** (not an independent third-party audit).
> This documents TokenFuse's trust boundaries, the deliberate design choices that
> have security consequences, and the concrete controls that are implemented.

## What TokenFuse is (and isn't) trusted for

TokenFuse sits **in the request path** between an agent and an LLM/tool provider.
It is a control point for *cost* and *agent-runtime safety*, not a general WAF or
an authentication provider. The two honest framings:

- **In scope:** bounding spend per run, stopping runaway loops, kill-switch,
  keeping secrets out of the model's context (MCP broker), replicating budgets so
  the enforcer isn't a single point of truth, and not itself becoming a new way
  to crash or exfiltrate.
- **Out of scope:** being the *only* network control in front of a provider,
  terminating public TLS for untrusted internet clients (put a hardened reverse
  proxy in front for that), or defending against a fully-compromised host.

## Trust boundaries

```
 ┌ agent (semi-trusted) ─────────────────┐
 │  sends prompts + a run id + budget    │
 └───────────────┬───────────────────────┘
                 │  (1) request-body limit, header allow-list
                 ▼
        ┌──────────────────┐   (3) budget check in replicated SM
        │  TokenFuse gw     │───────────────────────────────┐
        │  proxy + ledger   │                                ▼
        └────────┬──────────┘                        ┌──────────────┐
                 │ (2) connect-timeout, header       │ raft peers   │
                 │     allow-list on egress          │ (mTLS+token) │
                 ▼                                    └──────────────┘
        ┌──────────────────┐
        │ LLM / MCP upstream│  (trusted target you configured)
        └──────────────────┘
```

1. **Agent → gateway** is the least-trusted edge. Controls: request-body size
   limit, an explicit forward-header allow-list (only known headers are proxied
   upstream — arbitrary client headers are dropped), and the kill-switch.
2. **Gateway → upstream** egress uses a fixed, operator-configured endpoint and a
   connect timeout so a stalled upstream can't pin a connection open forever
   during the handshake.
3. **Gateway ↔ raft peers** (HA mode) is authenticated with a shared bearer
   token and, when configured, **mutual TLS** — an unauthenticated TCP client
   can't even complete the handshake. See [10 · HA cluster](10-ha-cluster.md).

## Implemented controls

| Control | Where | Notes |
|---|---|---|
| **Request-body size limit** | `app()` in `lib.rs`, `mcpbroker::app` | `DefaultBodyLimit`, default 16 MiB, `TOKENFUSE_MAX_BODY_BYTES`. Bounds memory a single client can force the gateway to buffer. |
| **Upstream connect timeout** | `provider::HttpProvider::new` | Default 10 s, `TOKENFUSE_UPSTREAM_CONNECT_TIMEOUT_SECS`. **No** whole-request timeout — responses stream (SSE) and may run for minutes. |
| **Egress header allow-list** | `provider::FORWARD_HEADERS` | Only known headers are forwarded upstream; arbitrary client headers are dropped. |
| **Cluster auth (bearer token)** | `crates/cluster` | Every endpoint except `/healthz` requires `Authorization: Bearer <token>`. |
| **Cluster mutual TLS** | `server::serve_mtls` | Client-cert peer authentication over rustls `WebPkiClientVerifier`, on top of the token. |
| **Cloud RBAC** | `crates/cloud` | `admin` vs `viewer` roles; mutations (kill, set-budget) require `admin`. Orgs isolated by key. |
| **Secrets kept out of context** | MCP broker + DLP | `{{secret:NAME}}` handles injected only on the wire; raw-secret DLP on args; response redaction. See [12](12-mcp-credential-broker.md). |
| **Dependency audit** | CI `security` job | `cargo audit` on every push/PR, for both the workspace and `crates/cluster`. |

## OIDC bearer authentication (optional, offline)

The Cloud control plane authenticates every request at a single chokepoint. The
default credential is an API key (`TOKENFUSE_CLOUD_KEYS`, `key:org[:role][:plan]`).
Enterprises that already run an IdP can additionally accept an **OIDC ID-token /
JWT** as a bearer alternative, so their existing identities work without minting
TokenFuse keys. This is implemented in `crates/cloud/src/oidc.rs`.

- **Default OFF.** OIDC is enabled only when `TOKENFUSE_CLOUD_OIDC_ISSUER`,
  `TOKENFUSE_CLOUD_OIDC_AUDIENCE` and `TOKENFUSE_CLOUD_OIDC_JWKS` are all set.
  When unconfigured the auth path is **byte-for-byte identical** to a keys-only
  deployment — the JWT branch is never consulted.
- **Keys win.** The API-key map is tried first; a JWT is only checked when no key
  matched. A valid API key always takes precedence.
- **Offline JWKS only.** `TOKENFUSE_CLOUD_OIDC_JWKS` holds the JWKS JSON inline or
  a path to a static file. There is **no** network fetch of the issuer's
  `.well-known` document or its keys — key rotation is an ops action (update the
  env/file and restart), not a runtime HTTP call.
- **Conservative validation.** A token is accepted only if: it is a well-formed
  JWS with a `kid`; the `kid` matches a key in the configured JWKS; the signature
  verifies; `exp` is present and not past; `iss` equals the configured issuer; and
  `aud` equals the configured audience. Allowed algorithms are derived from the
  **JWK key type** (RSA ⇒ RS256/384/512, EC ⇒ ES256/384), never from the
  attacker-controlled token header — closing the RS256→HS256 "alg confusion"
  downgrade. Any failure rejects the token (`401`).
- **Least privilege.** A verified token maps to `viewer` unless the roles claim
  (`TOKENFUSE_CLOUD_OIDC_ROLES_CLAIM`, default `roles`) contains the admin role
  (`TOKENFUSE_CLOUD_OIDC_ADMIN_ROLE`, default `admin`). A missing/empty org claim
  (`TOKENFUSE_CLOUD_OIDC_ORG_CLAIM`, default `org`) is rejected — no org, no
  access. Mutations by an OIDC admin are attributed in the audit trail as
  `oidc:<sub>` (a stable, non-secret id), never the raw token.
- **Deferred (not built here):** live/networked JWKS fetch, SAML, SCIM, and
  session cookies. Those are explicitly out of scope for this pass.

## Deliberate design choices with security consequences

These are **intentional**, documented, and configurable — not oversights.

- **Fail-open enforcement.** If the ledger/consensus path errors, `reserve`
  returns a reservation rather than blocking the agent. For a component whose job
  is to *stop* runaway spend, "the enforcer had a problem, so we stopped all
  traffic" is a worse failure than "we briefly stopped enforcing". Operators who
  want fail-*closed* semantics for a specific deployment can layer that policy
  above the gateway; the default stays fail-open on purpose. (HA mode exists
  precisely to make the fail-open window rare — budgets survive a node crash.)
- **Wildcard CORS on the Cloud API.** Auth is a bearer token in a header, not a
  cookie, so a permissive `Access-Control-Allow-Origin` does not enable CSRF: a
  malicious page still has no token to send.
- **No public-internet TLS assumption for the gateway data plane.** The gateway
  is designed to sit behind your own ingress. mTLS is provided for the *cluster*
  mesh (peer-to-peer), which is the part that genuinely spans hosts.

## `cargo audit` status

The audit gate is green: **0 vulnerabilities**. wasmtime (the optional `wasm`
policy-plugin feature, off by default and not in the shipped image) was bumped
from 27 → 43 to clear a batch of advisories including two critical Cranelift/
Winch sandbox-escape issues. Three transitive **unmaintained** *warnings* remain
(`paste`, `number_prefix`, `rustls-pemfile`) — informational, not
vulnerabilities, and none are on the request path in a way that affects safety.

## Explicitly not claimed

- This is an internal engineering hardening pass, **not** an independent security
  audit or a penetration test.
- No formal verification of the raft state machine beyond the property tests.
- Rate-limiting per-client is **not** built in — run the gateway behind an
  ingress/proxy that provides it if you expose it to untrusted callers. (Body
  limits and connect timeouts bound per-request resource use; they are not a
  substitute for request-rate limiting.)
