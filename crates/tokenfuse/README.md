# tokenfuse

**Runtime cost control & security for AI agents.**

TokenFuse is a drop-in proxy between your agent and its LLM/tool providers. It
enforces per-run budgets, detects runaway loops, provides a kill-switch, and
keeps secrets out of the model's context — without rewriting your agent.

TokenFuse runs as a **service**, not a library dependency. This crate is the
project's umbrella / name anchor; the gateway ships as the `tokenfuse` binary and
as Docker images:

```bash
docker run -p 4100:4100 -e TOKENFUSE_MODE=enforce ghcr.io/taipanbox/tokenfuse
```

Then point your provider client at `http://127.0.0.1:4100` and attach a few
`X-Fuse-*` headers.

- **Source & docs:** https://github.com/TAIPANBOX/tokenfuse
- **Python SDK:** `pip install tokenfuse`
- **JS/TS helpers:** `npm install tokenfuse`

Licensed under Apache-2.0.
