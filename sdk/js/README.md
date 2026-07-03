# tokenfuse (JS/TS SDK)

Thin, dependency-free client helpers for [TokenFuse](https://github.com/TAIPANBOX/tokenfuse)
— runtime cost control for AI agents.

TokenFuse is a drop-in proxy: you don't rewrite your agent, you point your
provider client at the gateway and attach a few `X-Fuse-*` headers. This package
builds those headers and URLs.

## Install

```bash
npm install tokenfuse
```

## Use

```js
const tf = require("tokenfuse");
const Anthropic = require("@anthropic-ai/sdk");

const client = new Anthropic({
  baseURL: tf.gatewayUrl(),                          // http://127.0.0.1:4100
  defaultHeaders: tf.runHeaders("run-42", { budgetUsd: 5.0 }),
});
```

When a run exceeds its budget (or trips a policy/loop/kill), the gateway returns
`402` with a stable JSON error contract (`budget_exceeded`, `loop_detected`,
`policy_violation`, `killed`, …) — inspect the response status/body.

## API

- `gatewayUrl(gateway?)` — base URL for the provider client.
- `messagesUrl(gateway?)` — the Anthropic-style messages endpoint.
- `runHeaders(runId, { budgetUsd, taskType, parentRunId, tags })` — the `X-Fuse-*` headers.

Ships with TypeScript types. Licensed under Apache-2.0.
