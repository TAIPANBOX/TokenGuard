"use strict";

/**
 * TokenFuse JS/TS SDK — thin helpers to route an agent's LLM calls through the
 * TokenFuse gateway. TokenFuse is a drop-in proxy: point your provider client at
 * the gateway and attach a few `X-Fuse-*` headers.
 *
 * Pure, dependency-free. Mirrors the Python SDK's helpers.
 */

const DEFAULT_GATEWAY = "http://127.0.0.1:4100";

/** Base URL to hand to a provider client's `baseURL`. */
function gatewayUrl(gateway = DEFAULT_GATEWAY) {
  return gateway.replace(/\/+$/, "");
}

/** Full URL of the Anthropic-style messages endpoint. */
function messagesUrl(gateway = DEFAULT_GATEWAY) {
  return `${gatewayUrl(gateway)}/v1/messages`;
}

/**
 * Build the `X-Fuse-*` attribution headers for a run. Only `runId` is required;
 * without it the gateway treats a call as an unmanaged pass-through.
 *
 * @param {string} runId
 * @param {{budgetUsd?: number, taskType?: string, parentRunId?: string, tags?: Record<string,string>}} [opts]
 * @returns {Record<string,string>}
 */
function runHeaders(runId, opts = {}) {
  const { budgetUsd, taskType, parentRunId, tags } = opts;
  /** @type {Record<string,string>} */
  const headers = { "X-Fuse-Run-Id": runId };
  if (budgetUsd !== undefined && budgetUsd !== null) {
    headers["X-Fuse-Budget-Usd"] = String(Number(budgetUsd));
  }
  if (taskType) headers["X-Fuse-Task-Type"] = taskType;
  if (parentRunId) headers["X-Fuse-Parent-Run-Id"] = parentRunId;
  if (tags && Object.keys(tags).length) {
    headers["X-Fuse-Tags"] = Object.entries(tags)
      .map(([k, v]) => `${k}=${v}`)
      .join(",");
  }
  return headers;
}

module.exports = {
  VERSION: "0.3.0",
  DEFAULT_GATEWAY,
  gatewayUrl,
  messagesUrl,
  runHeaders,
};
