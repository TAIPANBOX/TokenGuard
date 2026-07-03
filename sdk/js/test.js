"use strict";

// Minimal dependency-free test (node test.js) — asserts the header/URL helpers.
const assert = require("assert");
const tf = require("./index.js");

assert.strictEqual(tf.gatewayUrl("http://x:4100/"), "http://x:4100");
assert.strictEqual(tf.messagesUrl("http://x:4100"), "http://x:4100/v1/messages");

const h = tf.runHeaders("run-42", {
  budgetUsd: 5,
  taskType: "chat",
  parentRunId: "run-1",
  tags: { team: "core", env: "dev" },
});
assert.strictEqual(h["X-Fuse-Run-Id"], "run-42");
assert.strictEqual(h["X-Fuse-Budget-Usd"], "5");
assert.strictEqual(h["X-Fuse-Task-Type"], "chat");
assert.strictEqual(h["X-Fuse-Parent-Run-Id"], "run-1");
assert.strictEqual(h["X-Fuse-Tags"], "team=core,env=dev");

// runId-only → just the id header.
assert.deepStrictEqual(tf.runHeaders("solo"), { "X-Fuse-Run-Id": "solo" });

console.log("ok - tokenfuse js sdk");
