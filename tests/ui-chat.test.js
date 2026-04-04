"use strict";
const test   = require("node:test");
const assert = require("node:assert/strict");

const { buildSystemPrompt, buildMessages } = require("../scripts/lib/ui-chat");

test("buildSystemPrompt includes target and findings", () => {
  const ctx = {
    target: "acme", asset_type: "webapp",
    active_run: null,
    recent_findings: [{ id: "WEB-001", title: "SQLi", severity: "Critical" }],
    recent_logs: []
  };
  const prompt = buildSystemPrompt(ctx);
  assert.ok(prompt.includes("acme"));
  assert.ok(prompt.includes("webapp"));
  assert.ok(prompt.includes("WEB-001"));
  assert.ok(prompt.includes("SQLi"));
});

test("buildMessages returns array with system + user turns", () => {
  const msgs = buildMessages("What is the most critical finding?", {
    target: "acme", asset_type: "webapp",
    active_run: null, recent_findings: [], recent_logs: []
  });
  assert.ok(Array.isArray(msgs));
  assert.equal(msgs[0].role, "user");
  assert.ok(msgs[0].content.includes("What is the most critical finding?"));
});

test("streamChatResponse calls onError when API key missing", (t, done) => {
  const { streamChatResponse } = require("../scripts/lib/ui-chat");
  const origKey = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;

  streamChatResponse("hello", {}, () => {}, (err) => {
    assert.ok(err);
    assert.ok(err.message.includes("ANTHROPIC_API_KEY"));
    process.env.ANTHROPIC_API_KEY = origKey;
    done();
  });
});
