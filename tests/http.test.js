"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const http   = require("node:http");
const { ScopeError, buildScope, isInScope, httpRequest, captureEvidence, formatRequest, formatResponse } = require("../scripts/lib/http");
const { URL } = require("node:url");

// ── ScopeError ────────────────────────────────────────────────────────────────

test("ScopeError has correct name and properties", () => {
  const e = new ScopeError("http://evil.com", "not in scope");
  assert.equal(e.name, "ScopeError");
  assert.equal(e.url, "http://evil.com");
  assert.equal(e.reason, "not in scope");
  assert.ok(e instanceof Error);
});

// ── buildScope / isInScope ────────────────────────────────────────────────────

test("buildScope allows localhost always", () => {
  const scope = buildScope({ in_scope: ["example.com"], out_of_scope: [] });
  assert.doesNotThrow(() => scope.check("http://localhost:3000/api/test"));
  assert.doesNotThrow(() => scope.check("http://127.0.0.1:8080/admin"));
});

test("buildScope allows 192.168.x.x (local network) always", () => {
  const scope = buildScope({ in_scope: ["example.com"] });
  assert.doesNotThrow(() => scope.check("http://192.168.1.100:8080/test"));
});

test("buildScope allows exact hostname match", () => {
  const scope = buildScope({ in_scope: ["example.com"], out_of_scope: [] });
  assert.doesNotThrow(() => scope.check("https://example.com/path"));
});

test("buildScope blocks hostname not in in_scope", () => {
  const scope = buildScope({ in_scope: ["example.com"], out_of_scope: [] });
  assert.throws(() => scope.check("https://evil.com/attack"), ScopeError);
});

test("buildScope allows wildcard subdomain match", () => {
  const scope = buildScope({ in_scope: ["*.example.com"], out_of_scope: [] });
  assert.doesNotThrow(() => scope.check("https://api.example.com/v1/users"));
  assert.doesNotThrow(() => scope.check("https://sub.api.example.com/test"));
});

test("buildScope wildcard does not match bare domain", () => {
  const scope = buildScope({ in_scope: ["*.example.com"], out_of_scope: [] });
  assert.throws(() => scope.check("https://example.com/"), ScopeError);
});

test("buildScope blocks out_of_scope entry even if in in_scope", () => {
  const scope = buildScope({
    in_scope:     ["example.com", "*.example.com"],
    out_of_scope: ["admin.example.com"]
  });
  assert.throws(() => scope.check("https://admin.example.com/"), ScopeError);
});

test("buildScope allows URL prefix match", () => {
  const scope = buildScope({ in_scope: ["https://github.com/myorg/"], out_of_scope: [] });
  assert.doesNotThrow(() => scope.check("https://github.com/myorg/repo"));
});

test("buildScope URL prefix does not match different path", () => {
  const scope = buildScope({ in_scope: ["https://github.com/myorg/"], out_of_scope: [] });
  assert.throws(() => scope.check("https://github.com/otherorg/repo"), ScopeError);
});

test("buildScope with empty in_scope allows everything (no restriction)", () => {
  const scope = buildScope({ in_scope: [], out_of_scope: [] });
  assert.doesNotThrow(() => scope.check("https://anywhere.com/"));
});

test("buildScope with null scopeConfig allows everything", () => {
  const scope = buildScope(null);
  assert.doesNotThrow(() => scope.check("https://anywhere.com/"));
});

test("buildScope throws ScopeError for invalid URL", () => {
  const scope = buildScope({ in_scope: ["example.com"] });
  assert.throws(() => scope.check("not-a-url"), ScopeError);
});

// ── isInScope convenience wrapper ────────────────────────────────────────────

test("isInScope returns true for in-scope URL", () => {
  assert.equal(isInScope("https://example.com/api", { in_scope: ["example.com"] }), true);
});

test("isInScope returns false for out-of-scope URL", () => {
  assert.equal(isInScope("https://evil.com/attack", { in_scope: ["example.com"] }), false);
});

test("isInScope returns true for localhost regardless of scope", () => {
  assert.equal(isInScope("http://localhost:3000/api", { in_scope: ["example.com"] }), true);
});

// ── formatRequest / formatResponse ────────────────────────────────────────────

test("formatRequest produces valid HTTP request string", () => {
  const parsed  = new URL("https://example.com/api/users?q=test");
  const output  = formatRequest("GET", parsed, { "Authorization": "Bearer tok" }, null);
  assert.ok(output.includes("GET /api/users?q=test HTTP/1.1"));
  assert.ok(output.includes("Host: example.com"));
  assert.ok(output.includes("Authorization: Bearer tok"));
});

test("formatRequest includes body when provided", () => {
  const parsed = new URL("https://example.com/api/login");
  const output = formatRequest("POST", parsed, {}, '{"user":"admin"}');
  assert.ok(output.includes('{"user":"admin"}'));
});

test("formatResponse produces valid HTTP response string", () => {
  const res = {
    statusCode:    200,
    statusMessage: "OK",
    headers:       { "content-type": "application/json" },
    body:          '{"ok":true}'
  };
  const output = formatResponse(res);
  assert.ok(output.includes("HTTP/1.1 200 OK"));
  assert.ok(output.includes("content-type: application/json"));
  assert.ok(output.includes('{"ok":true}'));
});

// ── httpRequest — live test against a local server ───────────────────────────

test("httpRequest fetches a local HTTP server", async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("hello from test server");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  try {
    const result = await httpRequest(`http://127.0.0.1:${port}/test`);
    assert.equal(result.statusCode, 200);
    assert.ok(result.body.includes("hello from test server"));
  } finally {
    server.close();
  }
});

test("httpRequest times out when server is slow", async () => {
  const server = http.createServer((_req, _res) => {
    // Never respond
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  try {
    await assert.rejects(
      () => httpRequest(`http://127.0.0.1:${port}/test`, { timeoutMs: 100 }),
      /timed out/i
    );
  } finally {
    server.close();
  }
});

// ── captureEvidence ───────────────────────────────────────────────────────────

test("captureEvidence throws ScopeError for out-of-scope URL", async () => {
  await assert.rejects(
    () => captureEvidence("https://evil.com/attack", {}, { in_scope: ["example.com"] }),
    ScopeError
  );
});

test("captureEvidence returns structured evidence for in-scope request", async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<html>test</html>");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  try {
    const evidence = await captureEvidence(
      `http://127.0.0.1:${port}/test`,
      {},
      null,
      "tool ran OK"
    );
    assert.ok(typeof evidence.request     === "string");
    assert.ok(typeof evidence.response    === "string");
    assert.equal(evidence.tool_output, "tool ran OK");
    assert.equal(evidence.statusCode, 200);
    assert.equal(evidence.scoped, true);
    assert.ok(evidence.request.includes("GET /test HTTP/1.1"));
    assert.ok(evidence.response.includes("HTTP/1.1 200"));
  } finally {
    server.close();
  }
});
