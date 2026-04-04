"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const { ScopeError } = require("../scripts/lib/http");
const { runFfuf, runDalfox, runSqlmap, runJwtTool, runBrojack } = require("../scripts/lib/fuzzing");

// These tests validate the CONTRACT (scope enforcement, return shape, graceful
// degradation when tools are absent) — they do NOT require the actual tools to
// be installed. Tool-absent cases return a structured "not installed" result.

// ── Scope enforcement ─────────────────────────────────────────────────────────

test("runFfuf throws ScopeError for out-of-scope URL", () => {
  const scope = { in_scope: ["example.com"], out_of_scope: [] };
  assert.throws(
    () => runFfuf("https://evil.com/FUZZ", "/usr/share/wordlists/common.txt", {}, scope),
    ScopeError
  );
});

test("runDalfox throws ScopeError for out-of-scope URL", () => {
  const scope = { in_scope: ["example.com"], out_of_scope: [] };
  assert.throws(
    () => runDalfox("https://evil.com/?q=test", {}, scope),
    ScopeError
  );
});

test("runSqlmap throws ScopeError for out-of-scope URL", () => {
  const scope = { in_scope: ["example.com"], out_of_scope: [] };
  assert.throws(
    () => runSqlmap("https://evil.com/?id=1", {}, scope),
    ScopeError
  );
});

test("runBrojack throws ScopeError for out-of-scope URL", () => {
  const scope = { in_scope: ["example.com"], out_of_scope: [] };
  assert.throws(
    () => runBrojack("https://evil.com/", {}, scope),
    ScopeError
  );
});

test("runFfuf does not throw ScopeError for localhost", () => {
  // Scope check passes for localhost — tool may be absent but no ScopeError
  const scope = { in_scope: ["example.com"], out_of_scope: [] };
  assert.doesNotThrow(() => runFfuf("http://localhost:8080/FUZZ", "/tmp/list.txt", {}, scope));
});

test("runDalfox does not throw ScopeError for localhost", () => {
  const scope = { in_scope: ["example.com"], out_of_scope: [] };
  assert.doesNotThrow(() => runDalfox("http://localhost:8080/?q=test", {}, scope));
});

// ── Return shape when tool is absent ─────────────────────────────────────────

function isValidResult(r) {
  return (
    typeof r.command  === "string" &&
    typeof r.stdout   === "string" &&
    typeof r.stderr   === "string" &&
    typeof r.exitCode === "number" &&
    Array.isArray(r.findings)
  );
}

test("runFfuf returns valid result shape when tool absent", () => {
  // No scope restriction — test shape only
  const result = runFfuf("http://localhost:1/FUZZ", "/nonexistent.txt", {}, null);
  assert.ok(isValidResult(result), "result shape invalid");
});

test("runDalfox returns valid result shape when tool absent", () => {
  const result = runDalfox("http://localhost:1/?q=test", {}, null);
  assert.ok(isValidResult(result));
});

test("runSqlmap returns valid result shape when tool absent", () => {
  const result = runSqlmap("http://localhost:1/?id=1", {}, null);
  assert.ok(isValidResult(result));
});

test("runJwtTool returns valid result shape when tool absent", () => {
  const result = runJwtTool("eyJhbGciOiJIUzI1NiJ9.e30.abc");
  assert.ok(isValidResult(result));
});

test("runBrojack returns valid result shape when tool absent", () => {
  const result = runBrojack("http://localhost:1/", {}, null);
  assert.ok(isValidResult(result));
});

// ── findings always an array ──────────────────────────────────────────────────

test("findings array is always present even on error", () => {
  const tools = [
    () => runFfuf("http://localhost:1/FUZZ", "/tmp/x.txt", {}, null),
    () => runDalfox("http://localhost:1/?q=1", {}, null),
    () => runSqlmap("http://localhost:1/?id=1", {}, null),
    () => runJwtTool("eyJ.eyJ.sig"),
    () => runBrojack("http://localhost:1/", {}, null)
  ];
  for (const fn of tools) {
    const r = fn();
    assert.ok(Array.isArray(r.findings), `findings not an array for: ${r.command}`);
  }
});

// ── No scope config → no restriction ─────────────────────────────────────────

test("runFfuf with null scope does not restrict any URL", () => {
  assert.doesNotThrow(() => runFfuf("http://anywhere.com/FUZZ", "/tmp/x.txt", {}, null));
});

test("runSqlmap with null scope does not restrict any URL", () => {
  assert.doesNotThrow(() => runSqlmap("http://anywhere.com/?id=1", {}, null));
});
