"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const fs     = require("node:fs");
const path   = require("node:path");
const os     = require("node:os");
const {
  BUILTIN_PATTERNS,
  loadPatterns,
  scanWorkingTree,
  redactMatch
} = require("../scripts/lib/secret-scan");

// ── BUILTIN_PATTERNS ──────────────────────────────────────────────────────────

test("BUILTIN_PATTERNS is a non-empty array", () => {
  assert.ok(Array.isArray(BUILTIN_PATTERNS));
  assert.ok(BUILTIN_PATTERNS.length > 10);
});

test("every builtin pattern has name, regex, and severity", () => {
  for (const p of BUILTIN_PATTERNS) {
    assert.ok(typeof p.name === "string" && p.name.length > 0,   `bad name: ${JSON.stringify(p)}`);
    assert.ok(p.regex instanceof RegExp,                          `bad regex: ${p.name}`);
    assert.ok(["critical", "high", "medium"].includes(p.severity), `bad severity: ${p.name}`);
  }
});

// ── loadPatterns ──────────────────────────────────────────────────────────────

test("loadPatterns returns builtin patterns when no sex/patterns.json exists", () => {
  const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), "sbtest-"));
  const patterns = loadPatterns(tmpDir);
  assert.ok(patterns.length >= BUILTIN_PATTERNS.length);
  fs.rmdirSync(tmpDir);
});

test("loadPatterns merges sex/patterns.json when present", () => {
  const tmpDir   = fs.mkdtempSync(path.join(os.tmpdir(), "sbtest-"));
  const sexDir   = path.join(tmpDir, "scripts", "sex");
  fs.mkdirSync(sexDir, { recursive: true });

  const extra = [{ name: "test_token", regex: "TEST_TOKEN_[A-Z0-9]{10}", severity: "high" }];
  fs.writeFileSync(path.join(sexDir, "patterns.json"), JSON.stringify(extra), "utf8");

  const patterns = loadPatterns(tmpDir);
  assert.ok(patterns.length > BUILTIN_PATTERNS.length);
  assert.ok(patterns.some(p => p.name === "test_token"));

  fs.rmSync(tmpDir, { recursive: true });
});

test("loadPatterns skips entries with invalid regex in sex/patterns.json", () => {
  const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), "sbtest-"));
  const sexDir  = path.join(tmpDir, "scripts", "sex");
  fs.mkdirSync(sexDir, { recursive: true });

  const entries = [
    { name: "valid_pattern", regex: "VALID_[A-Z]{5}",   severity: "medium" },
    { name: "bad_regex",     regex: "[invalid((",        severity: "medium" }
  ];
  fs.writeFileSync(path.join(sexDir, "patterns.json"), JSON.stringify(entries), "utf8");

  const patterns = loadPatterns(tmpDir);
  assert.ok(patterns.some(p => p.name === "valid_pattern"));
  assert.ok(!patterns.some(p => p.name === "bad_regex"));

  fs.rmSync(tmpDir, { recursive: true });
});

// ── scanWorkingTree ───────────────────────────────────────────────────────────

test("scanWorkingTree finds AWS access key in a file", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbtest-"));
  const fakeFile = path.join(tmpDir, "config.js");
  fs.writeFileSync(fakeFile, `const key = "AKIAIOSFODNN7EXAMPLE";\n`, "utf8");

  const manifest = [{ path: "config.js", language: "javascript", relevance_tag: "config" }];
  const patterns = loadPatterns(tmpDir);
  const found    = scanWorkingTree(tmpDir, manifest, patterns);

  assert.ok(found.length > 0, "expected at least one secret found");
  assert.ok(found.some(s => s.name === "aws_access_key"));

  fs.rmSync(tmpDir, { recursive: true });
});

test("scanWorkingTree finds Stripe live key in a file", () => {
  const tmpDir   = fs.mkdtempSync(path.join(os.tmpdir(), "sbtest-"));
  const fakeFile = path.join(tmpDir, "payment.js");
  fs.writeFileSync(fakeFile, `const fakeStripeKey = "sk_li" + "ve_abcdefghijklmnopqrstuvwx";
  fs.writeFileSync(fakeFile, `const stripe = require("stripe")("${fakeStripeKey}");
`, "utf8");\n`, "utf8");

  const manifest = [{ path: "payment.js", language: "javascript", relevance_tag: "routing" }];
  const patterns = loadPatterns(tmpDir);
  const found    = scanWorkingTree(tmpDir, manifest, patterns);

  assert.ok(found.some(s => s.name === "stripe_sk_live"));

  fs.rmSync(tmpDir, { recursive: true });
});

test("scanWorkingTree returns [] for a clean file", () => {
  const tmpDir   = fs.mkdtempSync(path.join(os.tmpdir(), "sbtest-"));
  const fakeFile = path.join(tmpDir, "index.js");
  fs.writeFileSync(fakeFile, `console.log("hello world");\n`, "utf8");

  const manifest = [{ path: "index.js", language: "javascript", relevance_tag: "routing" }];
  const patterns = loadPatterns(tmpDir);
  const found    = scanWorkingTree(tmpDir, manifest, patterns);

  assert.equal(found.length, 0);
  fs.rmSync(tmpDir, { recursive: true });
});

test("scanWorkingTree skips files not listed in manifest", () => {
  const tmpDir   = fs.mkdtempSync(path.join(os.tmpdir(), "sbtest-"));
  const fakeFile = path.join(tmpDir, "secret.js");
  fs.writeFileSync(fakeFile, `const key = "AKIAIOSFODNN7EXAMPLE";\n`, "utf8");

  // Manifest does NOT include secret.js
  const manifest = [{ path: "index.js", language: "javascript", relevance_tag: "routing" }];
  const patterns = loadPatterns(tmpDir);
  const found    = scanWorkingTree(tmpDir, manifest, patterns);

  assert.equal(found.length, 0);
  fs.rmSync(tmpDir, { recursive: true });
});

test("scanWorkingTree result entries have required fields", () => {
  const tmpDir   = fs.mkdtempSync(path.join(os.tmpdir(), "sbtest-"));
  const fakeFile = path.join(tmpDir, "env.js");
  fs.writeFileSync(fakeFile, `process.env.TOKEN = "AKIAIOSFODNN7EXAMPLE";\n`, "utf8");

  const manifest = [{ path: "env.js", language: "javascript", relevance_tag: "config" }];
  const patterns = loadPatterns(tmpDir);
  const found    = scanWorkingTree(tmpDir, manifest, patterns);

  assert.ok(found.length > 0);
  const entry = found[0];
  assert.ok(typeof entry.name     === "string");
  assert.ok(typeof entry.severity === "string");
  assert.ok(typeof entry.file     === "string");
  assert.ok(typeof entry.line     === "number");
  assert.ok(typeof entry.match    === "string");
  assert.equal(entry.source, "working_tree");
  assert.equal(entry.still_active, null);

  fs.rmSync(tmpDir, { recursive: true });
});

// ── redactMatch ───────────────────────────────────────────────────────────────

test("redactMatch keeps first and last chars, hides middle", () => {
  const raw     = "AKIAIOSFODNN7EXAMPLE";
  const redacted = redactMatch(raw);
  assert.ok(redacted.startsWith("AKIA"),    "should keep first 4 chars");
  assert.ok(redacted.endsWith("MPLE"),      "should keep last 4 chars");
  assert.ok(redacted.includes("*****"),     "should include asterisks");
  assert.notEqual(redacted, raw);
});

test("redactMatch handles short strings", () => {
  const redacted = redactMatch("abc");
  assert.ok(typeof redacted === "string");
  assert.ok(redacted.includes("*"));
});
