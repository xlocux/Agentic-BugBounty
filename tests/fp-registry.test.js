"use strict";

const assert = require("node:assert/strict");
const { describe, it, before, after } = require("node:test");
const fs   = require("node:fs");
const path = require("node:path");
const os   = require("node:os");

const { persistRejectedCandidates, buildFpContext } = require("../scripts/lib/fp-registry");

// ── helpers ───────────────────────────────────────────────────────────────────

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "fp-test-"));
}

function makeDb(tmpDir) {
  const { openDatabase } = require("../scripts/lib/db");
  const dbPath = path.join(tmpDir, "test.db");
  return openDatabase(dbPath);
}

function writeCandidates(findingsDir, candidates) {
  const unconfirmed = path.join(findingsDir, "unconfirmed");
  fs.mkdirSync(unconfirmed, { recursive: true });
  fs.writeFileSync(
    path.join(unconfirmed, "candidates.json"),
    JSON.stringify({ schema_version: 2, candidates }),
    "utf8"
  );
}

// ── persistRejectedCandidates ─────────────────────────────────────────────────

describe("persistRejectedCandidates", () => {
  let tmpDir, db;

  before(() => {
    tmpDir = makeTempDir();
    db = makeDb(tmpDir);
  });

  after(() => {
    try { db.close(); } catch { /* ignore */ }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns 0 when candidates.json does not exist", () => {
    const missingDir = path.join(tmpDir, "missing");
    fs.mkdirSync(missingDir, { recursive: true });
    const count = persistRejectedCandidates(db, missingDir, "target-a", "run-1");
    assert.equal(count, 0);
  });

  it("returns 0 when candidates.json is empty / malformed", () => {
    const findingsDir = path.join(tmpDir, "bad-json");
    const unconfirmed = path.join(findingsDir, "unconfirmed");
    fs.mkdirSync(unconfirmed, { recursive: true });
    fs.writeFileSync(path.join(unconfirmed, "candidates.json"), "not-json", "utf8");
    const count = persistRejectedCandidates(db, findingsDir, "target-a", "run-2");
    assert.equal(count, 0);
  });

  it("ignores non-rejected candidates", () => {
    const findingsDir = path.join(tmpDir, "no-rejected");
    writeCandidates(findingsDir, [
      { state: "confirmed", vuln_class: "xss" },
      { state: "candidate", vuln_class: "sqli" }
    ]);
    const count = persistRejectedCandidates(db, findingsDir, "target-a", "run-3");
    assert.equal(count, 0);
  });

  it("persists rejected candidates and returns count", () => {
    const findingsDir = path.join(tmpDir, "has-rejected");
    writeCandidates(findingsDir, [
      {
        state: "rejected",
        vuln_class: "xss",
        false_positive_reason: "output_encoded",
        source: { file: "src/view.js", line: 42 },
        agent: "CLIENT"
      },
      {
        state: "rejected",
        vuln_class: "sqli",
        skepticism_gate: { reachability: "fail" }
      },
      { state: "confirmed", vuln_class: "idor" }
    ]);
    const count = persistRejectedCandidates(db, findingsDir, "target-b", "run-4");
    assert.equal(count, 2);
  });
});

// ── buildFpContext ────────────────────────────────────────────────────────────

describe("buildFpContext", () => {
  let tmpDir, db;

  before(() => {
    tmpDir = makeTempDir();
    db = makeDb(tmpDir);
    // Seed some FP entries
    const { writeFpEntry } = require("../scripts/lib/db");
    for (let i = 0; i < 3; i++) {
      writeFpEntry(db, {
        vuln_class: "xss",
        rejection_reason: "output_encoded",
        detail: "template auto-escaping",
        target: "test-target",
        run_id: "run-ctx"
      });
    }
    writeFpEntry(db, {
      vuln_class: "xss",
      rejection_reason: "csp_blocked",
      detail: "strict CSP header",
      target: "test-target",
      run_id: "run-ctx"
    });
  });

  after(() => {
    try { db.close(); } catch { /* ignore */ }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns non-empty string for seeded vuln class", () => {
    const ctx = buildFpContext(db, "xss");
    assert.ok(typeof ctx === "string");
    assert.ok(ctx.includes("KNOWN FALSE POSITIVE PATTERNS"), ctx);
    assert.ok(ctx.includes("output_encoded"), ctx);
  });

  it("includes count indicator (x3)", () => {
    const ctx = buildFpContext(db, "xss");
    assert.ok(ctx.includes("[x3]") || ctx.includes("[x"), ctx);
  });

  it("returns empty string for unknown vuln class", () => {
    const ctx = buildFpContext(db, "nonexistent_vuln_xyz");
    assert.equal(ctx, "");
  });
});
