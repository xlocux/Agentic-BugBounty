"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const os     = require("node:os");
const fs     = require("node:fs");
const path   = require("node:path");
const { shardPath, readShard, writeShard, mergeShards, listShards } = require("../scripts/lib/candidates-shard");

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bb-shard-test-"));
}

test("shardPath returns correct filename for agent", () => {
  const p = shardPath("/findings", "auth");
  assert.ok(p.endsWith("candidates_pool_auth.json"));
});

test("shardPath throws for unknown agent", () => {
  assert.throws(() => shardPath("/findings", "unknown"), /Unknown agent/);
});

test("readShard returns empty pool when file absent", () => {
  const dir  = tmpDir();
  const pool = readShard(dir, "auth");
  assert.equal(pool.schema_version, 2);
  assert.deepEqual(pool.candidates, []);
  fs.rmSync(dir, { recursive: true });
});

test("writeShard + readShard round-trips correctly", () => {
  const dir  = tmpDir();
  const pool = {
    schema_version: 2,
    generated_at:   "2026-03-31T10:00:00Z",
    target:         "acme",
    candidates: [{ id: "c1", state: "candidate", agent: "auth", vuln_class: "jwt", severity: "high", title: "JWT none" }]
  };
  writeShard(dir, "auth", pool);
  const back = readShard(dir, "auth");
  assert.equal(back.candidates.length, 1);
  assert.equal(back.candidates[0].id, "c1");
  fs.rmSync(dir, { recursive: true });
});

test("mergeShards deduplicates by candidate ID (last write wins)", () => {
  const dir = tmpDir();

  writeShard(dir, "auth", {
    schema_version: 2, generated_at: "2026-03-31T10:00:00Z", target: "acme",
    candidates: [{ id: "c1", state: "candidate", agent: "auth", vuln_class: "jwt", severity: "high", title: "v1" }]
  });
  writeShard(dir, "inject", {
    schema_version: 2, generated_at: "2026-03-31T10:00:00Z", target: "acme",
    candidates: [
      { id: "c1", state: "confirmed", agent: "inject", vuln_class: "jwt", severity: "critical", title: "v2" },
      { id: "c2", state: "candidate", agent: "inject", vuln_class: "sqli", severity: "high", title: "SQLi" }
    ]
  });

  const merged = mergeShards(dir);
  assert.equal(merged.candidates.length, 2);
  const c1 = merged.candidates.find(c => c.id === "c1");
  assert.equal(c1.state, "confirmed", "last write (inject) should win");
  fs.rmSync(dir, { recursive: true });
});

test("listShards returns only agents with existing shard files", () => {
  const dir = tmpDir();
  writeShard(dir, "auth",   { schema_version: 2, generated_at: "", target: "", candidates: [] });
  writeShard(dir, "client", { schema_version: 2, generated_at: "", target: "", candidates: [] });
  const list = listShards(dir);
  assert.ok(list.includes("auth"));
  assert.ok(list.includes("client"));
  assert.ok(!list.includes("inject"));
  fs.rmSync(dir, { recursive: true });
});
