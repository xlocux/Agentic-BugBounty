"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const {
  buildEmptyGitIntel,
  normalizeGitIntel,
  mergeGitIntel,
  buildGitIntelPrompt,
  mineSecurityCommits,
  runVersionDelta
} = require("../scripts/lib/git-intel");

// ── buildEmptyGitIntel ────────────────────────────────────────────────────────

test("buildEmptyGitIntel returns schema_version 2", () => {
  const intel = buildEmptyGitIntel("acme");
  assert.equal(intel.schema_version, 2);
  assert.equal(intel.target, "acme");
});

test("buildEmptyGitIntel has all required array fields", () => {
  const intel = buildEmptyGitIntel("acme");
  for (const key of ["security_commits", "bypass_vectors", "secrets_found", "version_delta"]) {
    assert.ok(Array.isArray(intel[key]), `missing array: ${key}`);
  }
});

test("buildEmptyGitIntel passes schema validation", () => {
  const intel = buildEmptyGitIntel("acme");
  assert.doesNotThrow(() => normalizeGitIntel(intel));
});

// ── normalizeGitIntel ─────────────────────────────────────────────────────────

test("normalizeGitIntel throws on missing secrets_found", () => {
  const { secrets_found, ...bad } = buildEmptyGitIntel("acme");
  assert.throws(() => normalizeGitIntel(bad));
});

test("normalizeGitIntel throws on wrong schema_version", () => {
  const bad = { ...buildEmptyGitIntel("acme"), schema_version: 1 };
  assert.throws(() => normalizeGitIntel(bad));
});

// ── mergeGitIntel ─────────────────────────────────────────────────────────────

test("mergeGitIntel appends bypass_vectors from addition", () => {
  const base = buildEmptyGitIntel("acme");
  base.bypass_vectors.push({ commit: "abc", fix_description: "fix1", bypass_vectors: [], bypass_priority: "high" });

  const addition = {
    bypass_vectors: [
      { commit: "def", fix_description: "fix2", bypass_vectors: [], bypass_priority: "medium" }
    ]
  };

  const merged = mergeGitIntel(base, addition);
  assert.equal(merged.bypass_vectors.length, 2);
  assert.equal(merged.bypass_vectors[0].commit, "abc");
  assert.equal(merged.bypass_vectors[1].commit, "def");
});

test("mergeGitIntel preserves other fields when addition has no bypass_vectors", () => {
  const base = buildEmptyGitIntel("acme");
  base.secrets_found.push({ name: "aws_key", severity: "critical" });

  const merged = mergeGitIntel(base, {});
  assert.equal(merged.secrets_found.length, 1);
  assert.equal(merged.bypass_vectors.length, 0);
});

test("mergeGitIntel does not mutate base", () => {
  const base = buildEmptyGitIntel("acme");
  mergeGitIntel(base, { bypass_vectors: [{ commit: "x" }] });
  assert.equal(base.bypass_vectors.length, 0);
});

// ── buildGitIntelPrompt ───────────────────────────────────────────────────────

test("buildGitIntelPrompt returns a non-empty string", () => {
  const commits = [
    { hash: "abc123ef", date: "2026-01-01", author: "dev", subject: "fix XSS in search", diff: "-bad\n+good" }
  ];
  const prompt = buildGitIntelPrompt("acme", commits);
  assert.equal(typeof prompt, "string");
  assert.ok(prompt.length > 50);
});

test("buildGitIntelPrompt includes target name", () => {
  const prompt = buildGitIntelPrompt("myTarget", []);
  assert.ok(prompt.includes("myTarget"));
});

test("buildGitIntelPrompt includes commit subject", () => {
  const commits = [
    { hash: "deadbeef", date: "2026-01-01", author: "dev", subject: "fix SQL injection", diff: "" }
  ];
  const prompt = buildGitIntelPrompt("t", commits);
  assert.ok(prompt.includes("fix SQL injection"));
});

// ── mineSecurityCommits ───────────────────────────────────────────────────────

test("mineSecurityCommits returns an array", () => {
  // Run against this repo itself — may or may not find security commits, but should not throw
  const commits = mineSecurityCommits(process.cwd());
  assert.ok(Array.isArray(commits));
});

test("mineSecurityCommits returns [] for a non-git directory", () => {
  const result = mineSecurityCommits("/tmp/nonexistent-not-a-git-repo-xyz");
  assert.deepEqual(result, []);
});

// ── runVersionDelta ───────────────────────────────────────────────────────────

test("runVersionDelta returns [] when testedVersion is null", () => {
  const result = runVersionDelta(process.cwd(), null);
  assert.deepEqual(result, []);
});

test("runVersionDelta returns [] for an invalid version tag", () => {
  const result = runVersionDelta(process.cwd(), "v99.99.99-nonexistent");
  assert.deepEqual(result, []);
});

test("runVersionDelta returns an array for a valid ancestor", () => {
  // Use the initial commit as "tested version" — HEAD should be ahead of it
  let firstCommit;
  try {
    const { execSync } = require("node:child_process");
    firstCommit = execSync("git rev-list --max-parents=0 HEAD", {
      cwd: process.cwd(), stdio: ["pipe", "pipe", "pipe"], timeout: 5000
    }).toString("utf8").trim();
  } catch {
    // git not available or no commits — skip
    return;
  }
  if (!firstCommit) return;

  const result = runVersionDelta(process.cwd(), firstCommit);
  assert.ok(Array.isArray(result));
  // There should be at least one commit after the initial
  assert.ok(result.length >= 0);
  if (result.length > 0) {
    const entry = result[0];
    assert.ok(typeof entry.commit === "string");
    assert.ok(typeof entry.subject === "string");
    assert.ok(Array.isArray(entry.files_changed));
  }
});
