"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const path   = require("node:path");
const os     = require("node:os");
const fs     = require("node:fs");
const { classifyFiles, buildManifest, walkDir, runFileTriage, EXCLUDE_PATTERNS } = require("../scripts/lib/file-triage");

// ── classifyFiles ─────────────────────────────────────────────────────────────

test("classifyFiles excludes node_modules paths", () => {
  const files = ["node_modules/lodash/index.js", "src/app.js"];
  const result = classifyFiles(files);
  assert.ok(!result.some(f => f.path.includes("node_modules")));
  assert.ok(result.some(f => f.path === "src/app.js"));
});

test("classifyFiles excludes dist and build paths", () => {
  const files = ["dist/bundle.js", "build/output.js", "src/index.js"];
  const result = classifyFiles(files);
  assert.equal(result.filter(f => f.path.startsWith("dist") || f.path.startsWith("build")).length, 0);
});

test("classifyFiles excludes all lockfiles", () => {
  const files = [
    "package-lock.json", "composer.lock", "Pipfile.lock",
    "yarn.lock", "poetry.lock", "go.sum",
    "src/db.js"
  ];
  const result = classifyFiles(files);
  assert.equal(result.length, 1);
  assert.equal(result[0].path, "src/db.js");
});

test("classifyFiles excludes binary assets", () => {
  const files = ["assets/logo.png", "fonts/roboto.woff2", "src/upload.js"];
  const result = classifyFiles(files);
  assert.ok(!result.some(f => f.path.match(/\.(png|jpg|gif|svg|woff|woff2|ttf|eot|ico|pdf)$/)));
});

test("classifyFiles includes source files", () => {
  const files = ["src/auth.js", "app/models/user.php", "routes/api.py", "controllers/main.go"];
  const result = classifyFiles(files);
  assert.equal(result.length, 4);
});

test("classifyFiles detects language from extension", () => {
  const files = ["src/auth.js", "app/user.php", "api/routes.py", "cmd/main.go"];
  const result = classifyFiles(files);
  const js  = result.find(f => f.path === "src/auth.js");
  const php = result.find(f => f.path === "app/user.php");
  assert.equal(js.language, "javascript");
  assert.equal(php.language, "php");
});

// ── buildManifest ─────────────────────────────────────────────────────────────

test("buildManifest returns schema_version 2", () => {
  const manifest = buildManifest("acme", []);
  assert.equal(manifest.schema_version, 2);
});

test("buildManifest includes target name", () => {
  const manifest = buildManifest("acme", []);
  assert.equal(manifest.target, "acme");
});

// ── relevance_tag ─────────────────────────────────────────────────────────────

test("classifyFiles returns relevance_tag for each file", () => {
  const files = ["src/auth.js", "app/user.php"];
  const result = classifyFiles(files);
  for (const f of result) {
    assert.ok(typeof f.relevance_tag === "string" && f.relevance_tag.length > 0,
      `expected non-empty relevance_tag, got: ${f.relevance_tag}`);
  }
});

// ── walkDir ───────────────────────────────────────────────────────────────────

test("walkDir returns relative paths for all files in a directory", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "triage-"));
  fs.writeFileSync(path.join(tmp, "app.js"), "");
  fs.mkdirSync(path.join(tmp, "sub"));
  fs.writeFileSync(path.join(tmp, "sub", "auth.js"), "");

  const result = walkDir(tmp);
  assert.ok(result.includes("app.js"), "should find app.js");
  assert.ok(result.includes("sub/auth.js"), "should find sub/auth.js");

  // Cleanup
  fs.rmSync(tmp, { recursive: true });
});

// ── runFileTriage ─────────────────────────────────────────────────────────────

test("runFileTriage returns manifest with schema_version 2 and relative paths", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "triage-"));
  fs.writeFileSync(path.join(tmp, "auth.js"), "");
  fs.writeFileSync(path.join(tmp, "package-lock.json"), "");

  const manifest = runFileTriage("testpkg", tmp);
  assert.equal(manifest.schema_version, 2);
  assert.equal(manifest.target, "testpkg");
  // package-lock.json excluded, auth.js included
  assert.ok(manifest.files.some(f => f.path === "auth.js"), "auth.js should be in manifest");
  assert.ok(!manifest.files.some(f => f.path === "package-lock.json"), "lockfile should be excluded");
  // All paths are relative (no absolute path components)
  for (const f of manifest.files) {
    assert.ok(!path.isAbsolute(f.path), `path should be relative: ${f.path}`);
  }

  // Cleanup
  fs.rmSync(tmp, { recursive: true });
});
