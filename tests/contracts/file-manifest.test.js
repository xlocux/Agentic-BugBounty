"use strict";
const test   = require("node:test");
const assert = require("node:assert/strict");
const { validate } = require("../../scripts/lib/schema-validator");

const VALID = {
  schema_version: 2,
  generated_at:   "2026-03-31T10:00:00Z",
  target:         "acme",
  files: [
    { path: "src/app.js", size_bytes: 1234, language: "javascript", relevance_tag: "routing" }
  ]
};

test("file-manifest: valid object passes", () => {
  assert.doesNotThrow(() => validate("file-manifest", VALID));
});

test("file-manifest: missing schema_version fails", () => {
  const { schema_version, ...bad } = VALID;
  assert.throws(() => validate("file-manifest", bad));
});

test("file-manifest: wrong schema_version fails", () => {
  assert.throws(() => validate("file-manifest", { ...VALID, schema_version: 1 }));
});

test("file-manifest: invalid relevance_tag fails", () => {
  const bad = { ...VALID, files: [{ path: "x.js", language: "js", relevance_tag: "invalid_tag" }] };
  assert.throws(() => validate("file-manifest", bad));
});
