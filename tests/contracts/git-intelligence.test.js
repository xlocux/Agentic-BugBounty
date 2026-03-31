"use strict";
const test   = require("node:test");
const assert = require("node:assert/strict");
const { validate } = require("../../scripts/lib/schema-validator");

const VALID = {
  schema_version:   2,
  generated_at:     "2026-03-31T10:00:00Z",
  target:           "acme",
  security_commits: [],
  bypass_vectors:   [],
  secrets_found:    [],
  version_delta:    []
};

test("git-intelligence: valid object passes", () => {
  assert.doesNotThrow(() => validate("git-intelligence", VALID));
});

test("git-intelligence: missing secrets_found fails", () => {
  const { secrets_found, ...bad } = VALID;
  assert.throws(() => validate("git-intelligence", bad));
});

test("git-intelligence: wrong schema_version fails", () => {
  assert.throws(() => validate("git-intelligence", { ...VALID, schema_version: 1 }));
});
