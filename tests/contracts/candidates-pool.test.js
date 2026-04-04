"use strict";
const test   = require("node:test");
const assert = require("node:assert/strict");
const { validate } = require("../../scripts/lib/schema-validator");

const VALID_CANDIDATE = {
  id:         "sha256:sqli:search.js:42",
  state:      "candidate",
  agent:      "inject",
  vuln_class: "sqli",
  severity:   "high",
  title:      "SQL injection in search endpoint",
  chain_id:   null,
  confidence: 0.85
};

const VALID = {
  schema_version: 2,
  generated_at:   "2026-03-31T10:00:00Z",
  target:         "acme",
  candidates:     [VALID_CANDIDATE]
};

test("candidates-pool: valid object passes", () => {
  assert.doesNotThrow(() => validate("candidates-pool", VALID));
});

test("candidates-pool: invalid state fails", () => {
  assert.throws(() => validate("candidates-pool", { ...VALID, candidates: [{ ...VALID_CANDIDATE, state: "maybe" }] }));
});

test("candidates-pool: invalid severity fails", () => {
  assert.throws(() => validate("candidates-pool", { ...VALID, candidates: [{ ...VALID_CANDIDATE, severity: "extreme" }] }));
});

test("candidates-pool: invalid agent fails", () => {
  assert.throws(() => validate("candidates-pool", { ...VALID, candidates: [{ ...VALID_CANDIDATE, agent: "unknown_agent" }] }));
});

test("candidates-pool: confidence out of range fails", () => {
  assert.throws(() => validate("candidates-pool", { ...VALID, candidates: [{ ...VALID_CANDIDATE, confidence: 1.5 }] }));
});
