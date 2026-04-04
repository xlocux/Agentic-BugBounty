"use strict";
const test   = require("node:test");
const assert = require("node:assert/strict");
const { validate } = require("../../scripts/lib/schema-validator");

const VALID = {
  schema_version:   2,
  generated_at:     "2026-03-31T10:00:00Z",
  target:           "acme",
  http_layer:       [],
  authentication:   [],
  authorization:    [],
  input_parsing:    [],
  async_ipc:        [],
  third_party:      [],
  environment:      [],
  javascript_sinks: [],
  external_domains: []
};

test("attack-surface: valid object passes", () => {
  assert.doesNotThrow(() => validate("attack-surface", VALID));
});

test("attack-surface: missing required field fails", () => {
  const { http_layer, ...bad } = VALID;
  assert.throws(() => validate("attack-surface", bad));
});

test("attack-surface: wrong schema_version fails", () => {
  assert.throws(() => validate("attack-surface", { ...VALID, schema_version: 1 }));
});
