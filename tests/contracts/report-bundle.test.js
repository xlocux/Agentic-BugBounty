"use strict";
const test   = require("node:test");
const assert = require("node:assert/strict");
const { validate } = require("../../scripts/lib/schema-validator");

const VALID_FINDING = {
  id:        "WEB-001",
  vuln_class:"sqli",
  severity:  "critical",
  title:     "SQL injection in search",
  evidence:  { request: "GET /search?q=1'", response: "HTTP/1.1 500", tool_output: "sqlmap: injectable" }
};

const VALID = {
  schema_version: 2,
  generated_at:   "2026-03-31T10:00:00Z",
  target:         "acme",
  findings:       [VALID_FINDING]
};

test("report-bundle: valid object passes", () => {
  assert.doesNotThrow(() => validate("report-bundle", VALID));
});

test("report-bundle: invalid ID format fails", () => {
  assert.throws(() => validate("report-bundle", { ...VALID, findings: [{ ...VALID_FINDING, id: "INVALID-01" }] }));
});

test("report-bundle: missing evidence.request fails", () => {
  assert.throws(() => validate("report-bundle", { ...VALID, findings: [{ ...VALID_FINDING, evidence: { response: "..." } }] }));
});

test("report-bundle: wrong schema_version fails", () => {
  assert.throws(() => validate("report-bundle", { ...VALID, schema_version: 1 }));
});
