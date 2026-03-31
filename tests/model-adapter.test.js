"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const path   = require("node:path");

// Point at test config so we don't depend on the real config/apis.json
process.env.APIS_CONFIG_PATH = path.resolve(__dirname, "fixtures/apis-test.json");

const { resolveModel, listRoles } = require("../scripts/lib/model-adapter");

test("resolveModel returns a model ID string for known role", () => {
  const model = resolveModel("researcher");
  assert.ok(typeof model === "string" && model.length > 0, "should return non-empty string");
});

test("resolveModel returns a model ID for coordinator role", () => {
  const model = resolveModel("coordinator");
  assert.ok(typeof model === "string" && model.length > 0);
});

test("resolveModel returns a model ID for triage role", () => {
  const model = resolveModel("triage");
  assert.ok(typeof model === "string" && model.length > 0);
});

test("resolveModel throws for unknown role", () => {
  assert.throws(() => resolveModel("nonexistent_role"), /unknown role/i);
});

test("listRoles returns an array of role names", () => {
  const roles = listRoles();
  assert.ok(Array.isArray(roles));
  assert.ok(roles.includes("researcher"));
  assert.ok(roles.includes("coordinator"));
  assert.ok(roles.includes("triage"));
});
