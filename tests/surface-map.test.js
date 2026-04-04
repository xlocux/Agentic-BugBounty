"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const { buildEmptySurface, mergeSurface, normalizeSurface } = require("../scripts/lib/surface-map");

test("buildEmptySurface returns schema_version 2", () => {
  const surface = buildEmptySurface("acme");
  assert.equal(surface.schema_version, 2);
  assert.equal(surface.target, "acme");
});

test("buildEmptySurface has all required category arrays", () => {
  const surface = buildEmptySurface("acme");
  const required = ["http_layer", "authentication", "authorization", "input_parsing",
                    "async_ipc", "third_party", "environment", "javascript_sinks", "external_domains"];
  for (const key of required) {
    assert.ok(Array.isArray(surface[key]), `missing array: ${key}`);
  }
});

test("mergeSurface combines entries from two surfaces", () => {
  const a = buildEmptySurface("acme");
  a.http_layer.push({ method: "GET", path: "/api/users", file: "routes.js", line: 10 });

  const b = buildEmptySurface("acme");
  b.http_layer.push({ method: "POST", path: "/api/login", file: "auth.js", line: 5 });

  const merged = mergeSurface(a, b);
  assert.equal(merged.http_layer.length, 2);
});

test("normalizeSurface passes schema validation", () => {
  const surface = buildEmptySurface("acme");
  const result = normalizeSurface(surface);
  assert.equal(result, surface);
});

test("normalizeSurface throws on invalid surface", () => {
  assert.throws(() => normalizeSurface({ schema_version: 2 }), /validation/i);
});
