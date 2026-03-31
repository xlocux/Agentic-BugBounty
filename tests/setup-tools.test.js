"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const { detectOS, detectPackageManagers, isToolInstalled, buildToolStatus } = require("../scripts/lib/tool-registry");

test("detectOS returns one of: linux, win32, darwin", () => {
  const os = detectOS();
  assert.ok(["linux", "win32", "darwin"].includes(os), `unexpected OS: ${os}`);
});

test("detectPackageManagers returns an array of strings", () => {
  const mgrs = detectPackageManagers();
  assert.ok(Array.isArray(mgrs));
  assert.ok(mgrs.length > 0, "should detect at least one package manager");
});

test("isToolInstalled returns true for node (always present)", () => {
  const found = isToolInstalled("node");
  assert.equal(found, true);
});

test("isToolInstalled returns false for a nonsense binary", () => {
  const found = isToolInstalled("xxxxxxxxxnotarealbin");
  assert.equal(found, false);
});

test("buildToolStatus returns object with required fields per tool", () => {
  const status = buildToolStatus();
  assert.ok(typeof status === "object");
  // Every entry must have installed + path fields
  for (const [name, entry] of Object.entries(status)) {
    assert.ok("installed" in entry, `${name} missing 'installed'`);
    assert.ok("path" in entry,      `${name} missing 'path'`);
  }
});

test("buildToolStatus marks node as installed", () => {
  const status = buildToolStatus();
  assert.ok(status.node?.installed === true);
});
