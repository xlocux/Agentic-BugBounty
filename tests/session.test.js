"use strict";
const test   = require("node:test");
const assert = require("node:assert/strict");
const fs     = require("node:fs");
const os     = require("node:os");
const path   = require("node:path");

const {
  writeState,
  writeResponse,
  waitForResponse,
  buildPlanForAssetType,
  isHitlMode
} = require("../scripts/lib/session");

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "session-test-"));
}

// ── writeState ─────────────────────────────────────────────────────────────

test("writeState writes valid session.json", () => {
  const dir = tmpDir();
  const sessionPath = path.join(dir, "session.json");
  const payload = {
    schema_version: "1.0",
    request_id: 1,
    written_at: new Date().toISOString(),
    written_by: "pipeline",
    status: "awaiting_approval",
    phase: "researcher",
    asset_type: "webapp",
    plan: []
  };
  writeState(sessionPath, payload);
  const written = JSON.parse(fs.readFileSync(sessionPath, "utf8"));
  assert.equal(written.request_id, 1);
  assert.equal(written.status, "awaiting_approval");
});

test("writeState throws if required field missing", () => {
  const dir = tmpDir();
  const sessionPath = path.join(dir, "session.json");
  assert.throws(
    () => writeState(sessionPath, { schema_version: "1.0", request_id: 1 }),
    /Schema validation failed/
  );
});

test("writeState throws if written_by is not pipeline", () => {
  const dir = tmpDir();
  const sessionPath = path.join(dir, "session.json");
  assert.throws(
    () => writeState(sessionPath, {
      schema_version: "1.0", request_id: 1,
      written_at: new Date().toISOString(), written_by: "ui",
      status: "running"
    }),
    /Schema validation failed/
  );
});

// ── writeResponse ──────────────────────────────────────────────────────────

test("writeResponse writes valid session-response.json", () => {
  const dir = tmpDir();
  const responsePath = path.join(dir, "session-response.json");
  const payload = {
    schema_version: "1.0",
    request_id: 1,
    written_at: new Date().toISOString(),
    written_by: "ui",
    status: "approved",
    approved_ops: ["AUTH", "INJECT"]
  };
  writeResponse(responsePath, payload);
  const written = JSON.parse(fs.readFileSync(responsePath, "utf8"));
  assert.equal(written.status, "approved");
  assert.deepEqual(written.approved_ops, ["AUTH", "INJECT"]);
});

test("writeResponse throws if written_by is not ui", () => {
  const dir = tmpDir();
  const responsePath = path.join(dir, "session-response.json");
  assert.throws(
    () => writeResponse(responsePath, {
      schema_version: "1.0", request_id: 1,
      written_at: new Date().toISOString(), written_by: "pipeline",
      status: "approved"
    }),
    /Schema validation failed/
  );
});

// ── waitForResponse ────────────────────────────────────────────────────────

test("waitForResponse resolves when matching request_id appears", async () => {
  const dir = tmpDir();
  const responsePath = path.join(dir, "session-response.json");

  setTimeout(() => {
    fs.writeFileSync(responsePath, JSON.stringify({
      schema_version: "1.0",
      request_id: 3,
      written_at: new Date().toISOString(),
      written_by: "ui",
      status: "approved",
      approved_ops: ["AUTH"]
    }), "utf8");
  }, 400);

  const result = await waitForResponse(responsePath, 3, 3000);
  assert.equal(result.request_id, 3);
  assert.equal(result.status, "approved");
});

test("waitForResponse skips stale request_id and waits for correct one", async () => {
  const dir = tmpDir();
  const responsePath = path.join(dir, "session-response.json");

  fs.writeFileSync(responsePath, JSON.stringify({
    schema_version: "1.0", request_id: 1,
    written_at: new Date().toISOString(), written_by: "ui", status: "approved"
  }), "utf8");

  setTimeout(() => {
    fs.writeFileSync(responsePath, JSON.stringify({
      schema_version: "1.0", request_id: 2,
      written_at: new Date().toISOString(), written_by: "ui",
      status: "assets_selected", selected_assets: ["ext-main"]
    }), "utf8");
  }, 400);

  const result = await waitForResponse(responsePath, 2, 3000);
  assert.equal(result.request_id, 2);
  assert.deepEqual(result.selected_assets, ["ext-main"]);
});

test("waitForResponse rejects after timeout", async () => {
  const dir = tmpDir();
  const responsePath = path.join(dir, "session-response.json");
  await assert.rejects(
    () => waitForResponse(responsePath, 99, 600),
    /timed out/
  );
});

// ── buildPlanForAssetType ──────────────────────────────────────────────────

test("buildPlanForAssetType webapp has mandatory AUTH and INJECT", () => {
  const { plan } = buildPlanForAssetType("webapp");
  const ids = plan.map((op) => op.id);
  assert.ok(ids.includes("AUTH"),   "missing AUTH");
  assert.ok(ids.includes("INJECT"), "missing INJECT");
  const mandatoryOps = plan.filter((op) => op.mandatory);
  assert.ok(mandatoryOps.every((op) => op.mandatory === true));
});

test("buildPlanForAssetType browserext has mandatory postmessage and dom_xss", () => {
  const { plan } = buildPlanForAssetType("browserext");
  const ids = plan.map((op) => op.id);
  assert.ok(ids.includes("postmessage"), "missing postmessage");
  assert.ok(ids.includes("dom_xss"),     "missing dom_xss");
});

test("buildPlanForAssetType excludes ops listed in surfaceMap.exclude", () => {
  const { plan } = buildPlanForAssetType("webapp", { exclude: ["MEDIA", "INFRA"] });
  const ids = plan.map((op) => op.id);
  assert.ok(!ids.includes("MEDIA"), "MEDIA should be excluded");
  assert.ok(!ids.includes("INFRA"), "INFRA should be excluded");
  assert.ok(ids.includes("AUTH"),   "AUTH must stay (mandatory)");
});

test("buildPlanForAssetType throws for unknown asset type", () => {
  assert.throws(
    () => buildPlanForAssetType("unknown_type"),
    /Unknown asset_type/
  );
});

// ── isHitlMode ─────────────────────────────────────────────────────────────

test("isHitlMode returns true when args.hitl is true", () => {
  assert.equal(isHitlMode({ hitl: true }), true);
});

test("isHitlMode returns false when args.hitl is false", () => {
  assert.equal(isHitlMode({ hitl: false }), false);
});

test("isHitlMode returns false when args.hitl is absent", () => {
  assert.equal(isHitlMode({}), false);
});
