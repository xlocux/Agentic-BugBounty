"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  REDACT_PATTERNS,
  redactString,
  redactEvidence,
  redactLogLine,
  redactBundle
} = require("../scripts/lib/redact");

// ── redactString ─────────────────────────────────────────────────────────────

describe("redactString", () => {
  it("redacts Authorization header", () => {
    const out = redactString("Authorization: Bearer eyJsometoken");
    assert.ok(out.includes("[REDACTED]"), out);
    assert.ok(!out.includes("eyJsometoken"), out);
  });

  it("redacts Cookie header", () => {
    const out = redactString("Cookie: session=abc123; other=val");
    assert.ok(out.includes("[REDACTED]"), out);
    assert.ok(!out.includes("abc123"), out);
  });

  it("redacts AWS Access Key ID", () => {
    const out = redactString("key: AKIAIOSFODNN7EXAMPLE");
    assert.ok(out.includes("AKIA[REDACTED]"), out);
    assert.ok(!out.includes("IOSFODNN7EXAMPLE"), out);
  });

  it("redacts JWT token", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const out = redactString(jwt);
    assert.ok(out.includes("[JWT_REDACTED]"), out);
  });

  it("redacts password in JSON-style key=value", () => {
    const out = redactString('{"password": "supersecret123"}');
    assert.ok(out.includes("[REDACTED]"), out);
    assert.ok(!out.includes("supersecret123"), out);
  });

  it("redacts Stripe live key", () => {
    // split to avoid triggering GitHub secret scanning on the test file itself
    const fakeKey = "sk_li" + "ve_abcdefghijklmnopqrstuvwx";
    const out = redactString(fakeKey);
    assert.ok(out.includes("sk_live_[REDACTED]"), out);
  });

  it("redacts X-API-Key header", () => {
    const out = redactString("X-API-Key: my-secret-api-key-value");
    assert.ok(out.includes("[REDACTED]"), out);
    assert.ok(!out.includes("my-secret-api-key-value"), out);
  });

  it("returns non-string input unchanged", () => {
    assert.equal(redactString(null), null);
    assert.equal(redactString(undefined), undefined);
  });

  it("does not mutate text without sensitive patterns", () => {
    const plain = "GET /api/users HTTP/1.1\nHost: example.com";
    assert.equal(redactString(plain), plain);
  });
});

// ── redactEvidence ────────────────────────────────────────────────────────────

describe("redactEvidence", () => {
  it("redacts request, response, and tool_output fields", () => {
    const ev = {
      request:     "Authorization: Bearer secret123abc",
      response:    "Set-Cookie: token=abc123def456; Path=/",
      tool_output: "password=mysecretpass99"
    };
    const out = redactEvidence(ev);
    assert.ok(!out.request.includes("secret123abc"));
    assert.ok(!out.response.includes("abc123def456"));
    assert.ok(!out.tool_output.includes("mysecretpass99"));
  });

  it("does not mutate the original object", () => {
    const ev = { request: "Authorization: Bearer tok", response: "ok" };
    const out = redactEvidence(ev);
    assert.notEqual(out, ev);
    assert.ok(ev.request.includes("Bearer tok"));
  });

  it("handles missing fields gracefully", () => {
    const ev = { request: "GET /foo" };
    const out = redactEvidence(ev);
    assert.equal(out.response, undefined);
    assert.equal(out.tool_output, undefined);
  });

  it("returns non-object input unchanged", () => {
    assert.equal(redactEvidence(null), null);
    assert.equal(redactEvidence("string"), "string");
  });
});

// ── redactLogLine ─────────────────────────────────────────────────────────────

describe("redactLogLine", () => {
  it("redacts a single log line", () => {
    const line = "[INFO] Authorization: Bearer mytoken123";
    const out = redactLogLine(line);
    assert.ok(out.includes("[REDACTED]"), out);
    assert.ok(!out.includes("mytoken123"), out);
  });
});

// ── redactBundle ─────────────────────────────────────────────────────────────

describe("redactBundle", () => {
  it("redacts evidence in all findings", () => {
    const bundle = {
      findings: [
        {
          id: "WEB-001",
          evidence: { request: "Authorization: Bearer tok1", response: "200 OK" }
        },
        {
          id: "WEB-002",
          evidence: { request: "GET /foo", response: "X-Auth-Token: secret99" }
        }
      ]
    };
    const out = redactBundle(bundle);
    assert.ok(!out.findings[0].evidence.request.includes("tok1"));
    assert.ok(!out.findings[1].evidence.response.includes("secret99"));
    // originals unchanged
    assert.ok(bundle.findings[0].evidence.request.includes("tok1"));
  });

  it("handles findings without evidence", () => {
    const bundle = { findings: [{ id: "WEB-001" }] };
    const out = redactBundle(bundle);
    assert.equal(out.findings[0].evidence, undefined);
  });

  it("returns bundle unchanged if no findings array", () => {
    const bundle = { meta: "test" };
    const out = redactBundle(bundle);
    assert.deepEqual(out, bundle);
  });

  it("REDACT_PATTERNS array is non-empty", () => {
    assert.ok(Array.isArray(REDACT_PATTERNS));
    assert.ok(REDACT_PATTERNS.length >= 10);
  });
});
