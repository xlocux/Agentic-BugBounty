"use strict";

const test   = require("node:test");
const assert = require("node:assert/strict");
const { extractDocs, extractSurface, extractResponse } = require("../scripts/lib/html-extract");

const SAMPLE_DOC_HTML = `
<html>
<head><style>body { color: red; }</style></head>
<body>
  <nav><a href="/home">Home</a></nav>
  <main>
    <h1>Installation Guide</h1>
    <p>Run npm install to get started.</p>
  </main>
  <footer>Copyright 2026</footer>
  <script>var secret = "api_key_123";</script>
</body>
</html>`;

const SAMPLE_SURFACE_HTML = `
<html>
<body>
  <nav>Nav noise</nav>
  <form action="/api/login" method="POST">
    <input name="username" type="text">
    <input name="password" type="password">
    <input name="_csrf" type="hidden" value="tok123">
    <button type="submit">Login</button>
  </form>
  <div data-endpoint="/api/users" data-role="admin">content</div>
  <!-- internal path: /var/www/app/config.php -->
  <script>var API_BASE = "/api/v2";</script>
  <script src="https://cdn.external.com/lib.js"></script>
  <a href="/dashboard">Dashboard</a>
</body>
</html>`;

const SAMPLE_RESPONSE_HTML = `
<html><body>
  <p>Hello world</p>
  <!-- debug: /home/ubuntu/app/src/controllers/user.js:142 -->
  <script>var pass = "hardcoded_password";</script>
</body></html>`;

// ── extractDocs ──────────────────────────────────────────────────────────────

test("extractDocs returns main content text", () => {
  const text = extractDocs(SAMPLE_DOC_HTML);
  assert.ok(text.includes("Installation Guide"));
  assert.ok(text.includes("npm install"));
});

test("extractDocs strips nav and footer", () => {
  const text = extractDocs(SAMPLE_DOC_HTML);
  assert.ok(!text.includes("Copyright 2026"));
  assert.ok(!text.includes("Home"));
});

test("extractDocs strips script tags", () => {
  const text = extractDocs(SAMPLE_DOC_HTML);
  assert.ok(!text.includes("api_key_123"));
});

// ── extractSurface ───────────────────────────────────────────────────────────

test("extractSurface captures inline scripts", () => {
  const result = extractSurface(SAMPLE_SURFACE_HTML);
  assert.ok(result.inline_scripts.some(s => s.includes("API_BASE")));
});

test("extractSurface captures external script sources", () => {
  const result = extractSurface(SAMPLE_SURFACE_HTML);
  assert.ok(result.script_srcs.includes("https://cdn.external.com/lib.js"));
});

test("extractSurface captures HTML comments", () => {
  const result = extractSurface(SAMPLE_SURFACE_HTML);
  assert.ok(result.comments.some(c => c.includes("/var/www/app")));
});

test("extractSurface captures forms with all fields including hidden", () => {
  const result = extractSurface(SAMPLE_SURFACE_HTML);
  assert.equal(result.forms.length, 1);
  const form = result.forms[0];
  assert.equal(form.action, "/api/login");
  assert.equal(form.method, "POST");
  const hiddenInput = form.inputs.find(i => i.type === "hidden");
  assert.ok(hiddenInput, "hidden input should be captured");
  assert.equal(hiddenInput.value, "tok123");
});

test("extractSurface captures data-* attributes", () => {
  const result = extractSurface(SAMPLE_SURFACE_HTML);
  assert.ok(result.data_attributes["data-endpoint"]);
  assert.ok(result.data_attributes["data-endpoint"].includes("/api/users"));
});

test("extractSurface captures links", () => {
  const result = extractSurface(SAMPLE_SURFACE_HTML);
  assert.ok(result.links.some(l => l.href === "/dashboard"));
});

// ── extractResponse ──────────────────────────────────────────────────────────

test("extractResponse detects internal_path anomaly", () => {
  const result = extractResponse(SAMPLE_RESPONSE_HTML);
  assert.ok(result.anomalies.includes("internal_path"));
});

test("extractResponse detects credential_leak anomaly", () => {
  const result = extractResponse(SAMPLE_RESPONSE_HTML);
  assert.ok(result.anomalies.includes("credential_leak"));
});

test("extractResponse includes surface fields", () => {
  const result = extractResponse(SAMPLE_RESPONSE_HTML);
  assert.ok(Array.isArray(result.inline_scripts));
  assert.ok(Array.isArray(result.forms));
});

test("extractResponse returns empty anomalies for clean page", () => {
  const clean = "<html><body><p>Hello</p></body></html>";
  const result = extractResponse(clean);
  assert.deepEqual(result.anomalies, []);
});
