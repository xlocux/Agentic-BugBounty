"use strict";
const fs   = require("node:fs");
const path = require("node:path");
const { validate } = require("./schema-validator");

// ── Writers ────────────────────────────────────────────────────────────────

function writeState(sessionPath, payload) {
  validate("session", payload);
  fs.mkdirSync(path.dirname(sessionPath), { recursive: true });
  fs.writeFileSync(sessionPath, JSON.stringify(payload, null, 2), "utf8");
}

function writeResponse(responsePath, payload) {
  validate("session-response", payload);
  fs.mkdirSync(path.dirname(responsePath), { recursive: true });
  fs.writeFileSync(responsePath, JSON.stringify(payload, null, 2), "utf8");
}

// ── Polling ────────────────────────────────────────────────────────────────

/**
 * Poll responsePath every 500ms until a response with matching request_id appears.
 * Rejects stale responses (different request_id are silently skipped).
 * Default timeout: 30 minutes.
 */
async function waitForResponse(responsePath, requestId, timeoutMs = 1800000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 500));
    if (!fs.existsSync(responsePath)) continue;
    let data;
    try { data = JSON.parse(fs.readFileSync(responsePath, "utf8")); } catch { continue; }
    if (data.request_id === requestId) return data;
  }
  throw new Error(
    `waitForResponse timed out after ${timeoutMs}ms for request_id=${requestId}`
  );
}

// ── Plan builder ───────────────────────────────────────────────────────────

const ASSET_PLANS = {
  webapp: {
    mandatory: [
      { id: "AUTH",   label: "Authentication & authorization checks",        mandatory: true,  reason: null },
      { id: "INJECT", label: "Injection vulnerabilities (SQLi, XSS, SSTI)", mandatory: true,  reason: null }
    ],
    optional: [
      { id: "CLIENT", label: "Client-side vulnerabilities",       mandatory: false, reason: "requires JS surface" },
      { id: "ACCESS", label: "Broken access control",             mandatory: false, reason: "requires multi-role surface" },
      { id: "MEDIA",  label: "File upload vulnerabilities",       mandatory: false, reason: "no upload endpoint found" },
      { id: "INFRA",  label: "Infrastructure / misconfiguration", mandatory: false, reason: null }
    ]
  },
  browserext: {
    mandatory: [
      { id: "postmessage", label: "postMessage vulnerabilities", mandatory: true, reason: null },
      { id: "dom_xss",     label: "DOM XSS",                     mandatory: true, reason: null }
    ],
    optional: [
      { id: "content_script", label: "Content script injection", mandatory: false, reason: "requires user interaction" },
      { id: "supply_chain",   label: "Supply chain audit",       mandatory: false, reason: null },
      { id: "permissions",    label: "Excessive permissions",    mandatory: false, reason: null }
    ]
  },
  mobileapp: {
    mandatory: [
      { id: "deep_links", label: "Deep link hijacking",    mandatory: true, reason: null },
      { id: "intent",     label: "Intent vulnerabilities", mandatory: true, reason: null }
    ],
    optional: [
      { id: "storage", label: "Insecure local storage",                mandatory: false, reason: null },
      { id: "network", label: "Network traffic / certificate pinning", mandatory: false, reason: null },
      { id: "crypto",  label: "Weak cryptography",                     mandatory: false, reason: null }
    ]
  },
  executable: {
    mandatory: [
      { id: "memory_corruption", label: "Memory corruption (buffer overflow, UAF)", mandatory: true, reason: null },
      { id: "binary_analysis",   label: "Binary analysis (symbols, ASLR, NX)",      mandatory: true, reason: null }
    ],
    optional: [
      { id: "input_validation", label: "Input validation",           mandatory: false, reason: null },
      { id: "priv_esc",         label: "Privilege escalation paths", mandatory: false, reason: null }
    ]
  }
};

/**
 * Build the session plan for a given asset type.
 * surfaceMap.exclude — array of op IDs to omit from optional ops
 * surfaceMap.context — string injected into session.json context field
 */
function buildPlanForAssetType(assetType, surfaceMap = {}) {
  const def = ASSET_PLANS[assetType];
  if (!def) throw new Error(`Unknown asset_type: "${assetType}"`);
  const excludeSet = new Set(surfaceMap.exclude || []);
  const plan = [
    ...def.mandatory,
    ...def.optional.filter((op) => !excludeSet.has(op.id))
  ];
  return { plan, context: surfaceMap.context || null };
}

// ── Misc ───────────────────────────────────────────────────────────────────

function isHitlMode(args) {
  return args.hitl === true;
}

module.exports = {
  writeState,
  writeResponse,
  waitForResponse,
  buildPlanForAssetType,
  isHitlMode,
  ASSET_PLANS
};
