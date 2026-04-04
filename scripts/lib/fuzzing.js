"use strict";

const { spawnSync } = require("node:child_process");
const fs            = require("node:fs");
const path          = require("node:path");
const { ScopeError, buildScope } = require("./http");
const { isToolInstalled } = require("./tool-registry");

// ── Shared helpers ────────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 120000; // 2 minutes per tool run

/**
 * Runs an external command synchronously and returns structured output.
 * @param {string}   bin
 * @param {string[]} args
 * @param {object}   opts  — { cwd, timeoutMs, env }
 * @returns {{ command: string, stdout: string, stderr: string, exitCode: number }}
 */
function runTool(bin, args, opts = {}) {
  const { cwd = process.cwd(), timeoutMs = DEFAULT_TIMEOUT_MS, env = process.env } = opts;
  const command = [bin, ...args].join(" ");
  const result = spawnSync(bin, args, {
    cwd,
    env,
    timeout:  timeoutMs,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024 // 10 MB
  });

  return {
    command,
    stdout:   (result.stdout || "").slice(0, 50000),
    stderr:   (result.stderr || "").slice(0, 10000),
    exitCode: result.status ?? -1
  };
}

/**
 * Asserts a URL is in scope before running a tool.
 * Throws ScopeError on violation.
 * @param {string} urlString
 * @param {object|null} scopeConfig
 */
function assertScope(urlString, scopeConfig) {
  if (scopeConfig) buildScope(scopeConfig).check(urlString);
}

// ── ffuf — endpoint / parameter fuzzing ─────────────────────────────────────

/**
 * Runs ffuf against a URL template.
 * The FUZZ keyword must appear somewhere in the urlTemplate.
 *
 * @param {string}   urlTemplate  e.g. "http://localhost:8080/FUZZ"
 * @param {string}   wordlist     absolute path to wordlist file
 * @param {{
 *   matchCodes?:  number[],   default [200,301,302,403]
 *   filterCodes?: number[],
 *   method?:      string,     default "GET"
 *   headers?:     string[],   e.g. ["Authorization: Bearer ..."]
 *   timeoutMs?:   number,
 *   extraArgs?:   string[]
 * }} options
 * @param {object|null} scopeConfig
 * @returns {{ command: string, stdout: string, stderr: string, exitCode: number, findings: string[] }}
 */
function runFfuf(urlTemplate, wordlist, options = {}, scopeConfig = null) {
  // Scope check on the base URL (strip FUZZ placeholder)
  const baseUrl = urlTemplate.replace("FUZZ", "");
  assertScope(baseUrl, scopeConfig);

  if (!isToolInstalled("ffuf")) {
    return { command: "ffuf (not installed)", stdout: "", stderr: "ffuf not found in PATH", exitCode: -1, findings: [] };
  }

  const {
    matchCodes  = [200, 301, 302, 403],
    filterCodes = [],
    method      = "GET",
    headers     = [],
    timeoutMs   = DEFAULT_TIMEOUT_MS,
    extraArgs   = []
  } = options;

  const args = [
    "-u", urlTemplate,
    "-w", wordlist,
    "-mc", matchCodes.join(","),
    "-X", method,
    "-o", "/dev/stdout",
    "-of", "json",
    "-s"                // silent — no banner
  ];

  for (const h of headers) args.push("-H", h);
  if (filterCodes.length) args.push("-fc", filterCodes.join(","));
  args.push(...extraArgs);

  const result = runTool("ffuf", args, { timeoutMs });

  // Extract finding URLs from JSON output
  const findings = [];
  try {
    const parsed = JSON.parse(result.stdout);
    if (Array.isArray(parsed.results)) {
      for (const r of parsed.results) {
        if (r.url) findings.push(r.url);
      }
    }
  } catch { /* non-JSON or empty output */ }

  return { ...result, findings };
}

// ── dalfox — XSS fuzzing ─────────────────────────────────────────────────────

/**
 * Runs dalfox against a URL for XSS detection.
 *
 * @param {string} urlString       target URL with parameter(s)
 * @param {{
 *   cookie?:   string,
 *   headers?:  string[],
 *   timeout?:  number,
 *   blind?:    string,     blind XSS callback URL
 *   extraArgs?: string[]
 * }} options
 * @param {object|null} scopeConfig
 * @returns {{ command: string, stdout: string, stderr: string, exitCode: number, findings: string[] }}
 */
function runDalfox(urlString, options = {}, scopeConfig = null) {
  assertScope(urlString, scopeConfig);

  if (!isToolInstalled("dalfox")) {
    return { command: "dalfox (not installed)", stdout: "", stderr: "dalfox not found in PATH", exitCode: -1, findings: [] };
  }

  const {
    cookie    = "",
    headers   = [],
    timeout   = 30,
    blind     = "",
    extraArgs = []
  } = options;

  const args = ["url", urlString, "--format", "json", "--silence", "--timeout", String(timeout)];

  if (cookie)  args.push("--cookie", cookie);
  if (blind)   args.push("--blind", blind);
  for (const h of headers) args.push("--header", h);
  args.push(...extraArgs);

  const result = runTool("dalfox", args, { timeoutMs: (timeout + 10) * 1000 });

  const findings = [];
  try {
    const lines = result.stdout.split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (obj.type === "POC" && obj.data) findings.push(obj.data);
      } catch { /* not a JSON line */ }
    }
  } catch { /* ignore */ }

  return { ...result, findings };
}

// ── sqlmap — SQL injection fuzzing ────────────────────────────────────────────

/**
 * Runs sqlmap against a URL to detect SQL injection.
 *
 * @param {string} urlString       target URL with parameter(s)
 * @param {{
 *   param?:     string,    specific parameter to test
 *   cookie?:    string,
 *   level?:     number,    1-5, default 3
 *   risk?:      number,    1-3, default 2
 *   dbms?:      string,    e.g. "mysql", "postgresql"
 *   extraArgs?: string[]
 * }} options
 * @param {object|null} scopeConfig
 * @returns {{ command: string, stdout: string, stderr: string, exitCode: number, findings: string[] }}
 */
function runSqlmap(urlString, options = {}, scopeConfig = null) {
  assertScope(urlString, scopeConfig);

  if (!isToolInstalled("sqlmap")) {
    return { command: "sqlmap (not installed)", stdout: "", stderr: "sqlmap not found in PATH", exitCode: -1, findings: [] };
  }

  const {
    param     = "",
    cookie    = "",
    level     = 3,
    risk      = 2,
    dbms      = "",
    extraArgs = []
  } = options;

  const args = [
    "-u", urlString,
    "--level", String(level),
    "--risk",  String(risk),
    "--batch",         // non-interactive
    "--output-dir", "/tmp/sqlmap_output"
  ];

  if (param)  args.push("-p", param);
  if (cookie) args.push("--cookie", cookie);
  if (dbms)   args.push("--dbms", dbms);
  args.push(...extraArgs);

  const result = runTool("sqlmap", args);

  // Parse sqlmap output for injectable parameters
  const findings = [];
  const injectRe = /Parameter: (.+?) \((.+?)\)/g;
  let m;
  while ((m = injectRe.exec(result.stdout)) !== null) {
    findings.push(`${m[1]} (${m[2]})`);
  }

  return { ...result, findings };
}

// ── jwt_tool — JWT weak secret brute force ────────────────────────────────────

/**
 * Runs jwt_tool to brute-force a JWT's HMAC secret.
 *
 * @param {string} token        JWT token string
 * @param {{
 *   wordlist?:  string,     path to wordlist, default rockyou
 *   extraArgs?: string[]
 * }} options
 * @returns {{ command: string, stdout: string, stderr: string, exitCode: number, findings: string[] }}
 */
function runJwtTool(token, options = {}) {
  if (!isToolInstalled("jwt_tool")) {
    return { command: "jwt_tool (not installed)", stdout: "", stderr: "jwt_tool not found in PATH", exitCode: -1, findings: [] };
  }

  const defaultWordlist = process.platform === "win32"
    ? "C:\\wordlists\\rockyou.txt"
    : "/usr/share/wordlists/rockyou.txt";

  const { wordlist = defaultWordlist, extraArgs = [] } = options;

  const args = [token, "-C", "-d", wordlist, ...extraArgs];
  const result = runTool("jwt_tool", args);

  const findings = [];
  // jwt_tool prints "[+] ... Key: <secret>" on success
  const keyRe = /\[\+\].*[Kk]ey:\s*(.+)/;
  const m = keyRe.exec(result.stdout);
  if (m) findings.push(`Weak secret found: ${m[1].trim()}`);

  return { ...result, findings };
}

// ── brojack — broken link hijacking ─────────────────────────────────────────

/**
 * Runs brojack to find expired/dead external links in a live target.
 *
 * @param {string} targetUrl          base URL to crawl
 * @param {{
 *   outfile?:  string,   path to save JSON results
 *   extraArgs?: string[]
 * }} options
 * @param {object|null} scopeConfig
 * @returns {{ command: string, stdout: string, stderr: string, exitCode: number, findings: string[] }}
 */
function runBrojack(targetUrl, options = {}, scopeConfig = null) {
  assertScope(targetUrl, scopeConfig);

  // brojack is a Python script — check if the brojack.py exists
  const brojackPath = path.resolve(__dirname, "..", "..", "tools", "brojack.py");
  const usePath     = fs.existsSync(brojackPath) ? brojackPath : "brojack";
  const python      = process.platform === "win32" ? "python" : "python3";

  const { outfile = "/tmp/brojack_results.json", extraArgs = [] } = options;

  const args = [
    usePath === "brojack" ? "-m" : usePath,
    ...(usePath === "brojack" ? ["brojack"] : []),
    "-d", targetUrl,
    "-t",            // test if domains are available for registration
    "-v",
    "--outfile", outfile,
    ...extraArgs
  ];

  const bin    = usePath === "brojack" ? python : python;
  const result = runTool(bin, args);

  const findings = [];
  // Parse outfile if it was written
  if (fs.existsSync(outfile)) {
    try {
      const raw = JSON.parse(fs.readFileSync(outfile, "utf8"));
      if (Array.isArray(raw)) {
        for (const r of raw) {
          if (r.domain || r.url) findings.push(r.domain || r.url);
        }
      }
    } catch { /* ignore */ }
  }

  // Also scan stdout for "TAKEABLE" or "expired" lines
  const takeableRe = /(?:TAKEABLE|expired|available).*?([\w.-]+\.[\w]+)/gi;
  let m2;
  while ((m2 = takeableRe.exec(result.stdout)) !== null) {
    const d = m2[1];
    if (!findings.includes(d)) findings.push(d);
  }

  return { ...result, findings };
}

module.exports = {
  runFfuf,
  runDalfox,
  runSqlmap,
  runJwtTool,
  runBrojack
};
