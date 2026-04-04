"use strict";

const http  = require("node:http");
const https = require("node:https");
const { URL } = require("node:url");

// ── Scope enforcement ─────────────────────────────────────────────────────────

/**
 * Thrown when a request is blocked by scope enforcement.
 * Callers MUST NOT catch and ignore — this is a hard block.
 */
class ScopeError extends Error {
  constructor(url, reason) {
    super(`OUT OF SCOPE: ${url} — ${reason}`);
    this.name  = "ScopeError";
    this.url   = url;
    this.reason = reason;
  }
}

/**
 * Normalises a scope entry into a matcher function.
 * Entries can be:
 *   "*.example.com"           → wildcard hostname
 *   "example.com"             → exact hostname
 *   "https://example.com/..."  → URL prefix
 *   "com.example.app"         → app identifier (skipped for HTTP scope checks)
 *
 * @param {string} entry
 * @returns {(hostname: string, href: string) => boolean}
 */
function buildMatcher(entry) {
  // URL prefix match
  if (entry.startsWith("http://") || entry.startsWith("https://")) {
    return (_hostname, href) => href.startsWith(entry);
  }
  // Wildcard hostname
  if (entry.startsWith("*.")) {
    const base = entry.slice(2).toLowerCase();
    return (hostname) => hostname.toLowerCase().endsWith("." + base);
  }
  // App identifier (contains no dots at domain level or has reversed-domain format)
  if (/^[a-z]+\.[a-z]+\.[a-z]/.test(entry) && !entry.includes("/")) {
    // Could be a hostname like "sub.example.com" OR an app ID "com.example.app"
    // Treat as hostname match
    return (hostname) => hostname.toLowerCase() === entry.toLowerCase();
  }
  // Plain hostname or IP
  return (hostname) => hostname.toLowerCase() === entry.toLowerCase();
}

/**
 * Compiles a scope config into a reusable checker object.
 *
 * @param {{ in_scope?: string[], out_of_scope?: string[] }} scopeConfig
 *   from target.json.scope
 * @returns {{ check: (url: string) => void }}
 */
function buildScope(scopeConfig) {
  const inMatchers  = (scopeConfig?.in_scope  || []).map(buildMatcher);
  const outMatchers = (scopeConfig?.out_of_scope || []).map(buildMatcher);

  function check(urlString) {
    // localhost / 127.x / ::1 are always allowed (local test environment)
    let parsed;
    try { parsed = new URL(urlString); }
    catch { throw new ScopeError(urlString, "invalid URL"); }

    const hostname = parsed.hostname;
    const href     = parsed.href;

    if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" ||
        /^127\./.test(hostname) || /^192\.168\./.test(hostname) ||
        /^10\./.test(hostname)  || /^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) {
      return; // always in-scope for local testing
    }

    // out_of_scope is a hard block, checked first
    for (const matcher of outMatchers) {
      if (matcher(hostname, href)) {
        throw new ScopeError(urlString, `matched out_of_scope entry`);
      }
    }

    // If in_scope list is empty → no restriction (warn only, don't block)
    if (inMatchers.length === 0) return;

    // Must match at least one in_scope entry
    for (const matcher of inMatchers) {
      if (matcher(hostname, href)) return;
    }

    throw new ScopeError(urlString, `not in in_scope list`);
  }

  return { check };
}

/**
 * Convenience: checks a URL against a scope config without building a checker.
 * @param {string} urlString
 * @param {{ in_scope?: string[], out_of_scope?: string[] }} scopeConfig
 * @returns {boolean}
 */
function isInScope(urlString, scopeConfig) {
  try {
    buildScope(scopeConfig).check(urlString);
    return true;
  } catch (e) {
    if (e instanceof ScopeError) return false;
    throw e;
  }
}

// ── HTTP request ──────────────────────────────────────────────────────────────

/**
 * Makes an HTTP/HTTPS request without scope enforcement.
 * Returns a structured response object.
 *
 * @param {string} urlString
 * @param {{
 *   method?: string,
 *   headers?: object,
 *   body?: string,
 *   timeoutMs?: number,
 *   followRedirects?: boolean,
 *   maxRedirects?: number
 * }} options
 * @returns {Promise<{
 *   statusCode: number,
 *   statusMessage: string,
 *   headers: object,
 *   body: string,
 *   redirects: string[]
 * }>}
 */
function httpRequest(urlString, options = {}) {
  const {
    method         = "GET",
    headers        = {},
    body           = null,
    timeoutMs      = 15000,
    followRedirects = true,
    maxRedirects    = 5
  } = options;

  return new Promise((resolve, reject) => {
    const redirects = [];

    function doRequest(url, redirectsLeft) {
      let parsed;
      try { parsed = new URL(url); }
      catch (e) { return reject(e); }

      const lib      = parsed.protocol === "https:" ? https : http;
      const reqOpts  = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method,
        headers: {
          "User-Agent": "AgenBB-Scanner/2.0",
          "Accept":     "*/*",
          ...headers
        }
      };

      const req = lib.request(reqOpts, (res) => {
        // Follow redirects
        if (followRedirects && [301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirectsLeft > 0) {
          let nextUrl;
          try {
            nextUrl = new URL(res.headers.location, url).href;
          } catch {
            nextUrl = res.headers.location;
          }
          redirects.push(nextUrl);
          res.resume();
          doRequest(nextUrl, redirectsLeft - 1);
          return;
        }

        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            statusCode:    res.statusCode,
            statusMessage: res.statusMessage || "",
            headers:       res.headers,
            body:          Buffer.concat(chunks).toString("utf8").slice(0, 8000),
            redirects
          });
        });
      });

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
      });

      req.on("error", reject);

      if (body) req.write(body);
      req.end();
    }

    doRequest(urlString, maxRedirects);
  });
}

// ── Evidence capture ──────────────────────────────────────────────────────────

/**
 * Formats a raw HTTP request as a printable string (for evidence.request).
 * @param {string} method
 * @param {URL}    parsed
 * @param {object} headers
 * @param {string|null} body
 * @returns {string}
 */
function formatRequest(method, parsed, headers, body) {
  const path     = parsed.pathname + parsed.search;
  const reqLine  = `${method} ${path} HTTP/1.1`;
  const hostLine = `Host: ${parsed.hostname}`;
  const headerLines = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\r\n");
  const parts = [reqLine, hostLine];
  if (headerLines) parts.push(headerLines);
  if (body) { parts.push(""); parts.push(body.slice(0, 500)); }
  return parts.join("\r\n");
}

/**
 * Formats a response as a printable string (for evidence.response).
 * @param {{ statusCode, statusMessage, headers, body }} res
 * @returns {string}
 */
function formatResponse(res) {
  const statusLine   = `HTTP/1.1 ${res.statusCode} ${res.statusMessage}`;
  const headerLines  = Object.entries(res.headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\r\n");
  const bodySnippet  = res.body ? res.body.slice(0, 500) : "";
  return `${statusLine}\r\n${headerLines}\r\n\r\n${bodySnippet}`;
}

/**
 * Makes an HTTP request with scope enforcement and captures structured evidence.
 *
 * @param {string} urlString
 * @param {object} options         — same as httpRequest options
 * @param {object} scopeConfig     — target.json.scope
 * @param {string} [toolOutput]    — optional: output from an external tool (sqlmap, dalfox, etc.)
 * @returns {Promise<{
 *   request: string,
 *   response: string,
 *   tool_output: string,
 *   statusCode: number,
 *   scoped: true
 * }>}
 * @throws {ScopeError} if the URL is out of scope
 */
async function captureEvidence(urlString, options = {}, scopeConfig = null, toolOutput = "") {
  // Hard scope check — throws ScopeError if out of scope
  if (scopeConfig) {
    buildScope(scopeConfig).check(urlString);
  }

  const method  = options.method || "GET";
  const parsed  = new URL(urlString);
  const headers = options.headers || {};
  const body    = options.body    || null;

  const res = await httpRequest(urlString, options);

  return {
    request:     formatRequest(method, parsed, { ...headers, "User-Agent": "AgenBB-Scanner/2.0" }, body),
    response:    formatResponse(res),
    tool_output: toolOutput || "",
    statusCode:  res.statusCode,
    scoped:      true
  };
}

module.exports = {
  ScopeError,
  buildScope,
  isInScope,
  httpRequest,
  captureEvidence,
  // Exported for tests
  formatRequest,
  formatResponse
};
