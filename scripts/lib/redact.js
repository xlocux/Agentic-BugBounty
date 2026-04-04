"use strict";

// ── Redaction patterns ────────────────────────────────────────────────────────
// Each entry: { name, regex, replacement }
// Patterns are applied in order; the first match wins for overlapping segments.

const REDACT_PATTERNS = [
  // HTTP Authorization header (any scheme: Bearer, Basic, Token, ...)
  {
    name:        "authorization_header",
    regex:       /(\bAuthorization\s*:\s*).+/gi,
    replacement: "$1[REDACTED]"
  },
  // Cookie header (full value)
  {
    name:        "cookie_header",
    regex:       /(\bCookie\s*:\s*).+/gi,
    replacement: "$1[REDACTED]"
  },
  // Set-Cookie header value (after the = and before ; or end)
  {
    name:        "set_cookie_value",
    regex:       /(\bSet-Cookie\s*:\s*\w+=)[^;\s]+/gi,
    replacement: "$1[REDACTED]"
  },
  // AWS Access Key ID
  {
    name:        "aws_access_key",
    regex:       /AKIA[0-9A-Z]{16}/g,
    replacement: "AKIA[REDACTED]"
  },
  // AWS Secret Key (common env var patterns)
  {
    name:        "aws_secret_key",
    regex:       /(AWS_SECRET[_A-Z]*\s*[=:]\s*["']?)[A-Za-z0-9/+=]{40}/gi,
    replacement: "$1[REDACTED]"
  },
  // Stripe live keys
  {
    name:        "stripe_sk_live",
    regex:       /sk_live_[0-9a-zA-Z]{24,}/g,
    replacement: "sk_live_[REDACTED]"
  },
  // Generic Bearer token (in URL query strings or JSON bodies)
  {
    name:        "bearer_token_url",
    regex:       /(\btoken=)[A-Za-z0-9\-_.~+/=]{20,}/gi,
    replacement: "$1[REDACTED]"
  },
  // JWT tokens (3-part dot-separated base64)
  {
    name:        "jwt",
    regex:       /eyJ[A-Za-z0-9\-_=]{10,}\.eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,}/g,
    replacement: "[JWT_REDACTED]"
  },
  // Generic password in key=value (JSON or form-encoded)
  {
    name:        "password_value",
    regex:       /("?(?:password|passwd|pwd|secret|api_?key)"?\s*[=:]\s*["']?)[^\s"',;&]{8,}/gi,
    replacement: "$1[REDACTED]"
  },
  // SSH / RSA private key block (full block)
  {
    name:        "private_key_block",
    regex:       /-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/g,
    replacement: "[PRIVATE_KEY_REDACTED]"
  },
  // X-API-Key / X-Auth-Token headers
  {
    name:        "x_api_key_header",
    regex:       /(\bX-(?:API-Key|Auth-Token|Access-Token|Secret-Key)\s*:\s*)\S+/gi,
    replacement: "$1[REDACTED]"
  }
];

// ── Core redaction ────────────────────────────────────────────────────────────

/**
 * Applies all redaction patterns to a string.
 * @param {string} text
 * @returns {string}
 */
function redactString(text) {
  if (!text || typeof text !== "string") return text;
  let result = text;
  for (const p of REDACT_PATTERNS) {
    result = result.replace(p.regex, p.replacement);
  }
  return result;
}

/**
 * Redacts an evidence object in place (request + response + tool_output).
 * Returns a new object — does not mutate the input.
 * @param {{ request?: string, response?: string, tool_output?: string }} evidence
 * @returns {object}
 */
function redactEvidence(evidence) {
  if (!evidence || typeof evidence !== "object") return evidence;
  return {
    ...evidence,
    request:     evidence.request     ? redactString(evidence.request)     : evidence.request,
    response:    evidence.response    ? redactString(evidence.response)    : evidence.response,
    tool_output: evidence.tool_output ? redactString(evidence.tool_output) : evidence.tool_output
  };
}

/**
 * Redacts a single log line.
 * Useful for streaming log sanitisation before writing to disk.
 * @param {string} line
 * @returns {string}
 */
function redactLogLine(line) {
  return redactString(line);
}

/**
 * Redacts all findings' evidence blocks in a report_bundle.json object.
 * Returns a new bundle — does not mutate.
 * @param {object} bundle
 * @returns {object}
 */
function redactBundle(bundle) {
  if (!bundle || !Array.isArray(bundle.findings)) return bundle;
  return {
    ...bundle,
    findings: bundle.findings.map(f => ({
      ...f,
      evidence: f.evidence ? redactEvidence(f.evidence) : f.evidence
    }))
  };
}

module.exports = {
  REDACT_PATTERNS,
  redactString,
  redactEvidence,
  redactLogLine,
  redactBundle
};
