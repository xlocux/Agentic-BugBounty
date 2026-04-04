"use strict";

const fs   = require("node:fs");
const path = require("node:path");
const { execSync } = require("node:child_process");

// ── Builtin patterns ──────────────────────────────────────────────────────────
// Covers the categories from the design spec.
// If scripts/sex/patterns.json is available, it is merged on top.

const BUILTIN_PATTERNS = [
  // AWS
  { name: "aws_access_key",     regex: /AKIA[0-9A-Z]{16}/,                                       severity: "critical" },
  { name: "aws_secret_key",     regex: /(?:aws[_-]?secret|AWS_SECRET)[_\s]*[=:]\s*["']?([A-Za-z0-9/+=]{40})/i, severity: "critical" },
  // SSH / RSA private keys
  { name: "ssh_private_key",    regex: /-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/,     severity: "critical" },
  { name: "rsa_private_key",    regex: /-----BEGIN RSA PRIVATE KEY-----/,                         severity: "critical" },
  // Stripe
  { name: "stripe_sk_live",     regex: /sk_live_[0-9a-zA-Z]{24,}/,                               severity: "critical" },
  { name: "stripe_rk_live",     regex: /rk_live_[0-9a-zA-Z]{24,}/,                               severity: "critical" },
  { name: "stripe_sk_test",     regex: /sk_test_[0-9a-zA-Z]{24,}/,                               severity: "high"     },
  // PayPal
  { name: "paypal_braintree",   regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/,   severity: "critical" },
  // GitHub
  { name: "github_token",       regex: /ghp_[A-Za-z0-9]{36}/,                                    severity: "high"     },
  { name: "github_oauth",       regex: /gho_[A-Za-z0-9]{36}/,                                    severity: "high"     },
  { name: "github_pat_v2",      regex: /github_pat_[A-Za-z0-9_]{82}/,                            severity: "high"     },
  // Firebase
  { name: "firebase_api_key",   regex: /AIzaSy[0-9A-Za-z\-_]{33}/,                              severity: "high"     },
  // OpenAI
  { name: "openai_api_key",     regex: /sk-[A-Za-z0-9]{48}/,                                     severity: "high"     },
  // Anthropic
  { name: "anthropic_api_key",  regex: /sk-ant-[A-Za-z0-9\-_]{95}/,                             severity: "high"     },
  // Azure
  { name: "azure_client_secret",regex: /[A-Za-z0-9~.\-_]{34}~[A-Za-z0-9~.\-_]{8}/,             severity: "high"     },
  // Google / GCP
  { name: "google_api_key",     regex: /AIza[0-9A-Za-z\-_]{35}/,                                severity: "high"     },
  // Slack
  { name: "slack_token",        regex: /xox[baprs]-[0-9a-zA-Z]{10,}/,                           severity: "medium"   },
  { name: "slack_webhook",      regex: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, severity: "medium" },
  // Twilio
  { name: "twilio_api_key",     regex: /SK[0-9a-fA-F]{32}/,                                     severity: "medium"   },
  // SendGrid
  { name: "sendgrid_api_key",   regex: /SG\.[A-Za-z0-9\-_.]{22}\.[A-Za-z0-9\-_.]{43}/,         severity: "medium"   },
  // Mailgun
  { name: "mailgun_api_key",    regex: /key-[0-9a-zA-Z]{32}/,                                   severity: "medium"   },
  // Telegram bot token
  { name: "telegram_bot_token", regex: /[0-9]{8,10}:[A-Za-z0-9\-_]{35}/,                       severity: "medium"   },
  // Discord
  { name: "discord_webhook",    regex: /discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/, severity: "medium" },
  // JWT
  { name: "jwt",                regex: /eyJ[A-Za-z0-9\-_=]{10,}\.eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,}/, severity: "medium" },
  // Generic high-entropy password assignment
  { name: "generic_password",   regex: /(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*["'][A-Za-z0-9!@#$%^&*(){}\[\]|:;<>,./?\-_+]{12,}["']/i, severity: "medium" },
  // Heroku
  { name: "heroku_api_key",     regex: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i, severity: "medium" },
  // DigitalOcean
  { name: "digitalocean_token", regex: /dop_v1_[a-f0-9]{64}/,                                   severity: "high"     },
  // Shopify
  { name: "shopify_token",      regex: /shpat_[a-fA-F0-9]{32}/,                                 severity: "medium"   },
  // Notion
  { name: "notion_token",       regex: /secret_[A-Za-z0-9]{43}/,                                severity: "medium"   },
  // OpenRouter / Groq / Replicate
  { name: "openrouter_key",     regex: /sk-or-v1-[A-Za-z0-9]{64}/,                              severity: "high"     },
  { name: "groq_api_key",       regex: /gsk_[A-Za-z0-9]{52}/,                                   severity: "high"     },
];

// ── Pattern loader ────────────────────────────────────────────────────────────

/**
 * Loads builtin patterns, optionally merging sex/patterns.json if available.
 * @param {string} projectRoot  root of the framework repo (not the target)
 * @returns {{ name: string, regex: RegExp, severity: string }[]}
 */
function loadPatterns(projectRoot) {
  const patterns = [...BUILTIN_PATTERNS];

  const sexPath = path.join(projectRoot, "scripts", "sex", "patterns.json");
  if (fs.existsSync(sexPath)) {
    try {
      const raw = JSON.parse(fs.readFileSync(sexPath, "utf8"));
      if (Array.isArray(raw)) {
        for (const p of raw) {
          if (p.name && p.regex) {
            try {
              patterns.push({
                name:     p.name,
                regex:    new RegExp(p.regex, "i"),
                severity: p.severity || "medium"
              });
            } catch { /* invalid regex — skip */ }
          }
        }
      }
    } catch { /* unreadable — skip */ }
  }

  return patterns;
}

// ── Working-tree scanner ──────────────────────────────────────────────────────

/**
 * Scans the working-tree files listed in the manifest for secret patterns.
 *
 * @param {string}   targetDir    absolute path to the target source root
 * @param {object[]} manifestFiles  file_manifest.json `.files` array
 * @param {object[]} patterns     output of loadPatterns()
 * @returns {object[]}  secrets found
 */
function scanWorkingTree(targetDir, manifestFiles, patterns) {
  const found = [];

  for (const f of manifestFiles) {
    const absPath = path.join(targetDir, f.path);
    let content;
    try { content = fs.readFileSync(absPath, "utf8"); }
    catch { continue; }

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        const match = p.regex.exec(lines[i]);
        if (match) {
          found.push({
            name:     p.name,
            severity: p.severity,
            file:     f.path,
            line:     i + 1,
            match:    redactMatch(match[0]),
            source:   "working_tree",
            still_active: null
          });
        }
      }
    }
  }

  return found;
}

// ── Git-history scanner ───────────────────────────────────────────────────────

/**
 * Scans the full git history (including deleted files and all diffs) for secrets.
 * Also checks stash entries.
 *
 * @param {string}   gitDir    absolute path to the git repo
 * @param {object[]} patterns
 * @returns {object[]}
 */
function scanGitHistory(gitDir, patterns) {
  const found = [];
  const seenKeys = new Set(); // deduplicate by name+match

  const sources = [
    // All commit diffs
    { label: "git_history",      cmd: "git log --no-pager -p --all --diff-filter=A --diff-filter=M --diff-filter=D", timeout: 60000 },
    // Stash
    { label: "git_stash",        cmd: "git stash list --no-pager",          timeout: 5000  },
  ];

  for (const src of sources) {
    let output = "";
    try {
      output = execSync(src.cmd, {
        cwd: gitDir, stdio: ["pipe", "pipe", "pipe"], timeout: src.timeout
      }).toString("utf8");
    } catch { continue; }

    if (!output.trim()) continue;

    const lines = output.split("\n");
    let currentCommit = "";
    let currentFile   = "";

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Track current commit
      if (line.startsWith("commit ")) {
        currentCommit = line.slice(7, 15);
        continue;
      }
      // Track current file
      if (line.startsWith("+++ b/")) {
        currentFile = line.slice(6);
        continue;
      }
      // Only scan added lines (lines starting with +)
      if (!line.startsWith("+")) continue;

      for (const p of patterns) {
        const match = p.regex.exec(line);
        if (!match) continue;

        const key = `${p.name}:${redactMatch(match[0])}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);

        found.push({
          name:     p.name,
          severity: p.severity,
          file:     currentFile || "(unknown)",
          commit:   currentCommit,
          match:    redactMatch(match[0]),
          source:   src.label,
          still_active: null
        });
      }
    }
  }

  return found;
}

// ── Gitleaks fallback ─────────────────────────────────────────────────────────

/**
 * Runs gitleaks if available. Returns secrets in normalized format.
 * @param {string} gitDir
 * @returns {object[]}
 */
function runGitleaksFallback(gitDir) {
  try {
    const raw = execSync(
      "gitleaks detect --source . --report-format json --report-path /dev/stdout --no-banner 2>/dev/null",
      { cwd: gitDir, stdio: ["pipe", "pipe", "pipe"], timeout: 60000 }
    ).toString("utf8");
    const results = JSON.parse(raw);
    if (!Array.isArray(results)) return [];
    return results.map(r => ({
      name:         r.RuleID || "gitleaks",
      severity:     "medium",
      file:         r.File || "(unknown)",
      commit:       r.Commit ? r.Commit.slice(0, 8) : null,
      match:        redactMatch(r.Secret || r.Match || ""),
      source:       "gitleaks",
      still_active: null
    }));
  } catch {
    return [];
  }
}

// ── Helper ────────────────────────────────────────────────────────────────────

/**
 * Redacts the middle of a matched secret so it's not stored in plain text.
 * Keeps first 4 and last 4 chars, replaces middle with *****.
 * @param {string} raw
 * @returns {string}
 */
function redactMatch(raw) {
  if (raw.length <= 12) return raw.slice(0, 2) + "***" + raw.slice(-2);
  return raw.slice(0, 4) + "*****" + raw.slice(-4);
}

// ── Public entry point ────────────────────────────────────────────────────────

/**
 * Runs the full secret scan for Stage 1.5, Task 3.
 *
 * Strategy:
 *   1. Load patterns (builtin + sex/patterns.json if present)
 *   2. Scan working tree (manifest files only — no node_modules etc.)
 *   3. Scan full git history for secrets in commit diffs
 *   4. If both 2+3 produce nothing AND gitleaks is available → fallback
 *
 * @param {string}   targetDir      absolute path to target source root
 * @param {object[]} manifestFiles  file_manifest.json `.files` array
 * @param {string}   gitDir         absolute path to git repo (often same as targetDir)
 * @param {string}   projectRoot    framework root (for locating sex/patterns.json)
 * @returns {object[]}  secrets_found array
 */
function runSecretScan(targetDir, manifestFiles, gitDir, projectRoot) {
  const patterns    = loadPatterns(projectRoot || targetDir);
  const fromTree    = scanWorkingTree(targetDir, manifestFiles, patterns);
  const fromHistory = scanGitHistory(gitDir || targetDir, patterns);

  const combined = [...fromTree, ...fromHistory];

  if (combined.length === 0) {
    const fromGitleaks = runGitleaksFallback(gitDir || targetDir);
    return fromGitleaks;
  }

  return combined;
}

module.exports = {
  BUILTIN_PATTERNS,
  loadPatterns,
  scanWorkingTree,
  scanGitHistory,
  runGitleaksFallback,
  runSecretScan,
  redactMatch
};
