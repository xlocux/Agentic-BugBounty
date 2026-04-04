"use strict";

const { execSync } = require("node:child_process");
const { validate }  = require("./schema-validator");

// ── Security commit keyword patterns ─────────────────────────────────────────

const SECURITY_KEYWORDS = [
  "fix", "patch", "security", "vuln", "cve", "xss", "sqli", "injection",
  "bypass", "sanitiz", "escap", "validat", "authori", "authenti", "permission",
  "privilege", "disclosure", "leak", "expos", "restrict", "protect", "harden",
  "prevent", "csrf", "ssrf", "rce", "lfi", "rfi", "idor", "traversal"
];

const SECURITY_RE = new RegExp(SECURITY_KEYWORDS.join("|"), "i");

// ── Empty skeleton ────────────────────────────────────────────────────────────

/**
 * Returns an empty, schema-valid git_intelligence.json v2 skeleton.
 * @param {string} target
 * @returns {object}
 */
function buildEmptyGitIntel(target) {
  return {
    schema_version:   2,
    generated_at:     new Date().toISOString(),
    target,
    security_commits: [],
    bypass_vectors:   [],
    secrets_found:    [],
    version_delta:    []
  };
}

/**
 * Validates and returns the intel object. Throws if invalid.
 * @param {object} intel
 * @returns {object}
 */
function normalizeGitIntel(intel) {
  validate("git-intelligence", intel);
  return intel;
}

/**
 * Merges bypass_vectors from an LLM result object into the base intel.
 * Only merges arrays that exist in the addition.
 * @param {object} base
 * @param {object} addition  LLM output — may contain bypass_vectors, security_commits
 * @returns {object}
 */
function mergeGitIntel(base, addition) {
  const merged = { ...base, generated_at: new Date().toISOString() };
  if (Array.isArray(addition.bypass_vectors)) {
    merged.bypass_vectors = [...base.bypass_vectors, ...addition.bypass_vectors];
  }
  if (Array.isArray(addition.security_commits)) {
    merged.security_commits = [...base.security_commits, ...addition.security_commits];
  }
  return merged;
}

// ── Task 1 — Security Commit Mining (deterministic) ───────────────────────────

/**
 * Mines git log for security-relevant commits.
 * Returns an array of { hash, date, author, subject, diff } objects.
 *
 * @param {string} gitDir   absolute path to the git repo root
 * @param {number} maxCommits  cap to avoid token explosion (default 50)
 * @returns {object[]}
 */
function mineSecurityCommits(gitDir, maxCommits = 50) {
  let log;
  try {
    log = execSync(
      "git log --no-pager --pretty=format:%H%x1f%ai%x1f%an%x1f%s --diff-filter=M",
      { cwd: gitDir, stdio: ["pipe", "pipe", "pipe"], timeout: 30000 }
    ).toString("utf8");
  } catch {
    return [];
  }

  const commits = [];
  for (const line of log.split("\n")) {
    const parts = line.split("\x1f");
    if (parts.length < 4) continue;
    const [hash, date, author, subject] = parts;
    if (!SECURITY_RE.test(subject)) continue;

    let diff = "";
    try {
      diff = execSync(
        `git show --no-pager -U3 ${hash}`,
        { cwd: gitDir, stdio: ["pipe", "pipe", "pipe"], timeout: 15000 }
      ).toString("utf8").slice(0, 6000); // cap diff size
    } catch { /* skip */ }

    commits.push({ hash, date, author, subject, diff });
    if (commits.length >= maxCommits) break;
  }

  return commits;
}

// ── Task 2 — Patch Bypass Analysis (LLM prompt) ───────────────────────────────

/**
 * Builds the LLM prompt for Tasks 1+2: given the mined security commits,
 * ask the cheap model to classify them and identify bypass vectors.
 *
 * @param {string}   target
 * @param {object[]} securityCommits  output of mineSecurityCommits()
 * @returns {string}
 */
function buildGitIntelPrompt(target, securityCommits) {
  const commitBlocks = securityCommits.map((c, i) =>
    `### Commit ${i + 1}: ${c.hash.slice(0, 8)} — ${c.subject}\nDate: ${c.date}  Author: ${c.author}\n\`\`\`diff\n${c.diff}\n\`\`\``
  ).join("\n\n");

  return `You are a security researcher performing patch bypass analysis for target: ${target}

For each security fix below, identify:
1. What was the original vulnerability (removed lines)
2. What was the fix applied (added lines)
3. Plausible bypass vectors — ways the fix may be incomplete or circumventable

Output a single JSON object:

{
  "bypass_vectors": [
    {
      "commit":                    "short hash",
      "fix_description":           "one sentence",
      "original_vulnerable_code":  "brief snippet",
      "fix_applied":               "brief snippet",
      "bypass_vectors": [
        {
          "vector":      "description of the bypass technique",
          "plausibility": "high|medium|low",
          "code_path":    "file:line if visible"
        }
      ],
      "bypass_priority": "high|medium|low"
    }
  ]
}

Rules:
- Only include entries with at least one bypass vector
- Omit commits where the fix is complete and no bypass is plausible
- Output ONLY valid JSON, nothing else

COMMITS TO ANALYZE:
${commitBlocks}
`;
}

// ── Task 4 — Version Delta Analysis (deterministic) ──────────────────────────

/**
 * Identifies commits applied after the tested version (if known).
 * Compares git log from tested_version..HEAD.
 *
 * @param {string}      gitDir
 * @param {string|null} testedVersion  semver tag or commit hash, e.g. "v1.2.3"
 * @returns {object[]}  array of { commit, date, subject, files_changed }
 */
function runVersionDelta(gitDir, testedVersion) {
  if (!testedVersion) return [];

  let log;
  try {
    log = execSync(
      `git log --no-pager --pretty=format:%H%x1f%ai%x1f%s ${testedVersion}..HEAD`,
      { cwd: gitDir, stdio: ["pipe", "pipe", "pipe"], timeout: 15000 }
    ).toString("utf8");
  } catch {
    return [];
  }

  const results = [];
  for (const line of log.split("\n")) {
    const parts = line.split("\x1f");
    if (parts.length < 3) continue;
    const [commit, date, subject] = parts;

    let filesChanged = [];
    try {
      const files = execSync(
        `git diff-tree --no-commit-id -r --name-only ${commit}`,
        { cwd: gitDir, stdio: ["pipe", "pipe", "pipe"], timeout: 5000 }
      ).toString("utf8").trim().split("\n").filter(Boolean);
      filesChanged = files.slice(0, 20);
    } catch { /* skip */ }

    results.push({ commit: commit.slice(0, 8), date, subject, files_changed: filesChanged });
  }

  return results;
}

module.exports = {
  buildEmptyGitIntel,
  normalizeGitIntel,
  mergeGitIntel,
  buildGitIntelPrompt,
  mineSecurityCommits,
  runVersionDelta
};
