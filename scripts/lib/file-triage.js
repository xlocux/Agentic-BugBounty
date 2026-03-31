"use strict";

const fs   = require("node:fs");
const path = require("node:path");

// ── Exclusion rules ───────────────────────────────────────────────────────────

const EXCLUDE_PATTERNS = [
  // Dependency trees
  /node_modules[\\/]/,
  /vendor[\\/]/,
  /\.git[\\/]/,
  // Build output
  /^dist[\\/]/, /^build[\\/]/, /^\.next[\\/]/, /^\.nuxt[\\/]/,
  /^__pycache__[\\/]/,
  // Minified / compiled
  /\.min\.(js|css)$/,
  /\.bundle\.js$/, /\.map$/,
  // Lockfiles
  /package-lock\.json$/, /composer\.lock$/, /Pipfile\.lock$/,
  /yarn\.lock$/, /poetry\.lock$/, /go\.sum$/,
  // Binary assets
  /\.(png|jpg|jpeg|gif|ico|svg|bmp|webp|woff|woff2|ttf|eot|otf|pdf|mp4|mp3|wav|zip|tar|gz|rar)$/i,
  // Generic docs (keep SECURITY.md, CHANGELOG.md)
  /^docs?[\\/].*\.(md|rst|txt)$/, /^README(\.\w+)?$/i,
];

const LANGUAGE_MAP = {
  js:    "javascript", ts:   "typescript", jsx:  "javascript", tsx: "typescript",
  php:   "php",        py:   "python",     rb:   "ruby",       go:  "go",
  java:  "java",       cs:   "csharp",     cpp:  "cpp",        c:   "c",
  rs:    "rust",       kt:   "kotlin",     swift:"swift",
  html:  "html",       twig: "twig",       ejs:  "html",       hbs: "handlebars",
  pug:   "pug",        blade: "php",
  json:  "json",       yaml: "yaml",       yml:  "yaml",
  xml:   "xml",        env:  "dotenv",     conf: "config",     ini: "config",
};

const RELEVANCE_TAGS = {
  javascript: "routing", typescript: "routing", python: "routing", ruby: "routing",
  go: "routing", java: "routing", php: "routing", csharp: "routing",
  html: "template", twig: "template", handlebars: "template", pug: "template",
  json: "config", yaml: "config", xml: "config", dotenv: "config", config: "config",
};

function detectLanguage(filePath) {
  const ext = path.extname(filePath).replace(".", "").toLowerCase();
  if (!ext) {
    const base = path.basename(filePath).toLowerCase();
    if (base === ".env" || base.startsWith(".env.")) return "dotenv";
    return "other";
  }
  return LANGUAGE_MAP[ext] || "other";
}

function detectRelevanceTag(filePath, language) {
  const lower = filePath.toLowerCase();
  if (/auth|login|session|token|jwt|oauth|saml|sso|password|credential/i.test(lower)) return "auth";
  if (/upload|file|media|image|avatar|attachment/i.test(lower)) return "upload";
  if (/model|entity|schema|migration|orm|database|db/i.test(lower)) return "db";
  if (/route|controller|handler|middleware|api|endpoint/i.test(lower)) return "routing";
  if (/queue|worker|cron|job|event|listener|async/i.test(lower)) return "async";
  if (/config|setting|env|constant/i.test(lower)) return "config";
  if (/template|view|partial|layout/i.test(lower)) return "template";
  return RELEVANCE_TAGS[language] || "other";
}

/**
 * Applies exclusion rules to a list of file paths.
 * Returns entries with path, language, relevance_tag.
 * Does NOT call any LLM — purely deterministic.
 *
 * @param {string[]} filePaths  relative file paths
 * @returns {object[]} filtered + annotated file entries
 */
function classifyFiles(filePaths) {
  return filePaths
    .filter(p => !EXCLUDE_PATTERNS.some(re => re.test(p.replace(/\\/g, "/"))))
    .map(p => {
      const language      = detectLanguage(p);
      const relevance_tag = detectRelevanceTag(p, language);
      const stat          = (() => { try { return fs.statSync(p); } catch { return null; } })();
      return {
        path:          p,
        size_bytes:    stat ? stat.size : null,
        language,
        relevance_tag
      };
    });
}

/**
 * Wraps classified files into a schema_version: 2 manifest.
 * @param {string}   target
 * @param {object[]} files  from classifyFiles()
 * @returns {object} file_manifest.json v2
 */
function buildManifest(target, files) {
  return {
    schema_version: 2,
    generated_at:   new Date().toISOString(),
    target,
    files
  };
}

/**
 * Walks a directory recursively and returns relative paths.
 * Skips symlinks and unreadable entries.
 * @param {string} dir     absolute path
 * @param {string} [base]  used for relative path calculation
 * @returns {string[]}
 */
function walkDir(dir, base = dir) {
  const results = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return results; }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const full = path.join(dir, entry.name);
    const rel  = path.relative(base, full).replace(/\\/g, "/");
    if (entry.isDirectory()) {
      results.push(...walkDir(full, base));
    } else if (entry.isFile()) {
      results.push(rel);
    }
  }
  return results;
}

/**
 * Main entry: walk targetDir, classify, return manifest.
 * Uses only deterministic rules — no LLM call.
 *
 * @param {string} target     target name (for manifest)
 * @param {string} targetDir  absolute path to target source
 * @returns {object} file_manifest.json v2
 */
function runFileTriage(target, targetDir) {
  const allFiles = walkDir(targetDir);
  const classified = classifyFiles(allFiles.map(f => path.join(targetDir, f).replace(/\\/g, "/")));
  // Normalize back to relative paths for portability
  const files = classified.map(f => ({
    ...f,
    path: path.relative(targetDir, f.path).replace(/\\/g, "/")
  }));
  return buildManifest(target, files);
}

module.exports = { classifyFiles, buildManifest, walkDir, runFileTriage, EXCLUDE_PATTERNS };
