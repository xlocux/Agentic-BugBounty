"use strict";

/**
 * explorer.js — Surface mapping agent (refactored with deterministic parser).
 *
 * Architecture:
 *   1. Deterministic parser (parser.py via parser-bridge.js)
 *      → extracts links, endpoints, secrets, tech, deps in milliseconds, zero tokens
 *   2. LLM (optional, only if OPENROUTER_API_KEY present)
 *      → classifies "interesting" endpoints from a compact batch of structured data
 *      → evaluates if a pattern looks like a real secret vs. placeholder (small batch)
 *
 * Failure contract: every error is isolated. The Explorer never blocks the pipeline.
 */

const fs   = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { parse } = require("./parser-bridge");
const { callLLMJson } = require("./llm");

// ─── Helpers ──────────────────────────────────────────────────────────────────

function log(msg) {
  process.stdout.write(`  \x1b[2m[explorer] ${msg}\x1b[0m\n`);
}

function findFiles(dir, extensions, maxFiles = 30) {
  if (!dir || !fs.existsSync(dir)) return [];
  try {
    const result = spawnSync(
      process.platform === "win32" ? "where" : "find",
      process.platform === "win32"
        ? [] // fallback handled below
        : [dir, "-type", "f",
           "-not", "-path", "*/node_modules/*",
           "-not", "-path", "*/.git/*",
           "-not", "-path", "*/dist/*",
           "-not", "-path", "*/build/*",
           ...extensions.flatMap((e) => ["-o", "-name", `*.${e}`]).slice(1)],
      { encoding: "utf8", timeout: 10_000 }
    );
    if (result.error || result.status !== 0) return fallbackFindFiles(dir, extensions, maxFiles);
    return (result.stdout || "").split("\n").filter(Boolean).slice(0, maxFiles);
  } catch {
    return fallbackFindFiles(dir, extensions, maxFiles);
  }
}

function fallbackFindFiles(dir, extensions, maxFiles) {
  const results = [];
  const extSet = new Set(extensions.map((e) => `.${e}`));
  function walk(d, depth) {
    if (depth > 6 || results.length >= maxFiles) return;
    try {
      const entries = fs.readdirSync(d, { withFileTypes: true });
      for (const entry of entries) {
        if (results.length >= maxFiles) return;
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) {
          if (["node_modules", ".git", "dist", "build", "__pycache__"].includes(entry.name)) continue;
          walk(full, depth + 1);
        } else if (entry.isFile() && extSet.has(path.extname(entry.name).toLowerCase())) {
          results.push(full);
        }
      }
    } catch { /* ignore permission errors */ }
  }
  walk(dir, 0);
  return results;
}

function safeReadFile(filePath, maxBytes = 200_000) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxBytes) {
      const buf = Buffer.alloc(maxBytes);
      const fd = fs.openSync(filePath, "r");
      fs.readSync(fd, buf, 0, maxBytes, 0);
      fs.closeSync(fd);
      return buf.toString("utf8");
    }
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

// ─── Step 1: Deterministic parser ────────────────────────────────────────────

async function runDeterministicParsing(assetContext) {
  const results = {
    endpoints:    [],
    secrets:      [],
    technologies: [],
    deps:         [],
    links:        [],
    auth_patterns:[],
    storage_keys: [],
    missing_security_headers: [],
    information_leakage: [],
  };

  const targetDir = assetContext.target;

  // ── Dependency manifests (any asset type) ─────────────────────────────────
  const depFiles = [
    "package.json", "requirements.txt", "pom.xml",
    "build.gradle", "Gemfile", "composer.json", "go.mod",
  ];

  if (targetDir && fs.existsSync(targetDir)) {
    for (const depFile of depFiles) {
      const fullPath = path.join(targetDir, depFile);
      const content = safeReadFile(fullPath, 100_000);
      if (content) {
        const parsed = parse("deps", { content, filename: depFile });
        if (parsed?.results) {
          results.deps.push(...(parsed.results.flagged_packages || []));
        }
      }
    }
  }

  // ── JS/TS endpoint extraction (whitebox) ──────────────────────────────────
  if (assetContext.mode === "whitebox" && targetDir && fs.existsSync(targetDir)) {
    const jsFiles = findFiles(targetDir, ["js", "ts", "jsx", "tsx", "mjs"], 25);
    for (const jsFile of jsFiles) {
      const content = safeReadFile(jsFile, 150_000);
      if (!content) continue;

      // Endpoints
      const epResult = parse("js_endpoints", { content });
      if (epResult?.results) {
        results.endpoints.push(...(epResult.results.endpoints || []));
        results.auth_patterns.push(...(epResult.results.auth_patterns || []));
        results.storage_keys.push(...(epResult.results.storage_keys || []));
      }

      // Secrets
      const secResult = parse("secrets", { content });
      if (secResult?.results?.secrets?.length > 0) {
        results.secrets.push(
          ...secResult.results.secrets.map((s) => ({ ...s, file: path.relative(targetDir, jsFile) }))
        );
      }
    }

    // PHP, Python, Ruby, Java source
    const sourceFiles = findFiles(targetDir, ["php", "py", "rb", "java", "go"], 20);
    for (const srcFile of sourceFiles) {
      const content = safeReadFile(srcFile, 100_000);
      if (!content) continue;
      const secResult = parse("secrets", { content });
      if (secResult?.results?.secrets?.length > 0) {
        results.secrets.push(
          ...secResult.results.secrets.map((s) => ({ ...s, file: path.relative(targetDir, srcFile) }))
        );
      }
    }

    // HTML files — links and forms
    const htmlFiles = findFiles(targetDir, ["html", "htm"], 10);
    for (const htmlFile of htmlFiles) {
      const content = safeReadFile(htmlFile, 200_000);
      if (!content) continue;
      const htmlResult = parse("html_links", { content });
      if (htmlResult?.results) {
        results.links.push(...(htmlResult.results.links || []));
      }
    }
  }

  // ── Blackbox: fetch URL and parse ─────────────────────────────────────────
  const targetUrl = assetContext.target && assetContext.target.startsWith("http")
    ? assetContext.target
    : null;

  if (targetUrl) {
    const fetchResult = parse("full_url", { url: targetUrl });
    if (fetchResult?.results && !fetchResult.results.error) {
      const fr = fetchResult.results;

      // Analyze headers
      const headerText = Object.entries(fr.headers || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join("\n");
      const headerResult = parse("headers", { content: headerText });
      if (headerResult?.results) {
        results.technologies.push(...(headerResult.results.technologies || []));
        results.missing_security_headers.push(
          ...(headerResult.results.missing_security_headers || [])
        );
        results.information_leakage.push(
          ...(headerResult.results.information_leakage || [])
        );
      }

      // Analyze HTML body
      if (fr.body_snippet && fr.content_type?.includes("html")) {
        const htmlResult = parse("html_links", {
          content: fr.body_snippet,
          url: targetUrl,
        });
        if (htmlResult?.results) {
          results.links.push(...(htmlResult.results.links || []).slice(0, 30));
        }
      }

      // Secrets in body (e.g. exposed API key on page)
      if (fr.body_snippet) {
        const secResult = parse("secrets", { content: fr.body_snippet });
        if (secResult?.results?.secrets?.length > 0) {
          results.secrets.push(...secResult.results.secrets);
        }
      }
    }
  }

  // Deduplication
  results.endpoints = deduplicateBy(results.endpoints, "path");
  results.secrets   = deduplicateBy(results.secrets, "masked_value");
  results.technologies = deduplicateBy(results.technologies, "name");

  return results;
}

function deduplicateBy(arr, key) {
  const seen = new Set();
  return arr.filter((item) => {
    const val = item[key];
    if (seen.has(val)) return false;
    seen.add(val);
    return true;
  });
}

// ─── Step 2: LLM classification (only on already-structured data) ─────────────

/**
 * Calls the LLM ONLY to classify endpoints as "interesting" for security.
 * Input: compact list of paths already extracted by the parser (~500 tokens max).
 * Output: subset of endpoints with security notes.
 */
async function classifyEndpointsWithLLM(endpoints) {
  if (!endpoints || endpoints.length === 0) return [];
  if (!process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY_1) {
    return endpoints.slice(0, 10); // Without LLM, return first 10
  }

  // Compact batch — only path and method, max 40 endpoints
  const batch = endpoints.slice(0, 40).map((ep) => ({
    path:   ep.path,
    method: ep.method || "unknown",
  }));

  const prompt = `You are a security researcher. Given these API endpoints extracted from a web application,
identify which ones are most interesting for security testing (auth bypass, IDOR, injection, sensitive data).

Endpoints:
${JSON.stringify(batch, null, 2)}

Respond with JSON only:
{
  "interesting": [
    { "path": "/api/...", "reason": "one sentence", "vuln_class": "IDOR|injection|auth|info_disclosure|other" }
  ]
}

Include at most 15 endpoints. Only include genuinely interesting ones, not static assets or public pages.`;

  try {
    const result = await callLLMJson(prompt, { timeoutMs: 30_000 });
    return result?.interesting || [];
  } catch {
    return [];
  }
}

// ─── Formatter output ─────────────────────────────────────────────────────────

function formatExplorerContextForPrompt(parsed, classified) {
  const parts = [];

  if (parsed.secrets?.length > 0) {
    parts.push("SECRETS / CREDENTIALS DETECTED:");
    for (const s of parsed.secrets.slice(0, 10)) {
      parts.push(`  • [${s.type}] entropy=${s.entropy} len=${s.length}${s.file ? ` in ${s.file}` : ""}`);
      parts.push(`    Context: ${s.context}`);
    }
  }

  if (classified?.length > 0) {
    parts.push("\nINTERESTING API ENDPOINTS (classified):");
    for (const ep of classified) {
      parts.push(`  • ${ep.path} [${ep.vuln_class}] — ${ep.reason}`);
    }
  } else if (parsed.endpoints?.length > 0) {
    parts.push(`\nAPI ENDPOINTS (${parsed.endpoints.length} found, top 15):`);
    for (const ep of parsed.endpoints.slice(0, 15)) {
      parts.push(`  • ${ep.method || "?"} ${ep.path} [${ep.source}]`);
    }
  }

  if (parsed.auth_patterns?.length > 0) {
    parts.push("\nAUTH PATTERNS:");
    for (const ap of parsed.auth_patterns.slice(0, 5)) {
      parts.push(`  • ${ap.type}: ${ap.context}`);
    }
  }

  if (parsed.storage_keys?.length > 0) {
    parts.push(`\nlocalStorage/sessionStorage KEYS (XSS targets): ${parsed.storage_keys.join(", ")}`);
  }

  if (parsed.technologies?.length > 0) {
    parts.push(`\nDETECTED STACK: ${parsed.technologies.map((t) => t.name).join(", ")}`);
  }

  if (parsed.missing_security_headers?.length > 0) {
    parts.push(`\nMISSING SECURITY HEADERS: ${parsed.missing_security_headers.map((h) => h.header).join(", ")}`);
  }

  if (parsed.information_leakage?.length > 0) {
    parts.push("\nINFORMATION LEAKAGE:");
    for (const leak of parsed.information_leakage.slice(0, 5)) {
      parts.push(`  • ${leak.header}: ${leak.risk}`);
    }
  }

  if (parsed.deps?.length > 0) {
    parts.push("\nFLAGGED DEPENDENCIES:");
    for (const dep of parsed.deps.slice(0, 8)) {
      parts.push(`  • ${dep.package}@${dep.version} — ${dep.flag}`);
    }
  }

  if (parsed.links?.length > 0) {
    const interesting = parsed.links.filter((l) =>
      /admin|api|internal|debug|config|login|auth|upload|download/.test(l.url)
    );
    if (interesting.length > 0) {
      parts.push(`\nINTERESTING LINKS (${interesting.length}):`);
      for (const l of interesting.slice(0, 10)) {
        parts.push(`  • [${l.tag}] ${l.url}`);
      }
    }
  }

  if (parts.length === 0) return "";

  return `\n\nEXPLORER AGENT PRE-ANALYSIS (deterministic parser)\n${"─".repeat(50)}\n${parts.join("\n")}\n${"─".repeat(50)}\nUse the above to prioritize your analysis. Do not re-verify what Explorer already confirmed.\n`;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function runExplorer(assetContext, projectRoot) {
  log("starting deterministic surface analysis...");
  const t0 = Date.now();

  let parsed = {};
  let classified = [];

  try {
    parsed = await runDeterministicParsing(assetContext);
    const elapsed1 = Date.now() - t0;
    log(`parser done in ${elapsed1}ms — endpoints:${parsed.endpoints?.length || 0} secrets:${parsed.secrets?.length || 0} tech:${parsed.technologies?.length || 0}`);
  } catch (e) {
    log(`parser error: ${e.message}`);
    return "";
  }

  // LLM classification only if there are enough endpoints and OpenRouter is configured
  if ((parsed.endpoints?.length || 0) > 5 &&
      (process.env.OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY_1)) {
    try {
      classified = await classifyEndpointsWithLLM(parsed.endpoints);
      const elapsed2 = Date.now() - t0;
      log(`LLM classification done in ${elapsed2}ms — ${classified.length} interesting endpoints`);
    } catch (e) {
      log(`LLM classification skipped: ${e.message}`);
    }
  }

  const hint = formatExplorerContextForPrompt(parsed, classified);
  const elapsed = Date.now() - t0;
  log(`total elapsed: ${elapsed}ms`);

  return hint;
}

module.exports = { runExplorer };
