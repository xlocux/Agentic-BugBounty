"use strict";

/**
 * hybrid-recon.js
 *
 * Executes Phase 0 (calibration) and Phase 1 (source recon) using a free
 * LLM (OpenRouter / Gemini CLI) so Claude only handles Phase 2+ analysis.
 *
 * Output: a structured recon_context object injected into the Claude prompt.
 *
 * Failure contract:
 *   - Any error at any step is caught and logged — the pipeline NEVER aborts.
 *   - On failure the function returns null; the caller falls back to letting
 *     Claude do the full Phase 0+1 itself (existing behaviour, no regression).
 */

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

// Load .env so OPENROUTER_API_KEY* are available when this module is used standalone
(function loadDotEnv() {
  const envPath = path.resolve(__dirname, "../../.env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim();
    if (key && !(key in process.env)) process.env[key] = val;
  }
})();

const { callLLMJson } = require("./llm");

// ─── Helpers ──────────────────────────────────────────────────────────────────

function log(msg) {
  process.stdout.write(`  \x1b[2m[hybrid-recon] ${msg}\x1b[0m\n`);
}

/**
 * Run a node script and return its stdout as a string.
 * Returns "" on failure — callers treat empty string as "unavailable".
 */
function runScript(scriptArgs, cwd) {
  const result = spawnSync("node", scriptArgs, {
    encoding: "utf8",
    timeout: 30000,
    windowsHide: true,
    cwd: cwd || process.cwd()
  });
  if (result.status !== 0 || result.error) return "";
  return (result.stdout || "").trim();
}

/**
 * Walk a directory and return a list of source-code files up to maxFiles.
 * Skips node_modules, .git, build artefacts.
 */
function walkSourceFiles(dir, maxFiles = 300) {
  const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "__pycache__", ".gradle", "vendor"]);
  const SOURCE_EXTS = new Set([
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".java", ".kt", ".swift", ".go", ".rb",
    ".php", ".cs", ".cpp", ".c", ".h", ".rs",
    ".json", ".xml", ".yaml", ".yml", ".html", ".htm"
  ]);
  const results = [];

  function walk(current) {
    if (results.length >= maxFiles) return;
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (results.length >= maxFiles) return;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(path.join(current, entry.name));
      } else if (entry.isFile()) {
        if (SOURCE_EXTS.has(path.extname(entry.name).toLowerCase())) {
          results.push(path.join(current, entry.name));
        }
      }
    }
  }

  if (fs.existsSync(dir)) walk(dir);
  return results;
}

/**
 * Read the first N lines of a file (for quick content sampling).
 */
function readFileHead(filePath, lines = 60) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    return content.split("\n").slice(0, lines).join("\n");
  } catch {
    return "";
  }
}

// ─── Phase 0: Calibration via query-calibration.js ───────────────────────────

function runCalibrationPhase(assetType, projectRoot) {
  log(`phase 0: loading calibration briefing for ${assetType}...`);
  const calibrationJson = runScript(
    ["scripts/query-calibration.js", "--asset", assetType, "--json"],
    projectRoot
  );
  if (!calibrationJson) {
    log("phase 0: calibration script unavailable — skipping");
    return null;
  }
  try {
    return JSON.parse(calibrationJson);
  } catch {
    log("phase 0: calibration output not JSON — skipping");
    return null;
  }
}

// ─── Phase 1: Source Recon via LLM ───────────────────────────────────────────

async function runSourceReconPhase(assetType, sourceDir, calibrationData) {
  log(`phase 1: walking source tree at ${sourceDir}...`);

  const files = walkSourceFiles(sourceDir);
  if (files.length === 0) {
    log("phase 1: no source files found — skipping LLM recon");
    return null;
  }

  log(`phase 1: found ${files.length} source files — sampling key files...`);

  // Sample: manifest/config/entry-point files get full head; rest just paths
  const KEY_PATTERNS = [
    /manifest/i, /package\.json$/, /config/i, /settings/i, /routes?/i,
    /index\.(js|ts|html)$/i, /main\.(js|ts|java|kt|swift|go)$/i,
    /auth/i, /background/i, /content.?script/i, /service.?worker/i
  ];

  const sampledFiles = [];
  const pathsOnly = [];

  for (const f of files) {
    const rel = path.relative(sourceDir, f);
    if (KEY_PATTERNS.some((p) => p.test(rel))) {
      sampledFiles.push({ path: rel, head: readFileHead(f, 50) });
    } else {
      pathsOnly.push(rel);
    }
  }

  // Cap samples to avoid overloading the free model context window
  const MAX_SAMPLES = 20;
  const truncatedSamples = sampledFiles.slice(0, MAX_SAMPLES);
  const truncatedPaths = pathsOnly.slice(0, 200);

  const calibrationSummary = calibrationData
    ? `Top vuln classes for ${assetType}: ${
        (calibrationData.top_classes || []).slice(0, 5).map((c) => c.name || c).join(", ")
      }`
    : `No calibration data available for ${assetType}.`;

  const prompt = `You are a security researcher performing Phase 1 source reconnaissance on a ${assetType} asset.

CALIBRATION CONTEXT:
${calibrationSummary}

SOURCE FILES (${files.length} total):

KEY FILES WITH CONTENT:
${truncatedSamples.map((f) => `### ${f.path}\n\`\`\`\n${f.head}\n\`\`\``).join("\n\n")}

ALL FILE PATHS:
${truncatedPaths.join("\n")}

Your task: produce a structured JSON reconnaissance report with these fields:
{
  "entry_points": ["list of main entry point files"],
  "auth_layer": ["files handling authentication/authorization"],
  "data_sinks": ["files likely containing dangerous sinks: eval, innerHTML, exec, query, etc."],
  "ipc_channels": ["files handling message passing, IPC, intents, postMessage, etc."],
  "external_comms": ["files making HTTP requests or talking to external services"],
  "config_files": ["configuration and credential files"],
  "interesting_patterns": ["up to 10 specific file:pattern pairs worth investigating, e.g. 'background.js: uses eval()'"],
  "attack_surface_summary": "2-3 sentence summary of the most promising attack surface for a ${assetType}"
}

Be specific. File paths must be real paths from the list above.`;

  log("phase 1: asking free LLM to map attack surface...");
  const result = await callLLMJson(prompt, { timeoutMs: 90000 });
  log("phase 1: recon map received");
  return result;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Run hybrid Phase 0+1 and return a context object to inject into the Claude prompt.
 * Returns null on any failure — the pipeline must fall back gracefully.
 *
 * @param {object} assetContext  Pipeline asset context (asset, target, mode, targetRef, ...)
 * @param {string} projectRoot   Absolute path to the project root (for running scripts)
 * @returns {object|null}        Recon context or null if unavailable
 */
async function runHybridRecon(assetContext, projectRoot) {
  const { asset: assetType, target: sourceDir } = assetContext;

  log(`starting hybrid recon for ${assetType} at ${sourceDir}`);

  // Phase 0: calibration (sync, fast)
  let calibrationData = null;
  try {
    calibrationData = runCalibrationPhase(assetType, projectRoot);
  } catch (e) {
    log(`phase 0 error: ${e.message} — continuing without calibration`);
  }

  // Phase 1: source recon (async, LLM-powered)
  let reconMap = null;
  try {
    reconMap = await runSourceReconPhase(assetType, sourceDir, calibrationData);
  } catch (e) {
    log(`phase 1 error: ${e.message} — continuing without recon map`);
  }

  if (!calibrationData && !reconMap) {
    log("hybrid recon produced no output — Claude will handle Phase 0+1 itself");
    return null;
  }

  const result = {
    generated_at: new Date().toISOString(),
    asset_type: assetType,
    source_dir: sourceDir,
    calibration: calibrationData,
    recon_map: reconMap
  };

  log(`hybrid recon complete — injecting context into Claude prompt`);
  return result;
}

/**
 * Format the recon context into a prompt section for Claude.
 * Returns "" if context is null.
 */
function formatReconContextForPrompt(reconContext) {
  if (!reconContext) return "";

  const lines = [
    "",
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    "PRE-COMPUTED RECON — SKIP Phase 0 and Phase 1 (already done below)",
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    `Generated: ${reconContext.generated_at}`,
    ""
  ];

  if (reconContext.calibration) {
    lines.push("## CALIBRATION BRIEFING (Phase 0 output)");
    lines.push("```json");
    lines.push(JSON.stringify(reconContext.calibration, null, 2));
    lines.push("```");
    lines.push("");
  }

  if (reconContext.recon_map) {
    const m = reconContext.recon_map;
    lines.push("## SOURCE RECON MAP (Phase 1 output)");

    if (m.attack_surface_summary) {
      lines.push(`**Attack surface:** ${m.attack_surface_summary}`);
      lines.push("");
    }
    if (m.entry_points?.length) {
      lines.push(`**Entry points:** ${m.entry_points.join(", ")}`);
    }
    if (m.auth_layer?.length) {
      lines.push(`**Auth layer:** ${m.auth_layer.join(", ")}`);
    }
    if (m.data_sinks?.length) {
      lines.push(`**Data sinks:** ${m.data_sinks.join(", ")}`);
    }
    if (m.ipc_channels?.length) {
      lines.push(`**IPC / messaging:** ${m.ipc_channels.join(", ")}`);
    }
    if (m.external_comms?.length) {
      lines.push(`**External comms:** ${m.external_comms.join(", ")}`);
    }
    if (m.interesting_patterns?.length) {
      lines.push("");
      lines.push("**Patterns worth investigating:**");
      for (const p of m.interesting_patterns) {
        lines.push(`  - ${p}`);
      }
    }
    lines.push("");
  }

  lines.push("Start directly at Phase 2 (Static Analysis) using the recon map above.");
  lines.push("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  return lines.join("\n");
}

module.exports = { runHybridRecon, formatReconContextForPrompt };
