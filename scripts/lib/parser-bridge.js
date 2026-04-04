"use strict";

/**
 * parser-bridge.js — Bridge Node.js → Python deterministic parser.
 *
 * Spawns scripts/lib/parser.py and communicates via JSON on stdin/stdout.
 * No LLM calls — everything is deterministic and fast.
 *
 * API:
 *   const { parse } = require("./parser-bridge");
 *   const result = parse("js_endpoints", { content: "..." });
 *   const result = parse("html_links",   { content: "...", url: "https://..." });
 *   const result = parse("secrets",      { content: "..." });
 *   const result = parse("headers",      { content: "Server: nginx\n..." });
 *   const result = parse("deps",         { content: "...", filename: "package.json" });
 *   const result = parse("full_url",     { url: "https://target.com" });
 */

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

const PARSER_SCRIPT = path.resolve(__dirname, "parser.py");
const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Run the Python parser for a specific task.
 *
 * @param {string} task — "html_links" | "js_endpoints" | "secrets" | "headers" | "deps" | "full_url"
 * @param {object} opts — { content?, url?, filename?, max_bytes?, timeoutMs? }
 * @returns {{ results: object, stats: object } | null} — null on error
 */
function parse(task, opts = {}) {
  if (!fs.existsSync(PARSER_SCRIPT)) {
    return null; // parser.py not found — graceful degradation
  }

  const input = JSON.stringify({
    task,
    content:   opts.content   || "",
    url:       opts.url       || "",
    filename:  opts.filename  || "",
    max_bytes: opts.max_bytes || 100_000,
  });

  // Try python3 first, then python as fallback
  const pythonBin = process.platform === "win32" ? "python" : "python3";

  const result = spawnSync(pythonBin, [PARSER_SCRIPT], {
    input,
    encoding:    "utf8",
    timeout:     opts.timeoutMs || DEFAULT_TIMEOUT_MS,
    windowsHide: true,
    maxBuffer:   10 * 1024 * 1024, // 10MB max output
  });

  if (result.error || result.status !== 0) {
    return null; // Silent fallback
  }

  try {
    const parsed = JSON.parse(result.stdout.trim());
    if (parsed.error) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Batch version: runs multiple tasks via Promise.allSettled.
 * Each has its own separate Python process (no shared state).
 *
 * @param {Array<{task: string, opts: object}>} tasks
 * @returns {Promise<Array<object|null>>}
 */
async function parseBatch(tasks) {
  return Promise.allSettled(
    tasks.map(({ task, opts }) =>
      new Promise((resolve) => resolve(parse(task, opts)))
    )
  ).then((results) =>
    results.map((r) => (r.status === "fulfilled" ? r.value : null))
  );
}

module.exports = { parse, parseBatch };
