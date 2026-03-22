"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

// ─── Config ───────────────────────────────────────────────────────────────────

function loadOpenRouterConfig() {
  const configPath = path.resolve(__dirname, "../../config/openrouter.json");
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    // Fallback if config file is missing
    return {
      free_models: [
        "meta-llama/llama-3.3-70b-instruct:free",
        "qwen/qwen3-coder:free",
        "google/gemma-3-27b-it:free"
      ],
      researcher_model: "openai/gpt-oss-120b:free",
      api_keys_env: ["OPENROUTER_API_KEY_1", "OPENROUTER_API_KEY_2", "OPENROUTER_API_KEY_3", "OPENROUTER_API_KEY_4", "OPENROUTER_API_KEY_5", "OPENROUTER_API_KEY"],
      retry_on_status: [401, 429, 503, 502]
    };
  }
}

const OPENROUTER_CONFIG = loadOpenRouterConfig();

/**
 * Collect all non-empty API keys from env vars listed in config.
 * Returns an array; empty array means no keys configured.
 */
function getApiKeys() {
  const keys = [];
  for (const envVar of (OPENROUTER_CONFIG.api_keys_env || [])) {
    const val = process.env[envVar];
    if (val && val.trim()) keys.push(val.trim());
  }
  // Deduplicate
  return [...new Set(keys)];
}

const RETRY_STATUSES = new Set(OPENROUTER_CONFIG.retry_on_status || [401, 429, 503, 502]);

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Call a free LLM with the given prompt, expecting a JSON object back.
 * Falls back: Gemini CLI (sync via spawnSync) → OpenRouter model+key rotation (async).
 *
 * NOTE: callGeminiCli is intentionally synchronous (uses spawnSync).
 * Do NOT convert it to async — the sync call is correct for script contexts.
 */
async function callLLMJson(prompt, { timeoutMs = 120000 } = {}) {
  const fullPrompt = `${prompt}\n\nRespond ONLY with a valid JSON object. No markdown, no explanation, no code fences.`;

  // 1. Try Gemini via ccw cli (spawnSync — no shell, no quoting issues on any platform)
  try {
    return callGeminiCli(fullPrompt, timeoutMs);
  } catch (e) {
    process.stderr.write(`[llm] Gemini CLI failed: ${e.message}\n`);
  }

  // 2. Try OpenRouter with key+model rotation
  const apiKeys = getApiKeys();
  if (apiKeys.length === 0) {
    throw new Error(
      "All LLM backends failed. Gemini CLI unavailable and no OPENROUTER_API_KEY* env vars are set."
    );
  }

  const models = OPENROUTER_CONFIG.free_models || [];
  for (const model of models) {
    for (const key of apiKeys) {
      try {
        return await callOpenRouter(fullPrompt, model, key, timeoutMs);
      } catch (e) {
        process.stderr.write(`[llm] OpenRouter ${model} (key …${key.slice(-4)}) failed: ${e.message}\n`);
        // Continue to next key/model on retryable errors
      }
    }
  }

  throw new Error("All LLM backends exhausted (Gemini CLI + all OpenRouter free models × all keys).");
}

/**
 * Synchronous Gemini call via ccw cli subprocess.
 * Uses spawnSync with an args array — no shell involved, works on Windows and Unix.
 * NOTE: intentionally synchronous. Do not convert to async.
 */
function callGeminiCli(prompt, timeoutMs) {
  const result = spawnSync(
    "ccw",
    ["cli", "-p", prompt, "--tool", "gemini", "--mode", "analysis"],
    { encoding: "utf8", timeout: timeoutMs, windowsHide: true }
  );
  if (result.status !== 0 || result.error) {
    const errMsg = result.stderr || result.error?.message || `exit code ${result.status}`;
    throw new Error(`ccw cli failed: ${errMsg}`);
  }
  return extractJson(result.stdout || "");
}

/**
 * Call one OpenRouter model with one API key.
 * Throws on HTTP errors — caller rotates to next key/model.
 */
async function callOpenRouter(prompt, model, apiKey, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/agentic-bugbounty",
        "X-Title": "Agentic BugBounty"
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.2,
        response_format: { type: "json_object" }
      }),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}${body ? ": " + body.slice(0, 120) : ""}`);
    }
    const data = await res.json();
    const content = data.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty response from OpenRouter");
    return extractJson(content);
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Call a specific OpenRouter model for researcher use (not the free fallback chain).
 * Rotates through all configured API keys on retryable failures.
 * Falls back to the free model chain if the primary model fails on all keys.
 * Returns the raw text response — researcher outputs are markdown/JSON mixed.
 */
async function callResearcherModel(prompt, { model, timeoutMs = 300000 } = {}) {
  const primaryModel = model || OPENROUTER_CONFIG.researcher_model || "openai/gpt-oss-120b:free";
  const apiKeys = getApiKeys();
  if (apiKeys.length === 0) {
    throw new Error("OPENROUTER_API_KEY* not set — cannot call secondary researcher model");
  }

  // Try primary model with all keys
  for (const key of apiKeys) {
    try {
      return await callOpenRouterRaw(prompt, primaryModel, key, timeoutMs);
    } catch (e) {
      process.stderr.write(`[llm] Researcher model ${primaryModel} (key …${key.slice(-4)}) failed: ${e.message}\n`);
    }
  }

  // Fallback to free model chain (raw text, no JSON enforcement)
  process.stderr.write("[llm] Primary researcher model failed — trying free model fallback chain\n");
  const models = OPENROUTER_CONFIG.free_models || [];
  for (const fallbackModel of models) {
    if (fallbackModel === primaryModel) continue; // already tried
    for (const key of apiKeys) {
      try {
        return await callOpenRouterRaw(prompt, fallbackModel, key, timeoutMs);
      } catch (e) {
        process.stderr.write(`[llm] Fallback ${fallbackModel} (key …${key.slice(-4)}) failed: ${e.message}\n`);
      }
    }
  }

  throw new Error("All researcher model backends exhausted.");
}

/**
 * Raw OpenRouter call — returns text, no JSON parsing.
 */
async function callOpenRouterRaw(prompt, model, apiKey, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/agentic-bugbounty",
        "X-Title": "Agentic BugBounty Dual Researcher"
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.4
      }),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}${body ? ": " + body.slice(0, 120) : ""}`);
    }
    const data = await res.json();
    return data.choices?.[0]?.message?.content || "";
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Extract the first complete JSON object or array from arbitrary text.
 * Uses brace-matching — handles multi-block LLM responses robustly.
 */
function extractJson(text) {
  const openBrace = text.indexOf("{");
  const openBracket = text.indexOf("[");

  let start;
  if (openBrace === -1 && openBracket === -1) {
    throw new Error("No JSON found in LLM response");
  } else if (openBrace === -1) {
    start = openBracket;
  } else if (openBracket === -1) {
    start = openBrace;
  } else {
    start = Math.min(openBrace, openBracket);
  }

  const opener = text[start];
  const closer = opener === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (escape) { escape = false; continue; }
    if (ch === "\\") { escape = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (ch === opener) depth++;
    else if (ch === closer) {
      depth--;
      if (depth === 0) return JSON.parse(text.slice(start, i + 1));
    }
  }
  throw new Error("Unterminated JSON in LLM response");
}

module.exports = { callLLMJson, callResearcherModel };
