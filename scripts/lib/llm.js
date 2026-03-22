"use strict";

const { spawnSync } = require("node:child_process");

const OPENROUTER_MODELS = [
  "meta-llama/llama-4-scout:free",
  "qwen/qwen3-4b:free",
  "google/gemini-2.5-flash-preview:free"
];

/**
 * Call a free LLM with the given prompt, expecting a JSON object back.
 * Falls back: Gemini CLI (sync via spawnSync) → OpenRouter model chain (async).
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

  // 2. Try OpenRouter models in order
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    throw new Error(
      "All LLM backends failed. Gemini CLI unavailable and OPENROUTER_API_KEY is not set."
    );
  }
  for (const model of OPENROUTER_MODELS) {
    try {
      return await callOpenRouter(fullPrompt, model, apiKey, timeoutMs);
    } catch (e) {
      process.stderr.write(`[llm] OpenRouter ${model} failed: ${e.message}\n`);
    }
  }

  throw new Error("All LLM backends exhausted (Gemini CLI + all OpenRouter free models).");
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
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
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
 * Returns the raw text response — researcher outputs are markdown/JSON mixed.
 */
async function callResearcherModel(prompt, { model = "openai/gpt-4.5-preview", timeoutMs = 300000 } = {}) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) throw new Error("OPENROUTER_API_KEY not set — cannot call secondary researcher model");
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
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
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
