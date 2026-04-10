"use strict";

/**
 * openrouter-agent.js
 * Minimal agentic loop for OpenRouter models.
 * Implements read_file / write_file / bash / list_dir tools so the
 * researcher and triager agents can operate as they do under the Claude CLI.
 */

const fs      = require("node:fs");
const path    = require("node:path");
const { execSync } = require("node:child_process");

const OR_API_URL = "https://openrouter.ai/api/v1/chat/completions";
const MAX_ITER   = 80;   // hard ceiling on agentic turns
const MAX_TOKENS = 8192; // per call

// ── Tool definitions ───────────────────────────────────────────────────────

const TOOLS = [
  {
    type: "function",
    function: {
      name: "read_file",
      description: "Read the full text content of a file.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Absolute or project-relative path." }
        },
        required: ["path"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "write_file",
      description: "Create or overwrite a file with the given content.",
      parameters: {
        type: "object",
        properties: {
          path:    { type: "string" },
          content: { type: "string" }
        },
        required: ["path", "content"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "bash",
      description: "Run a shell command and return its stdout/stderr (max 8 KB).",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string" }
        },
        required: ["command"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "list_dir",
      description: "List the files and directories inside a directory (non-recursive).",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string" }
        },
        required: ["path"]
      }
    }
  }
];

// ── Tool execution ─────────────────────────────────────────────────────────

const BLOCKED_COMMANDS = /rm\s+-rf\s+\/|mkfs|dd\s+if=|shutdown|reboot|format\s+[A-Za-z]:/i;

function executeTool(name, args) {
  try {
    switch (name) {
      case "read_file": {
        const content = fs.readFileSync(args.path, "utf8");
        return { output: content.slice(0, 32768) }; // cap at 32 KB
      }
      case "write_file": {
        fs.mkdirSync(path.dirname(args.path), { recursive: true });
        fs.writeFileSync(args.path, args.content, "utf8");
        return { output: `Written ${args.content.length} bytes to ${args.path}` };
      }
      case "bash": {
        if (BLOCKED_COMMANDS.test(args.command)) {
          return { error: "Command blocked by safety filter." };
        }
        const out = execSync(args.command, {
          encoding: "utf8",
          timeout: 30000,
          maxBuffer: 8 * 1024 * 1024
        });
        return { output: out.slice(0, 8192) };
      }
      case "list_dir": {
        const entries = fs.readdirSync(args.path, { withFileTypes: true });
        const lines   = entries.map((e) => (e.isDirectory() ? `[dir]  ${e.name}` : `[file] ${e.name}`));
        return { output: lines.join("\n") };
      }
      default:
        return { error: `Unknown tool: ${name}` };
    }
  } catch (err) {
    return { error: err.message };
  }
}

// ── OpenRouter API call ────────────────────────────────────────────────────

async function callOpenRouter(messages, model, apiKey) {
  const res = await fetch(OR_API_URL, {
    method:  "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${apiKey}`,
      "HTTP-Referer":  "https://github.com/agentic-bugbounty",
      "X-Title":       "Agentic Bug Bounty",
    },
    body: JSON.stringify({
      model,
      messages,
      tools:        TOOLS,
      tool_choice:  "auto",
      max_tokens:   MAX_TOKENS,
    })
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`OpenRouter HTTP ${res.status}: ${body.slice(0, 300)}`);
  }
  return res.json();
}

// ── Agent loop ─────────────────────────────────────────────────────────────

/**
 * Run an agentic loop on OpenRouter.
 * @param {string}   prompt   - Full agent prompt (from compose-agent-prompt.js).
 * @param {string}   model    - OpenRouter model ID.
 * @param {string}   apiKey   - OPENROUTER_API_KEY.
 * @param {Function} logFn    - Called with each text line for live output.
 * @param {string}   [logPath]- Optional file path to append output lines.
 */
async function runOpenRouterAgent(prompt, model, apiKey, logFn, logPath) {
  if (!apiKey) throw new Error("OPENROUTER_API_KEY not set — add it in Settings.");

  const messages = [{ role: "user", content: prompt }];
  let iteration  = 0;

  while (iteration < MAX_ITER) {
    iteration++;

    let data;
    try {
      data = await callOpenRouter(messages, model, apiKey);
    } catch (err) {
      throw new Error(`OpenRouter API error (iter ${iteration}): ${err.message}`);
    }

    const choice = data.choices?.[0];
    if (!choice) throw new Error("OpenRouter returned empty choices.");

    const msg = choice.message;
    messages.push(msg);

    // Stream any text content to the log
    if (msg.content) {
      for (const line of msg.content.split("\n")) {
        logFn(line);
        if (logPath) {
          try { fs.appendFileSync(logPath, line + "\n", "utf8"); } catch { /* non-fatal */ }
        }
      }
    }

    // Done — no tool calls
    if (!msg.tool_calls || msg.tool_calls.length === 0) break;

    // Execute each tool call and collect results
    const toolResults = [];
    for (const tc of msg.tool_calls) {
      let fnArgs;
      try { fnArgs = JSON.parse(tc.function.arguments); } catch { fnArgs = {}; }

      logFn(`[tool: ${tc.function.name}] ${JSON.stringify(fnArgs).slice(0, 120)}`);

      const result   = executeTool(tc.function.name, fnArgs);
      const resultTx = result.error ? `ERROR: ${result.error}` : (result.output || "");

      toolResults.push({
        role:         "tool",
        tool_call_id: tc.id,
        content:      resultTx.slice(0, 16384), // cap tool result size
      });
    }
    messages.push(...toolResults);
  }

  if (iteration >= MAX_ITER) {
    logFn(`[openrouter-agent] reached max iterations (${MAX_ITER}) — stopping.`);
  }
}

module.exports = { runOpenRouterAgent };
