"use strict";
const https = require("node:https");

const DEFAULT_MODEL = "claude-haiku-4-5-20251001";

function buildSystemPrompt(ctx) {
  const findingsSummary = (ctx.recent_findings || [])
    .map(f => `  - [${f.id}] ${f.title} (${f.severity})`)
    .join("\n") || "  (none yet)";

  const logsSummary = (ctx.recent_logs || []).slice(-5).join("\n") || "  (no active run)";

  return [
    `You are a security research assistant embedded in the Agentic BugBounty framework.`,
    ``,
    `Current context:`,
    `  Target: ${ctx.target || "unknown"}`,
    `  Asset type: ${ctx.asset_type || "unknown"}`,
    `  Active run: ${ctx.active_run ? `${ctx.active_run.stage} — ${ctx.active_run.elapsed}` : "none"}`,
    ``,
    `Recent confirmed findings:`,
    findingsSummary,
    ``,
    `Recent log lines:`,
    logsSummary,
    ``,
    `Answer concisely. Use markdown for structure. Focus on actionable security insight.`
  ].join("\n");
}

function buildMessages(message, ctx) {
  return [{ role: "user", content: message }];
}

// Streams response chunks to onChunk(text), calls onDone(err) when complete.
function streamChatResponse(message, ctx, onChunk, onDone) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) { onDone(new Error("ANTHROPIC_API_KEY not set in .env")); return; }

  const model  = process.env.UI_CHAT_MODEL || DEFAULT_MODEL;
  const body   = JSON.stringify({
    model,
    max_tokens: 1024,
    system: buildSystemPrompt(ctx),
    messages: buildMessages(message, ctx),
    stream: true
  });

  const req = https.request({
    hostname: "api.anthropic.com",
    path:     "/v1/messages",
    method:   "POST",
    headers:  {
      "Content-Type":      "application/json",
      "x-api-key":         key,
      "anthropic-version": "2023-06-01",
      "Content-Length":    Buffer.byteLength(body)
    }
  }, (res) => {
    let buf = "";
    res.on("data", chunk => {
      buf += chunk.toString();
      const lines = buf.split("\n");
      buf = lines.pop(); // keep incomplete line
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const data = line.slice(6).trim();
        if (data === "[DONE]") continue;
        try {
          const evt = JSON.parse(data);
          if (evt.type === "content_block_delta" && evt.delta?.text) {
            onChunk(evt.delta.text);
          }
        } catch {}
      }
    });
    res.on("end", () => onDone(null));
    res.on("error", onDone);
    if (res.statusCode !== 200) {
      onDone(new Error(`Anthropic API error: ${res.statusCode}`));
    }
  });

  req.on("error", onDone);
  req.write(body);
  req.end();
}

module.exports = { buildSystemPrompt, buildMessages, streamChatResponse };
