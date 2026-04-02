"use strict";

/**
 * notify.js — provider-agnostic notification layer.
 *
 * Supported channels: telegram, discord, slack
 * Config: config/apis.json → notifications
 * Keys:   .env → TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DISCORD_WEBHOOK_URL, SLACK_WEBHOOK_URL
 *
 * Usage:
 *   const { notify, notifyBatch } = require("./notify");
 *   await notify("finding_confirmed", { severity: "Critical", title: "SQLi in /api/users", url: "..." });
 *   await notifyBatch("new_subdomain_bulk", items);
 */

const fs   = require("node:fs");
const path = require("node:path");

const CONFIG_PATH = path.resolve(__dirname, "../../config/apis.json");
let _config = null;

function getConfig() {
  if (!_config) _config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  return _config;
}

const SEVERITY_EMOJI = {
  critical: "🔴",
  high:     "🟠",
  medium:   "🟡",
  low:      "🔵",
  info:     "⚪"
};

const EVENT_EMOJI = {
  finding_confirmed:             "🎯",
  cve_match:                     "⚡",
  new_subdomain_interesting:     "🆕",
  subdomain_takeover_candidate:  "⚠️",
  new_subdomain_bulk:            "📋",
  subdomain_dead:                "💀",
  tech_stack_changed:            "🔄",
  run_completed:                 "✅",
  session_limit_hit:             "⏸️",
  scheduled_scan_started:        "⏰",
  // v2 cyberpunk events
  agent_completed:               "🤖",
  all_agents_completed:          "🏁",
  chain_found:                   "⛓️",
  secret_found:                  "🔑",
  patch_bypass_found:            "🩹",
  stage_completed:               "✅",
  setup_failed:                  "❌",
  teleport_ready:                "📦",
  progress_update:               "📊"
};

// ── Message builders ──────────────────────────────────────────────────────────

function buildMessage(event, data) {
  const emoji = EVENT_EMOJI[event] || "ℹ️";

  switch (event) {
    case "finding_confirmed": {
      const sev = (data.severity || "").toLowerCase();
      return [
        `${emoji} ${SEVERITY_EMOJI[sev] || ""} *FINDING — ${(data.severity || "").toUpperCase()}*`,
        "",
        `*${escMd(data.title || "Untitled")}*`,
        data.target     ? `Target:    \`${escMd(data.target)}\`` : null,
        data.component  ? `Component: \`${escMd(data.component)}\`` : null,
        data.vuln_class ? `Class:     ${escMd(data.vuln_class)}` : null,
        data.report_id  ? `ID:        ${escMd(data.report_id)}` : null,
        data.url        ? `\n[View report](${data.url})` : null
      ].filter(Boolean).join("\n");
    }

    case "cve_match": {
      const lines = [
        `${emoji} *CVE MATCH — ${escMd(data.cve_id || "")}*`,
        "",
        data.description ? escMd(truncate(data.description, 200)) : null,
        data.cvss_score  ? `CVSS: *${data.cvss_score}*` : null,
        "",
        "*Affected hosts in scope:*"
      ];
      if (Array.isArray(data.hosts)) {
        for (const h of data.hosts.slice(0, 5)) {
          const conf = h.confidence ? ` _(${h.confidence})_` : "";
          const ver  = h.version    ? ` — v${escMd(h.version)}` : "";
          lines.push(`  • \`${escMd(h.subdomain)}\`${ver}${conf}`);
        }
        if (data.hosts.length > 5) lines.push(`  _…and ${data.hosts.length - 5} more_`);
      }
      if (data.nvd_url) lines.push(`\n[NVD](${data.nvd_url})`);
      return lines.filter(Boolean).join("\n");
    }

    case "new_subdomain_interesting": {
      return [
        `${emoji} *NEW INTERESTING SUBDOMAIN*`,
        "",
        `\`${escMd(data.subdomain || "")}\``,
        data.target      ? `Target:  ${escMd(data.target)}` : null,
        data.ip          ? `IP:      \`${escMd(data.ip)}\`` : null,
        data.tech        ? `Stack:   ${escMd(data.tech)}` : null,
        data.http_status ? `HTTP:    ${data.http_status}` : null
      ].filter(Boolean).join("\n");
    }

    case "subdomain_takeover_candidate": {
      return [
        `${emoji} *TAKEOVER CANDIDATE*`,
        "",
        `\`${escMd(data.subdomain || "")}\``,
        data.cname    ? `CNAME:    \`${escMd(data.cname)}\`` : null,
        data.provider ? `Provider: ${escMd(data.provider)}` : null,
        data.target   ? `Target:   ${escMd(data.target)}` : null
      ].filter(Boolean).join("\n");
    }

    case "run_completed": {
      return [
        `${emoji} *SCAN COMPLETE — ${escMd(data.target || "")}*`,
        "",
        data.run_type         ? `Type:         ${escMd(data.run_type)}` : null,
        data.subdomains_found !== undefined ? `Subdomains:   ${data.subdomains_found}` : null,
        data.hosts_live       !== undefined ? `Live:         ${data.hosts_live}` : null,
        data.hosts_interesting !== undefined ? `Interesting:  ${data.hosts_interesting}` : null,
        data.findings_count   !== undefined ? `Findings:     *${data.findings_count}*` : null,
        data.duration_s       !== undefined ? `Duration:     ${formatDuration(data.duration_s)}` : null
      ].filter(Boolean).join("\n");
    }

    case "session_limit_hit": {
      return [
        `${emoji} *SESSION LIMIT HIT*`,
        "",
        `Target: ${escMd(data.target || "")}`,
        `Phase:  ${escMd(data.phase || "")}`,
        data.findings_so_far !== undefined ? `Findings so far: ${data.findings_so_far}` : null,
        "",
        "Resume with:",
        `\`node scripts/run-pipeline.js --target ${escMd(data.target || "")} --resume\``
      ].filter(Boolean).join("\n");
    }

    case "new_subdomain_bulk": {
      const items = Array.isArray(data.items) ? data.items : [];
      return [
        `${emoji} *${items.length} NEW SUBDOMAIN${items.length !== 1 ? "S" : ""} — ${escMd(data.target || "")}*`,
        "",
        ...items.slice(0, 10).map((s) => `  • \`${escMd(s)}\``),
        items.length > 10 ? `  _…and ${items.length - 10} more_` : null
      ].filter(Boolean).join("\n");
    }

    case "subdomain_dead": {
      const items = Array.isArray(data.items) ? data.items : [];
      return [
        `${emoji} *${items.length} SUBDOMAIN${items.length !== 1 ? "S" : ""} OFFLINE — ${escMd(data.target || "")}*`,
        ...items.slice(0, 5).map((s) => `  • \`${escMd(s)}\``)
      ].filter(Boolean).join("\n");
    }

    case "tech_stack_changed": {
      return [
        `${emoji} *TECH CHANGE — \`${escMd(data.subdomain || "")}\`*`,
        data.old_value ? `Before: ${escMd(data.old_value)}` : null,
        data.new_value ? `After:  ${escMd(data.new_value)}` : null
      ].filter(Boolean).join("\n");
    }

    // ── v2 cyberpunk events ────────────────────────────────────────────────────

    case "agent_completed": {
      const domain     = (data.domain || "UNKNOWN").toUpperCase();
      const candidates = data.candidates != null ? data.candidates : "?";
      const elapsed    = data.elapsed    ? `${data.elapsed}` : "";
      return [
        `${emoji} *[${escMd(domain)}] RUNNER DONE${elapsed ? ` — ${escMd(elapsed)}` : ""}*`,
        "",
        `Candidates surfaced: *${candidates}*`,
        data.target ? `Target: \`${escMd(data.target)}\`` : null
      ].filter(Boolean).join("\n");
    }

    case "all_agents_completed": {
      return [
        `${emoji} *ALL RUNNERS SURFACED — THE GRID IS CLEAR*`,
        "",
        data.target     ? `Target:     \`${escMd(data.target)}\`` : null,
        data.candidates != null ? `Candidates: *${data.candidates}*` : null,
        data.confirmed  != null ? `Confirmed:  *${data.confirmed}*`  : null,
        data.elapsed    ? `Elapsed:    ${escMd(data.elapsed)}` : null,
        "",
        "_Chain coordinator running. Hold tight._"
      ].filter(Boolean).join("\n");
    }

    case "chain_found": {
      const sev = (data.severity || "").toLowerCase();
      return [
        `${emoji} *CHAIN REACTION — FULL KILL PATH MAPPED*`,
        "",
        "Strung the nodes together, choom. One pull unravels everything.",
        data.chain_id    ? `Chain:    *${escMd(data.chain_id)}*` : null,
        data.description ? escMd(truncate(data.description, 120)) : null,
        data.members     ? `Members:  ${escMd(data.members)}` : null,
        data.severity    ? `Severity: *${escMd(data.severity)}* ${SEVERITY_EMOJI[sev] || ""}` : null,
        data.target      ? `Target:   \`${escMd(data.target)}\`` : null,
        "",
        "_Combined impact: corpo nightmare fuel._"
      ].filter(Boolean).join("\n");
    }

    case "secret_found": {
      return [
        `${emoji} *GHOST DATA IN THE GRID — SECRET BLEEDING*`,
        "",
        "Some gonk hardcoded their soul into the repo.",
        data.secret_type ? `Type:   *${escMd(data.secret_type)}*` : null,
        data.file        ? `File:   \`${escMd(data.file)}\`` : null,
        data.commit      ? `Commit: \`${escMd(data.commit)}\`` : null,
        data.target      ? `Target: \`${escMd(data.target)}\`` : null,
        "",
        "_Still hot? Jack in and verify before they notice._"
      ].filter(Boolean).join("\n");
    }

    case "patch_bypass_found": {
      return [
        `${emoji} *THEIR FIX IS BROKEN, CHOOM*`,
        "",
        "They patched the wound but left the artery open.",
        data.commit       ? `Commit:  \`${escMd(data.commit)}\`` : null,
        data.description  ? escMd(truncate(data.description, 100)) : null,
        data.bypass       ? `Bypass:  ${escMd(data.bypass)}` : null,
        data.target       ? `Target:  \`${escMd(data.target)}\`` : null
      ].filter(Boolean).join("\n");
    }

    case "stage_completed": {
      return [
        `${emoji} *STAGE DONE — ${escMd((data.stage || "").toUpperCase())}*`,
        "",
        data.target  ? `Target:   \`${escMd(data.target)}\`` : null,
        data.elapsed ? `Elapsed:  ${escMd(data.elapsed)}` : null,
        data.detail  ? escMd(truncate(data.detail, 100)) : null
      ].filter(Boolean).join("\n");
    }

    case "setup_failed": {
      return [
        `${emoji} *SETUP FAILED — ABORTING JACK-IN*`,
        "",
        data.target  ? `Target: \`${escMd(data.target)}\`` : null,
        data.reason  ? `Reason: ${escMd(truncate(data.reason, 200))}` : null,
        "",
        "_The grid rejected us. Check logs and retry._"
      ].filter(Boolean).join("\n");
    }

    case "teleport_ready": {
      return [
        `${emoji} *GHOST COPY READY — SESSION IN THE CAN*`,
        "",
        "Your session's been compressed into pure data, choom.",
        data.file     ? `File:       \`${escMd(data.file)}\`` : null,
        data.size     ? `Size:       ${escMd(data.size)}` : null,
        data.target   ? `Target:     \`${escMd(data.target)}\`` : null,
        data.stages   ? `Stages done: ${escMd(data.stages)}` : null,
        "",
        "_Splice it on the other rig:_",
        "`node scripts/teleport.js --import <file>`"
      ].filter(Boolean).join("\n");
    }

    case "progress_update": {
      return [
        `${emoji} *PROGRESS UPDATE — ${escMd((data.target || "").toUpperCase())}*`,
        "",
        data.phase      ? `Phase:       ${escMd(data.phase)}` : null,
        data.domain     ? `Domain:      *${escMd(data.domain)}*` : null,
        data.candidates != null ? `Candidates:  ${data.candidates}` : null,
        data.confirmed  != null ? `Confirmed:   *${data.confirmed}*` : null,
        data.elapsed    ? `Elapsed:     ${escMd(data.elapsed)}` : null
      ].filter(Boolean).join("\n");
    }

    default:
      return `${emoji} ${escMd(String(data?.message || event))}`;
  }
}

// ── Severity filter ───────────────────────────────────────────────────────────

const SEVERITY_ORDER = ["informative", "low", "medium", "high", "critical"];

function meetsMinSeverity(eventData, minSeverity) {
  if (!minSeverity) return true;
  const sev  = (eventData?.severity || "").toLowerCase();
  if (!sev)  return true; // non-severity events always pass
  return SEVERITY_ORDER.indexOf(sev) >= SEVERITY_ORDER.indexOf(minSeverity.toLowerCase());
}

// ── Channel senders ───────────────────────────────────────────────────────────

async function sendTelegram(text) {
  const token  = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) throw new Error("Telegram: missing BOT_TOKEN or CHAT_ID");
  const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id:    chatId,
      text,
      parse_mode: "Markdown",
      disable_web_page_preview: true
    })
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Telegram HTTP ${res.status}: ${body}`);
  }
}

async function sendDiscord(text) {
  const url = process.env.DISCORD_WEBHOOK_URL;
  if (!url) throw new Error("Discord: missing DISCORD_WEBHOOK_URL");
  // Convert minimal Markdown to Discord-compatible (strip [] links, keep bold/code)
  const discordText = text.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
  const res = await fetch(url, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: discordText })
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Discord HTTP ${res.status}: ${body}`);
  }
}

async function sendSlack(text) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) throw new Error("Slack: missing SLACK_WEBHOOK_URL");
  const slackText = text.replace(/\*([^*]+)\*/g, "*$1*").replace(/`([^`]+)`/g, "`$1`");
  const res = await fetch(url, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: slackText })
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Slack HTTP ${res.status}: ${body}`);
  }
}

// ── Batch queue ───────────────────────────────────────────────────────────────

const _batchQueues = {};    // event → { targetId, items }[]
let   _batchTimer  = null;

function enqueueBatch(event, data) {
  if (!_batchQueues[event]) _batchQueues[event] = [];
  _batchQueues[event].push(data);
}

async function flushBatches() {
  for (const [event, items] of Object.entries(_batchQueues)) {
    if (!items.length) continue;
    // Group by target
    const byTarget = {};
    for (const item of items) {
      const t = item.target || "unknown";
      if (!byTarget[t]) byTarget[t] = [];
      byTarget[t].push(item.subdomain || item.value || JSON.stringify(item));
    }
    for (const [target, subItems] of Object.entries(byTarget)) {
      await notify(event, { target, items: subItems }).catch(() => {});
    }
    delete _batchQueues[event];
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Send an immediate notification to all enabled channels.
 * @param {string} event  — event key from config notifications.rules.events
 * @param {object} data   — event-specific payload
 */
async function notify(event, data = {}) {
  const cfg      = getConfig();
  const notifCfg = cfg.notifications || {};
  const rules    = notifCfg.rules    || {};
  const eventRule = rules.events?.[event] || {};

  // Severity gate
  const minSev = eventRule.min_severity || rules.min_severity;
  if (minSev && !meetsMinSeverity(data, minSev)) return;

  // If batch-only event — enqueue instead of sending immediately
  if (eventRule.batch && !eventRule.immediate) {
    enqueueBatch(event, data);
    scheduleBatchFlush(rules.batch_interval_seconds || 3600);
    return;
  }

  const text = buildMessage(event, data);
  const errors = [];

  const channels = [
    { key: "telegram", fn: sendTelegram },
    { key: "discord",  fn: sendDiscord  },
    { key: "slack",    fn: sendSlack    }
  ];

  for (const { key, fn } of channels) {
    const chCfg = notifCfg[key];
    if (!chCfg?.enabled) continue;
    try {
      await fn(text);
    } catch (e) {
      errors.push(`${key}: ${e.message}`);
    }
  }

  if (errors.length) {
    // Non-fatal — log but don't throw
    process.stderr.write(`[notify] send errors: ${errors.join(", ")}\n`);
  }
}

/**
 * Enqueue items for the next batch flush (for non-immediate events).
 * @param {string} event
 * @param {string} target
 * @param {string[]} items
 */
function notifyBatch(event, target, items) {
  const cfg      = getConfig();
  const rules    = cfg.notifications?.rules || {};
  for (const item of items) {
    enqueueBatch(event, { target, subdomain: item });
  }
  scheduleBatchFlush(rules.batch_interval_seconds || 3600);
}

/**
 * Force immediate flush of all pending batch queues.
 * Call this at the end of a pipeline run.
 */
async function flushPendingNotifications() {
  if (_batchTimer) { clearTimeout(_batchTimer); _batchTimer = null; }
  await flushBatches();
}

function scheduleBatchFlush(intervalSeconds) {
  if (_batchTimer) return; // already scheduled
  _batchTimer = setTimeout(async () => {
    _batchTimer = null;
    await flushBatches().catch(() => {});
  }, intervalSeconds * 1000);
  if (_batchTimer.unref) _batchTimer.unref(); // don't keep Node alive
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escMd(str) {
  // Escape Telegram MarkdownV1 special chars (not V2 — simpler)
  return String(str || "").replace(/([_*[\]()~`>#+\-=|{}.!])/g, "\\$1");
}

function truncate(str, maxLen) {
  if (!str || str.length <= maxLen) return str;
  return str.slice(0, maxLen - 1) + "…";
}

function formatDuration(seconds) {
  if (seconds < 60)   return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

module.exports = {
  notify,
  notifyBatch,
  flushPendingNotifications
};
