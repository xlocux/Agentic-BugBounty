#!/usr/bin/env node
"use strict";

/**
 * check-apis.js — health check for all configured API integrations.
 * Usage: node scripts/check-apis.js [--json] [--tier <1|2|3>]
 */

process.env.NODE_OPTIONS = `${process.env.NODE_OPTIONS || ""} --no-warnings`.trim();

const fs   = require("node:fs");
const path = require("node:path");

// Load .env
(function loadDotEnv() {
  const envPath = path.resolve(__dirname, "../.env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const eq = t.indexOf("=");
    if (eq === -1) continue;
    const key = t.slice(0, eq).trim();
    const val = t.slice(eq + 1).trim();
    if (key && !(key in process.env)) process.env[key] = val;
  }
})();

const CONFIG_PATH = path.resolve(__dirname, "../config/apis.json");
const config      = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));

// ── CLI args ──────────────────────────────────────────────────────────────────
const args      = process.argv.slice(2);
const jsonMode  = args.includes("--json");
const tierFilter = (() => {
  const i = args.indexOf("--tier");
  return i !== -1 ? Number(args[i + 1]) : null;
})();

// ── Colour helpers ────────────────────────────────────────────────────────────
const c = {
  reset:  "\x1b[0m",
  green:  "\x1b[32m",
  red:    "\x1b[31m",
  yellow: "\x1b[33m",
  cyan:   "\x1b[36m",
  grey:   "\x1b[90m",
  bold:   "\x1b[1m"
};
const col = (s, code) => jsonMode ? s : `${code}${s}${c.reset}`;

// ── Env key resolution ────────────────────────────────────────────────────────
function resolveEnv(envMap) {
  const resolved = {};
  for (const [field, envVar] of Object.entries(envMap)) {
    resolved[field] = process.env[envVar] || null;
  }
  return resolved;
}

function hasRequiredKeys(envMap) {
  if (!envMap || Object.keys(envMap).length === 0) return true; // no keys needed
  return Object.values(envMap).some((envVar) => {
    const val = process.env[envVar];
    return val && val.trim() && !val.startsWith("your_");
  });
}

// ── Live API probes ───────────────────────────────────────────────────────────
async function probeNvd(cfg) {
  const key = process.env[cfg.env.api_key];
  const headers = { "User-Agent": "agentic-bugbounty/check-apis" };
  if (key && !key.startsWith("your_")) headers["apiKey"] = key;
  const url = `${cfg.base_url}?keywordSearch=test&resultsPerPage=1`;
  const res = await fetchWithTimeout(url, { headers }, 8000);
  const withKey = key && !key.startsWith("your_");
  return {
    ok: res.ok,
    detail: res.ok
      ? `${withKey ? "2000 req/30s (key)" : "50 req/30s (no key)"}`
      : `HTTP ${res.status}`
  };
}

async function probeOsv(cfg) {
  const res = await fetchWithTimeout(
    `${cfg.base_url}/query`,
    { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: { name: "lodash", ecosystem: "npm" } }) },
    8000
  );
  return { ok: res.ok, detail: res.ok ? "unlimited, no key" : `HTTP ${res.status}` };
}

async function probeWpscan(cfg) {
  const key = process.env[cfg.env.api_token];
  if (!key || key.startsWith("your_")) return { ok: false, detail: "no key configured" };
  const res = await fetchWithTimeout(
    `${cfg.base_url}/status`,
    { headers: { "Authorization": `Token token=${key}` } },
    8000
  );
  if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
  const data = await res.json().catch(() => ({}));
  const left = data.requests_remaining ?? "?";
  return { ok: true, detail: `${left} req/day remaining` };
}

async function probeShodan(cfg) {
  const key = process.env[cfg.env.api_key];
  if (!key || key.startsWith("your_")) return { ok: false, detail: "no key configured" };
  const res = await fetchWithTimeout(
    `${cfg.base_url}/api-info?key=${key}`, {}, 8000
  );
  if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
  const data = await res.json().catch(() => ({}));
  const credits = data.query_credits ?? "?";
  return { ok: true, detail: `${credits} query credits remaining` };
}

async function probeSecurityTrails(cfg) {
  const key = process.env[cfg.env.api_key];
  if (!key || key.startsWith("your_")) return { ok: false, detail: "no key configured" };
  const res = await fetchWithTimeout(
    `${cfg.base_url}/ping`,
    { headers: { "APIKEY": key } },
    8000
  );
  return { ok: res.ok, detail: res.ok ? "key valid" : `HTTP ${res.status}` };
}

async function probeVirusTotal(cfg) {
  const key = process.env[cfg.env.api_key];
  if (!key || key.startsWith("your_")) return { ok: false, detail: "no key configured" };
  const res = await fetchWithTimeout(
    `${cfg.base_url}/users/me`,
    { headers: { "x-apikey": key } },
    8000
  );
  if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
  const data = await res.json().catch(() => ({}));
  const left = data.data?.attributes?.quotas?.api_requests_daily?.allowed ?? "?";
  const used = data.data?.attributes?.quotas?.api_requests_daily?.used ?? "?";
  return { ok: true, detail: `${left - used}/${left} req/day remaining` };
}

async function probeCensys(cfg) {
  const id     = process.env[cfg.env.api_id];
  const secret = process.env[cfg.env.api_secret];
  if (!id || id.startsWith("your_")) return { ok: false, detail: "no key configured" };
  const creds = Buffer.from(`${id}:${secret}`).toString("base64");
  const res = await fetchWithTimeout(
    `${cfg.base_url}/account`,
    { headers: { "Authorization": `Basic ${creds}` } },
    8000
  );
  return { ok: res.ok, detail: res.ok ? "credentials valid" : `HTTP ${res.status}` };
}

async function probeUrlscan(cfg) {
  const key = process.env[cfg.env.api_key];
  if (!key || key.startsWith("your_")) return { ok: null, detail: "optional — no key (public use ok)" };
  const res = await fetchWithTimeout(
    `${cfg.base_url}/user/quotas`,
    { headers: { "API-Key": key } },
    8000
  );
  return { ok: res.ok, detail: res.ok ? "key valid" : `HTTP ${res.status}` };
}

async function probeOtx(cfg) {
  const key = process.env[cfg.env.api_key];
  if (!key || key.startsWith("your_")) return { ok: false, detail: "no key configured" };
  const res = await fetchWithTimeout(
    `${cfg.base_url}/user/me`,
    { headers: { "X-OTX-API-KEY": key } },
    8000
  );
  return { ok: res.ok, detail: res.ok ? "key valid" : `HTTP ${res.status}` };
}

async function probeWappalyzer(cfg) {
  const key = process.env[cfg.env.api_key];
  if (!key || key.startsWith("your_")) return { ok: false, detail: "no key configured" };
  const res = await fetchWithTimeout(
    `${cfg.base_url}/technologies?website=https://example.com`,
    { headers: { "x-api-key": key } },
    8000
  );
  return { ok: res.ok, detail: res.ok ? "key valid" : `HTTP ${res.status}` };
}

async function probeH1(cfg) {
  const user  = process.env[cfg.env.username];
  const token = process.env[cfg.env.token];
  if (!user || !token || user.startsWith("your_")) return { ok: false, detail: "no credentials" };
  const creds = Buffer.from(`${user}:${token}`).toString("base64");
  const res = await fetchWithTimeout(
    `${cfg.base_url}/me`,
    { headers: { "Authorization": `Basic ${creds}`, "Accept": "application/json" } },
    8000
  );
  return { ok: res.ok, detail: res.ok ? "credentials valid" : `HTTP ${res.status}` };
}

async function probeTelegram(cfg) {
  const token = process.env[cfg.env.bot_token];
  if (!token || token.startsWith("your_")) return { ok: false, detail: "no token configured" };
  const res = await fetchWithTimeout(
    `https://api.telegram.org/bot${token}/getMe`,
    {},
    8000
  );
  if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
  const data = await res.json().catch(() => ({}));
  const name = data.result?.username || "unknown";
  const chatId = process.env[cfg.env.chat_id];
  const chatOk = chatId && !chatId.startsWith("your_");
  return {
    ok: chatOk,
    detail: chatOk ? `@${name} — chat_id configured` : `@${name} — missing TELEGRAM_CHAT_ID`
  };
}

async function probeDiscord(cfg) {
  const url = process.env[cfg.env.webhook_url];
  if (!url || url.startsWith("your_")) return { ok: false, detail: "no webhook configured" };
  // Validate URL shape without sending a message
  const valid = url.startsWith("https://discord.com/api/webhooks/");
  return { ok: valid, detail: valid ? "webhook URL looks valid" : "URL format invalid" };
}

// ── Generic key-only check ────────────────────────────────────────────────────
function checkKeyOnly(envMap) {
  if (hasRequiredKeys(envMap)) return { ok: true,  detail: "key configured (not probed)" };
  return                               { ok: false, detail: "no key configured" };
}

// ── Probe dispatcher ──────────────────────────────────────────────────────────
const PROBERS = {
  nvd:            probeNvd,
  osv:            probeOsv,
  wpscan:         probeWpscan,
  shodan:         probeShodan,
  securitytrails: probeSecurityTrails,
  virustotal:     probeVirusTotal,
  censys:         probeCensys,
  urlscan:        probeUrlscan,
  alienvault_otx: probeOtx,
  wappalyzer:     probeWappalyzer,
  hackerone:      probeH1,
  telegram:       probeTelegram,
  discord:        probeDiscord
};

// ── Timeout-safe fetch ────────────────────────────────────────────────────────
function fetchWithTimeout(url, opts = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...opts, signal: controller.signal })
    .finally(() => clearTimeout(timer))
    .catch((e) => {
      if (e.name === "AbortError") throw new Error("timeout");
      throw e;
    });
}

// ── Section runner ────────────────────────────────────────────────────────────
async function checkSection(sectionName, section) {
  const results = [];
  for (const [key, cfg] of Object.entries(section)) {
    if (key.startsWith("_")) continue;
    const tier = cfg.tier || null;
    if (tierFilter && tier !== tierFilter) continue;

    const label     = key.padEnd(18);
    const tierTag   = tier ? `[T${tier}]` : "    ";
    const enabled   = cfg.enabled !== false;
    const envMap    = cfg.env || {};
    const hasKey    = hasRequiredKeys(envMap);

    if (!enabled) {
      results.push({ key, tier, ok: null, detail: "disabled in config/apis.json", enabled: false });
      continue;
    }

    let probe;
    try {
      const prober = PROBERS[key];
      if (prober) {
        probe = await prober(cfg);
      } else {
        probe = checkKeyOnly(envMap);
      }
    } catch (e) {
      probe = { ok: false, detail: e.message || "error" };
    }

    results.push({ key, tier, label, tierTag, enabled, hasKey, ...probe });
  }
  return results;
}

// ── Render ────────────────────────────────────────────────────────────────────
function statusIcon(ok, enabled) {
  if (!enabled)      return col("  —  ", c.grey);
  if (ok === null)   return col("  ?  ", c.yellow);
  if (ok)            return col("  ✓  ", c.green);
  return               col("  ✗  ", c.red);
}

function printSection(title, results) {
  if (!results.length) return;
  console.log(`\n${col(title, c.cyan + c.bold)}`);
  console.log(col("─".repeat(62), c.grey));
  for (const r of results) {
    const icon    = statusIcon(r.ok, r.enabled);
    const tier    = r.tier ? col(`[T${r.tier}]`, c.grey) : "     ";
    const name    = col((r.key || "").padEnd(20), r.ok ? c.reset : r.ok === null ? c.grey : c.reset);
    const detail  = col(r.detail || "", r.ok ? c.grey : c.yellow);
    console.log(`${icon} ${tier} ${name} ${detail}`);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  if (!jsonMode) {
    console.log(col("\n╔══════════════════════════════════════════════════════════╗", c.cyan));
    console.log(col("║  AGENTIC BUGBOUNTY — API HEALTH CHECK                    ║", c.cyan));
    console.log(col("╚══════════════════════════════════════════════════════════╝", c.cyan));
  }

  const all = {};

  const sections = [
    ["Bug Bounty Platforms",       config.platforms],
    ["Vulnerability Intelligence", config.vulnerability_intelligence],
    ["Recon Intelligence",         config.recon_intelligence],
    ["Tech Detection",             config.tech_detection],
    ["Notifications",              config.notifications]
  ];

  for (const [title, section] of sections) {
    const results = await checkSection(title, section);
    all[title] = results;
    if (!jsonMode) printSection(title, results);
  }

  // ── Summary ────────────────────────────────────────────────────────────────
  const flat        = Object.values(all).flat();
  const enabled     = flat.filter((r) => r.enabled !== false);
  const passing     = enabled.filter((r) => r.ok === true);
  const failing     = enabled.filter((r) => r.ok === false);
  const optional    = enabled.filter((r) => r.ok === null);
  const tier1Fail   = failing.filter((r) => r.tier === 1);

  if (jsonMode) {
    console.log(JSON.stringify({ sections: all, summary: { passing: passing.length, failing: failing.length, optional: optional.length } }, null, 2));
    process.exit(tier1Fail.length > 0 ? 1 : 0);
  }

  console.log(`\n${col("─".repeat(62), c.grey)}`);
  console.log(`  ${col("✓", c.green)} ${passing.length} passing   ${col("✗", c.red)} ${failing.length} failing   ${col("?", c.yellow)} ${optional.length} optional/skipped`);

  if (tier1Fail.length > 0) {
    console.log(`\n${col("  Tier 1 issues:", c.red + c.bold)}`);
    for (const r of tier1Fail) {
      console.log(`    ${col("✗", c.red)} ${r.key} — ${r.detail}`);
      if (config.vulnerability_intelligence?.[r.key]?.get_key) {
        console.log(col(`      → ${config.vulnerability_intelligence[r.key].get_key}`, c.grey));
      }
      if (config.recon_intelligence?.[r.key]?.get_key) {
        console.log(col(`      → ${config.recon_intelligence[r.key].get_key}`, c.grey));
      }
      if (config.notifications?.[r.key]?.get_key) {
        console.log(col(`      → ${config.notifications[r.key].get_key}`, c.grey));
      }
    }
  }

  console.log();
  process.exit(tier1Fail.length > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
