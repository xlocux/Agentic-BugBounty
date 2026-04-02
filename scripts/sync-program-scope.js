#!/usr/bin/env node
"use strict";

/**
 * sync-program-scope.js — parse a bug bounty program URL and extract scope.
 *
 * Supports:
 *   HackerOne   — API first, HTML scrape fallback
 *   Bugcrowd    — bbscope API
 *   Intigriti   — bbscope API
 *   YesWeHack   — bbscope API
 *   bbscope URL — direct
 *
 * Usage:
 *   node scripts/sync-program-scope.js --url https://hackerone.com/acme
 *   node scripts/sync-program-scope.js --url https://bugcrowd.com/acme --handle acme
 *   node scripts/sync-program-scope.js --url https://hackerone.com/acme --json
 *
 * Output:
 *   - Upserts target in targets_registry
 *   - Writes scope_rules (in/out, domain/vuln/asset)
 *   - Prints summary table
 *   - Optionally --json for machine-readable output
 */

process.env.NODE_OPTIONS = `${process.env.NODE_OPTIONS || ""} --no-warnings`.trim();

const fs   = require("node:fs");
const path = require("node:path");
const https = require("node:https");

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

const { openDatabase, resolveGlobalDatabasePath, upsertTarget, replaceScopeRules } = require("./lib/db");
const { fetchProgramScope, syncBbscopeProgramIntel, PLATFORM_LABELS } = require("./lib/bbscope");
const { notify } = require("./lib/notify");

// ── CLI args ──────────────────────────────────────────────────────────────────
const args       = process.argv.slice(2);
const jsonMode   = args.includes("--json");
const programUrl = (() => { const i = args.indexOf("--url"); return i !== -1 ? args[i + 1] : null; })();
const handleArg  = (() => { const i = args.indexOf("--handle"); return i !== -1 ? args[i + 1] : null; })();

if (!programUrl) {
  console.error("Usage: node scripts/sync-program-scope.js --url <program_url> [--handle <handle>] [--json]");
  process.exit(1);
}

// ── Colours ───────────────────────────────────────────────────────────────────
const c = {
  reset: "\x1b[0m", green: "\x1b[32m", red: "\x1b[31m",
  yellow: "\x1b[33m", cyan: "\x1b[36m", grey: "\x1b[90m", bold: "\x1b[1m"
};
const col = (s, code) => jsonMode ? s : `${code}${s}${c.reset}`;

// ── Platform detection ────────────────────────────────────────────────────────
function detectPlatform(url) {
  const u = url.toLowerCase();
  if (u.includes("hackerone.com"))  return "h1";
  if (u.includes("bugcrowd.com"))   return "bc";
  if (u.includes("intigriti.com"))  return "it";
  if (u.includes("yeswehack.com"))  return "ywh";
  if (u.includes("bbscope.com"))    return "bbscope";
  return null;
}

function extractHandle(url, platform) {
  if (handleArg) return handleArg;
  try {
    const u    = new URL(url);
    const segs = u.pathname.replace(/^\//, "").split("/").filter(Boolean);

    switch (platform) {
      case "h1":       return segs[0] || null;
      case "bc":       {
        // Bugcrowd: /acme or /engagements/acme
        if (segs[0] === "engagements") return segs.slice(0, 2).join("/");
        return segs[0] || null;
      }
      case "it":       return segs[segs.length - 1] || null; // last segment
      case "ywh":      return segs[segs.length - 1] || null;
      case "bbscope":  return segs[segs.length - 1] || null;
      default:         return segs[0] || null;
    }
  } catch {
    return null;
  }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function fetchHtml(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      { hostname: u.hostname, path: u.pathname + u.search, method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) agentic-bugbounty/1.0",
                   "Accept": "text/html,application/json", ...headers } },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return fetchHtml(res.headers.location, headers).then(resolve).catch(reject);
        }
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (d) => { body += d; });
        res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers }));
      }
    );
    req.on("error", reject);
    req.end();
  });
}

function fetchJson(url, headers = {}) {
  return fetchHtml(url, { Accept: "application/json", ...headers })
    .then((r) => ({ ...r, data: JSON.parse(r.body) }));
}

// ── HackerOne scope extraction ────────────────────────────────────────────────

async function fetchH1ScopeViaApi(handle) {
  const user  = process.env.H1_API_USERNAME;
  const token = process.env.H1_API_TOKEN;
  if (!user || !token || user.startsWith("your_")) return null;

  const creds = Buffer.from(`${user}:${token}`).toString("base64");
  const auth  = { Authorization: `Basic ${creds}`, Accept: "application/json" };

  // Fetch structured scope
  let scopeItems = [];
  let page = 1;
  while (true) {
    const res = await fetchJson(
      `https://api.hackerone.com/v1/hackers/programs/${handle}/structured_scopes?page[size]=100&page[number]=${page}`,
      auth
    ).catch(() => null);
    if (!res || res.status !== 200) break;
    const items = res.data?.data || [];
    scopeItems = scopeItems.concat(items);
    if (!res.data?.links?.next) break;
    page++;
  }

  // Fetch program meta for out-of-scope and policy text
  const meta = await fetchJson(
    `https://api.hackerone.com/v1/hackers/programs/${handle}`,
    auth
  ).catch(() => null);

  return { scopeItems, meta: meta?.data || null };
}

function normalizeH1Scope(scopeItems, programHandle) {
  const rules = [];

  for (const item of scopeItems) {
    const attr       = item.attributes || {};
    const identifier = attr.asset_identifier || "";
    const assetType  = attr.asset_type || "";
    const eligible   = attr.eligible_for_submission !== false;
    const type       = eligible ? "in" : "out";

    // Classify entity_type
    let entityType = "asset";
    const idLower  = identifier.toLowerCase();
    if (assetType === "URL" || assetType === "WILDCARD" || idLower.startsWith("*.") ||
        idLower.match(/^[\w.-]+\.[a-z]{2,}$/)) {
      entityType = "domain";
    } else if (assetType === "IP_ADDRESS" || assetType === "CIDR") {
      entityType = "ip";
    }

    rules.push({
      type,
      entity_type: entityType,
      pattern:     identifier,
      source:      "h1_api"
    });
  }

  return rules;
}

function extractH1OutOfScopeFromHtml(html) {
  // Try to extract out-of-scope section from policy HTML
  const rules = [];

  // Common patterns: "Out of Scope" section with domain lists
  const outSectionMatch = html.match(/out.of.scope[\s\S]{0,5000}/i);
  if (!outSectionMatch) return rules;

  const section = outSectionMatch[0];
  // Extract domain-like patterns
  const domainRe = /(?:^|\s)((?:\*\.)?[\w-]+\.[\w.-]+)/gm;
  let m;
  while ((m = domainRe.exec(section)) !== null) {
    const pattern = m[1].trim();
    if (pattern.length > 3 && pattern.length < 100) {
      rules.push({ type: "out", entity_type: "domain", pattern, source: "h1_html_parse" });
    }
  }

  return rules;
}

async function fetchH1Scope(handle) {
  // Try API first
  const apiResult = await fetchH1ScopeViaApi(handle);

  if (apiResult?.scopeItems?.length) {
    const rules = normalizeH1Scope(apiResult.scopeItems, handle);

    // Add vuln scope from policy text if available
    const policy = apiResult.meta?.attributes?.policy || "";
    const vulnRules = extractVulnScopeFromText(policy, "h1_policy");
    return [...rules, ...vulnRules];
  }

  // Fallback: scrape public page
  console.error(col(`  [h1] API unavailable or no credentials — falling back to HTML scrape`, c.yellow));
  const res = await fetchHtml(`https://hackerone.com/${handle}`).catch(() => null);
  if (!res || res.status !== 200) {
    throw new Error(`HackerOne page not accessible for handle: ${handle}`);
  }

  // H1 embeds program data in a __NEXT_DATA__ script tag
  const nextDataMatch = res.body.match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);
  if (nextDataMatch) {
    try {
      const nextData = JSON.parse(nextDataMatch[1]);
      const program  = nextData?.props?.pageProps?.program ||
                       nextData?.props?.pageProps?.data?.program;
      if (program) {
        return extractScopeFromH1ProgramObject(program);
      }
    } catch { /* parse failed */ }
  }

  // Last resort: regex extraction from HTML
  return extractH1OutOfScopeFromHtml(res.body);
}

function extractScopeFromH1ProgramObject(program) {
  const rules = [];
  const scopes = program.structured_scopes?.edges || program.in_scope || [];

  for (const edge of scopes) {
    const node = edge.node || edge;
    const id   = node.asset_identifier || node.identifier || "";
    if (!id) continue;
    rules.push({
      type:        "in",
      entity_type: id.includes(".") ? "domain" : "asset",
      pattern:     id,
      source:      "h1_html"
    });
  }

  const oos = program.out_of_scope || [];
  for (const item of oos) {
    const id = item.asset_identifier || item || "";
    if (!id || typeof id !== "string") continue;
    rules.push({
      type:        "out",
      entity_type: id.includes(".") ? "domain" : "asset",
      pattern:     id,
      source:      "h1_html"
    });
  }

  return rules;
}

// ── Vuln scope extraction from policy text ────────────────────────────────────

const VULN_CLASS_PATTERNS = [
  { re: /sql\s*injection|sqli/i,          class: "sqli" },
  { re: /xss|cross.site.script/i,         class: "xss" },
  { re: /ssrf|server.side.request/i,      class: "ssrf" },
  { re: /rce|remote.code.exec/i,          class: "rce" },
  { re: /csrf|cross.site.request.forgery/i, class: "csrf" },
  { re: /idor|insecure.direct.object/i,   class: "idor" },
  { re: /xxe|xml.external/i,             class: "xxe" },
  { re: /open.redirect/i,                class: "open_redirect" },
  { re: /auth(entication)?.bypass/i,     class: "auth_bypass" },
  { re: /subdomain.takeover/i,           class: "subdomain_takeover" },
  { re: /self.xss/i,                     class: "self_xss" },
  { re: /dos|denial.of.service/i,        class: "dos" },
  { re: /rate.limit/i,                   class: "rate_limiting" },
  { re: /clickjacking/i,                 class: "clickjacking" },
  { re: /csv.injection/i,                class: "csv_injection" },
  { re: /host.header/i,                  class: "host_header" }
];

const OUT_OF_SCOPE_MARKERS = [
  "out of scope", "not in scope", "excluded", "not eligible",
  "will not be rewarded", "will not accept"
];

function extractVulnScopeFromText(text, source) {
  if (!text) return [];
  const rules = [];
  const textLower = text.toLowerCase();

  // Find out-of-scope sections
  for (const marker of OUT_OF_SCOPE_MARKERS) {
    const idx = textLower.indexOf(marker);
    if (idx === -1) continue;

    // Look at surrounding context (500 chars)
    const section = textLower.slice(idx, idx + 500);
    for (const { re, class: vulnClass } of VULN_CLASS_PATTERNS) {
      if (re.test(section)) {
        rules.push({ type: "out", entity_type: "vuln", pattern: vulnClass, source });
      }
    }
  }

  return rules;
}

// ── bbscope-based platforms ───────────────────────────────────────────────────

async function fetchBbscopeScope(platform, handle) {
  const intel = await syncBbscopeProgramIntel(platform, handle);
  return intel.scopes.map((s) => ({
    type:        s.eligible_for_submission !== false ? "in" : "out",
    entity_type: classifyAssetType(s.asset_type, s.asset_identifier),
    pattern:     s.asset_identifier || "",
    source:      `bbscope_${platform}`
  })).filter((r) => r.pattern);
}

function classifyAssetType(assetType, identifier) {
  const t  = (assetType || "").toUpperCase();
  const id = (identifier || "").toLowerCase();
  if (t === "URL" || t === "WILDCARD" || id.startsWith("*.") || id.match(/^[\w.-]+\.[a-z]{2,}$/)) {
    return "domain";
  }
  if (t === "IP_ADDRESS" || t === "CIDR") return "ip";
  if (t === "GOOGLE_PLAY_APP_ID" || t === "APPLE_STORE_APP_ID") return "asset";
  return "asset";
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const platform = detectPlatform(programUrl);
  if (!platform) {
    console.error(col(`Unknown platform for URL: ${programUrl}`, c.red));
    console.error("Supported: hackerone.com, bugcrowd.com, intigriti.com, yeswehack.com, bbscope.com");
    process.exit(1);
  }

  const handle = extractHandle(programUrl, platform);
  if (!handle) {
    console.error(col(`Could not extract program handle from URL: ${programUrl}`, c.red));
    console.error("Use --handle <handle> to specify it manually.");
    process.exit(1);
  }

  if (!jsonMode) {
    console.log(col("\n╔══════════════════════════════════════════════════════════╗", c.cyan));
    console.log(col("║  SYNC PROGRAM SCOPE                                      ║", c.cyan));
    console.log(col("╚══════════════════════════════════════════════════════════╝", c.cyan));
    console.log(`  Platform : ${col(PLATFORM_LABELS[platform] || platform, c.bold)}`);
    console.log(`  Handle   : ${col(handle, c.bold)}`);
    console.log(`  URL      : ${col(programUrl, c.grey)}`);
    console.log();
  }

  // Fetch scope rules
  let rules = [];
  console.error(`[scope] fetching scope from ${PLATFORM_LABELS[platform] || platform}...`);

  switch (platform) {
    case "h1":     rules = await fetchH1Scope(handle); break;
    case "bbscope":
    case "bc":
    case "it":
    case "ywh":    rules = await fetchBbscopeScope(platform === "bbscope" ? "h1" : platform, handle); break;
    default:       throw new Error(`Unsupported platform: ${platform}`);
  }

  if (!rules.length) {
    console.error(col("  WARNING: no scope rules extracted — check URL or credentials", c.yellow));
  }

  // Persist to global DB
  const dbPath = resolveGlobalDatabasePath();
  const db     = openDatabase(dbPath);

  const target = upsertTarget(db, {
    handle,
    platform: PLATFORM_LABELS[platform] || platform,
    program_url: programUrl
  });

  replaceScopeRules(db, target.id, rules);
  db.close();

  // Build summary
  const inDomains  = rules.filter((r) => r.type === "in"  && r.entity_type === "domain");
  const outDomains = rules.filter((r) => r.type === "out" && r.entity_type === "domain");
  const inVulns    = rules.filter((r) => r.type === "in"  && r.entity_type === "vuln");
  const outVulns   = rules.filter((r) => r.type === "out" && r.entity_type === "vuln");
  const inAssets   = rules.filter((r) => r.type === "in"  && r.entity_type === "asset");
  const inIps      = rules.filter((r) => r.type === "in"  && r.entity_type === "ip");

  if (jsonMode) {
    console.log(JSON.stringify({
      handle, platform, program_url: programUrl,
      target_id: target.id,
      rules,
      summary: {
        in_domains:  inDomains.length,
        out_domains: outDomains.length,
        in_vulns:    inVulns.length,
        out_vulns:   outVulns.length,
        in_assets:   inAssets.length,
        in_ips:      inIps.length
      }
    }, null, 2));
    return;
  }

  // Print scope table
  console.log(col("  IN-SCOPE DOMAINS", c.green + c.bold));
  if (inDomains.length) {
    for (const r of inDomains) {
      console.log(`    ${col("✓", c.green)} ${r.pattern}  ${col(`(${r.source})`, c.grey)}`);
    }
  } else {
    console.log(col("    (none found)", c.grey));
  }

  if (inIps.length) {
    console.log(col("\n  IN-SCOPE IPs / CIDRs", c.green + c.bold));
    for (const r of inIps) {
      console.log(`    ${col("✓", c.green)} ${r.pattern}  ${col(`(${r.source})`, c.grey)}`);
    }
  }

  if (inAssets.length) {
    console.log(col("\n  IN-SCOPE ASSETS (apps / other)", c.green + c.bold));
    for (const r of inAssets) {
      console.log(`    ${col("✓", c.green)} ${r.pattern}  ${col(`(${r.source})`, c.grey)}`);
    }
  }

  if (outDomains.length) {
    console.log(col("\n  OUT-OF-SCOPE DOMAINS", c.red + c.bold));
    for (const r of outDomains) {
      console.log(`    ${col("✗", c.red)} ${r.pattern}  ${col(`(${r.source})`, c.grey)}`);
    }
  }

  if (outVulns.length) {
    console.log(col("\n  OUT-OF-SCOPE VULN CLASSES", c.red + c.bold));
    for (const r of outVulns) {
      console.log(`    ${col("✗", c.red)} ${r.pattern}  ${col(`(${r.source})`, c.grey)}`);
    }
  }

  console.log(col("\n─────────────────────────────────────────────────────────", c.grey));
  console.log(`  ${col(rules.length, c.bold)} rules saved for target ${col(handle, c.cyan)}`);
  console.log(`  DB: ${col(dbPath, c.grey)}\n`);

  // Notify if channels configured
  await notify("run_completed", {
    target:   handle,
    run_type: "scope_sync",
    subdomains_found: inDomains.length
  }).catch(() => {});
}

main().catch((e) => {
  console.error(col(`\nFATAL: ${e.message}`, "\x1b[31m"));
  if (process.env.DEBUG) console.error(e.stack);
  process.exit(1);
});
