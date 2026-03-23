#!/usr/bin/env node
"use strict";

/**
 * sync-calibration-dataset.js
 *
 * Reads the global disclosed_reports from the SQLite DB (or JSON snapshot),
 * classifies each report by (asset_type, vuln_class) using title/weakness/cwe heuristics,
 * aggregates calibration_patterns with severity distributions and samples,
 * and persists everything back to the global DB.
 *
 * This does NOT call the H1 API directly — it enriches the already-synced dataset.
 * Run h1:disclosed (or h1:bootstrap) first to populate the base data.
 *
 * Usage:
 *   node scripts/sync-calibration-dataset.js [--out-dir <path>]
 */

const path = require("node:path");
const {
  openDatabase,
  replaceCalibrationPatterns,
  replaceReportBehaviors,
  resolveGlobalDatabasePath
} = require("./lib/db");
const { readJson } = require("./lib/io");

const DEFAULT_SAMPLE_SIZE = 5;
const DEFAULT_TOP_PROGRAMS = 10;

// ---------------------------------------------------------------------------
// Classification taxonomy
// Each entry maps to { asset_type, vuln_class } based on title/weakness/cwe
// Ordered by specificity — first match wins
// ---------------------------------------------------------------------------
const CLASSIFICATION_RULES = [
  // --- Chrome Extension specific ---
  {
    asset_type: "browserext",
    vuln_class: "uxss",
    patterns: [/\buxss\b/i, /universal.*xss/i, /cross.?origin.*script/i]
  },
  {
    asset_type: "browserext",
    vuln_class: "privilege_escalation_messages",
    patterns: [/chrome.*extension.*message/i, /postmessage.*extension/i, /extension.*privilege/i, /content.?script.*background/i]
  },
  {
    asset_type: "browserext",
    vuln_class: "extension_data_leak",
    patterns: [/extension.*data.*leak/i, /chrome.*storage.*leak/i]
  },

  // --- Mobile App specific ---
  {
    asset_type: "mobileapp",
    vuln_class: "deep_link_injection",
    patterns: [/deep.?link/i, /intent.*injection/i, /android.*scheme/i, /url.*scheme.*android/i]
  },
  {
    asset_type: "mobileapp",
    vuln_class: "insecure_data_storage",
    patterns: [/insecure.*storage/i, /cleartext.*storage/i, /sensitive.*data.*storage/i, /shared.*pref.*sensitive/i]
  },
  {
    asset_type: "mobileapp",
    vuln_class: "webview_xss",
    patterns: [/webview.*xss/i, /webview.*javascript/i, /addjavascript.*interface/i]
  },
  {
    asset_type: "mobileapp",
    vuln_class: "ssl_pinning_bypass",
    patterns: [/ssl.*pin/i, /certificate.*pin/i, /\btrust.*anchor/i]
  },
  {
    asset_type: "mobileapp",
    vuln_class: "exported_component",
    patterns: [/exported.*activity/i, /exported.*receiver/i, /exported.*provider/i, /android.*exported/i]
  },

  // --- Executable specific ---
  {
    asset_type: "executable",
    vuln_class: "buffer_overflow",
    patterns: [/buffer.*overflow/i, /\bstack.*overflow\b/i, /heap.*overflow/i, /\bcwe-120\b/i, /\bcwe-121\b/i, /\bcwe-122\b/i]
  },
  {
    asset_type: "executable",
    vuln_class: "memory_corruption",
    patterns: [/memory.*corruption/i, /use.after.free/i, /double.free/i, /\buaf\b/i, /\bcwe-416\b/i, /\bcwe-415\b/i]
  },
  {
    asset_type: "executable",
    vuln_class: "command_injection_native",
    patterns: [/command.*injection.*native/i, /\bsystem\(\)/i, /os.*command.*exec/i]
  },
  {
    asset_type: "executable",
    vuln_class: "format_string",
    patterns: [/format.*string/i, /\bcwe-134\b/i, /printf.*user/i]
  },

  // --- Generic web vulns (webapp + fallback) ---
  {
    asset_type: "webapp",
    vuln_class: "xss",
    patterns: [/\bxss\b/i, /cross.?site.*script/i, /html.*injection/i, /\bcwe-79\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "sql_injection",
    patterns: [/\bsqli?\b/i, /sql.*injection/i, /\bcwe-89\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "ssrf",
    patterns: [/\bssrf\b/i, /server.side.*request.*forgery/i, /\bcwe-918\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "idor",
    patterns: [/\bidor\b/i, /insecure.*direct.*object/i, /broken.*access.*control/i, /\bcwe-639\b/i, /\bcwe-284\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "csrf",
    patterns: [/\bcsrf\b/i, /cross.?site.*request.*forgery/i, /\bcwe-352\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "auth_bypass",
    patterns: [/auth.*bypass/i, /authentication.*bypass/i, /\bauth.*flaw/i, /\bcwe-287\b/i, /\bcwe-306\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "open_redirect",
    patterns: [/open.*redirect/i, /url.*redirect/i, /\bcwe-601\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "rce",
    patterns: [/\brce\b/i, /remote.*code.*exec/i, /code.*inject/i, /\bcwe-94\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "ssti",
    patterns: [/\bssti\b/i, /server.side.*template.*injection/i, /template.*inject/i, /\bcwe-1336\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "xxe",
    patterns: [/\bxxe\b/i, /xml.*external.*entity/i, /\bcwe-611\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "file_upload",
    patterns: [/file.*upload/i, /unrestricted.*upload/i, /\bcwe-434\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "path_traversal",
    patterns: [/path.*traversal/i, /directory.*traversal/i, /\bcwe-22\b/i, /\.\.\//]
  },
  {
    asset_type: "webapp",
    vuln_class: "postmessage",
    patterns: [/postmessage/i, /cross.?frame/i, /cross.?origin.*message/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "cors",
    patterns: [/\bcors\b/i, /cross.origin.*resource.*shar/i, /\bcwe-346\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "oauth",
    patterns: [/\boauth\b/i, /\boidc\b/i, /openid.*connect/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "saml",
    patterns: [/\bsaml\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "prototype_pollution",
    patterns: [/prototype.*pollution/i, /\bcwe-1321\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "deserialization",
    patterns: [/deserializ/i, /\bcwe-502\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "race_condition",
    patterns: [/race.*condition/i, /toctou/i, /time.*of.*check/i, /\bcwe-362\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "graphql",
    patterns: [/graphql/i, /introspection/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "host_header",
    patterns: [/host.*header/i, /password.*reset.*poison/i, /\bcwe-116\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "business_logic",
    patterns: [/business.*logic/i, /workflow.*bypass/i, /logic.*flaw/i, /\bcwe-840\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "subdomain_takeover",
    patterns: [/subdomain.*takeover/i, /dangling.*dns/i, /\bcwe-350\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "information_disclosure",
    patterns: [/information.*disclosure/i, /data.*exposure/i, /sensitive.*data.*exposure/i, /\bcwe-200\b/i, /\bcwe-209\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "csp_bypass",
    patterns: [/\bcsp\b.*bypass/i, /content.*security.*policy/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "http_smuggling",
    patterns: [/http.*smuggl/i, /request.*smuggl/i, /\bcwe-444\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "clickjacking",
    patterns: [/clickjacking/i, /\bcwe-1021\b/i, /ui.*redress/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "ldap_injection",
    patterns: [/ldap.*inject/i, /\bcwe-90\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "nosqli",
    patterns: [/nosql.*inject/i, /mongodb.*inject/i, /\bcwe-943\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "command_injection",
    patterns: [/command.*inject/i, /os.*command/i, /\bcwe-77\b/i, /\bcwe-78\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "xxss_stored",
    patterns: [/stored.*xss/i, /persistent.*xss/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "web_cache_poisoning",
    patterns: [/cache.*poison/i, /web.*cache.*inject/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "supply_chain",
    patterns: [/supply.*chain/i, /dependency.*confusion/i, /npm.*typosquat/i, /\bcwe-1357\b/i]
  },
  {
    asset_type: "webapp",
    vuln_class: "account_takeover",
    patterns: [/account.*takeover/i, /\bato\b/i, /session.*hijack/i, /\bcwe-384\b/i]
  }
];

// ---------------------------------------------------------------------------
// Classify a single report into { asset_type, vuln_class }
// ---------------------------------------------------------------------------
function classifyReport(report) {
  const haystack = [report.title, report.weakness, report.cwe]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  for (const rule of CLASSIFICATION_RULES) {
    if (rule.patterns.some((p) => p.test(haystack))) {
      return { asset_type: rule.asset_type, vuln_class: rule.vuln_class };
    }
  }

  return { asset_type: "webapp", vuln_class: "other" };
}

// ---------------------------------------------------------------------------
// Aggregate classified reports into calibration_patterns
// ---------------------------------------------------------------------------
function buildCalibrationPatterns(classifiedReports) {
  const patternMap = new Map();

  for (const report of classifiedReports) {
    const key = `${report.asset_type}::${report.vuln_class}`;

    if (!patternMap.has(key)) {
      patternMap.set(key, {
        asset_type: report.asset_type,
        vuln_class: report.vuln_class,
        total_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        informative_count: 0,
        sample_titles: [],
        sample_urls: [],
        program_counts: new Map(),
        cwe_counts: new Map(),
        weakness_counts: new Map()
      });
    }

    const entry = patternMap.get(key);
    entry.total_count += 1;

    const sev = (report.severity_rating || "").toLowerCase();
    if (sev === "critical") entry.critical_count += 1;
    else if (sev === "high") entry.high_count += 1;
    else if (sev === "medium") entry.medium_count += 1;
    else if (sev === "low") entry.low_count += 1;
    else entry.informative_count += 1;

    if (entry.sample_titles.length < DEFAULT_SAMPLE_SIZE && report.title) {
      entry.sample_titles.push(report.title);
    }
    if (entry.sample_urls.length < DEFAULT_SAMPLE_SIZE && report.url) {
      entry.sample_urls.push(report.url);
    }

    if (report.program_handle) {
      const pc = entry.program_counts.get(report.program_handle) || 0;
      entry.program_counts.set(report.program_handle, pc + 1);
    }
    if (report.cwe) {
      const cc = entry.cwe_counts.get(report.cwe) || 0;
      entry.cwe_counts.set(report.cwe, cc + 1);
    }
    if (report.weakness) {
      const wc = entry.weakness_counts.get(report.weakness) || 0;
      entry.weakness_counts.set(report.weakness, wc + 1);
    }
  }

  const patterns = {};
  for (const [key, entry] of patternMap.entries()) {
    const topPrograms = [...entry.program_counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, DEFAULT_TOP_PROGRAMS)
      .map(([handle, count]) => ({ handle, count }));

    const topCwe = [...entry.cwe_counts.entries()]
      .sort((a, b) => b[1] - a[1])[0];

    const topWeakness = [...entry.weakness_counts.entries()]
      .sort((a, b) => b[1] - a[1])[0];

    patterns[key] = {
      asset_type: entry.asset_type,
      vuln_class: entry.vuln_class,
      total_count: entry.total_count,
      critical_count: entry.critical_count,
      high_count: entry.high_count,
      medium_count: entry.medium_count,
      low_count: entry.low_count,
      informative_count: entry.informative_count,
      sample_titles: entry.sample_titles,
      sample_urls: entry.sample_urls,
      top_programs: topPrograms,
      typical_cwe: topCwe ? topCwe[0] : null,
      typical_weakness: topWeakness ? topWeakness[0] : null
    };
  }

  return patterns;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const parsed = { outDir: path.resolve("data", "global-intelligence") };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--out-dir" || argv[i] === "--out-dir=") {
      parsed.outDir = path.resolve(argv[i + 1] || "");
      i++;
    } else if (argv[i].startsWith("--out-dir=")) {
      parsed.outDir = path.resolve(argv[i].split("=")[1]);
    }
  }
  return parsed;
}

async function main() {
  const args = parseArgs(process.argv);
  const dbPath = resolveGlobalDatabasePath(args.outDir);

  console.log(`Loading disclosed reports from: ${dbPath}`);

  const db = openDatabase(dbPath);

  // Read all disclosed reports directly from DB (include hacktivity_summary if present)
  const allReports = db
    .prepare(`
      SELECT disclosed_key, remote_id, program_handle, program_name, title,
             severity_rating, weakness, cwe, url, disclosed_at, hacktivity_summary
      FROM disclosed_reports
      ORDER BY disclosed_at DESC
    `)
    .all();

  if (allReports.length === 0) {
    console.error("No disclosed reports found. Run 'npm run h1:disclosed' or 'npm run h1:bootstrap' first.");
    db.close();
    process.exit(1);
  }

  console.log(`Classifying ${allReports.length} disclosed reports...`);

  const classifiedReports = allReports.map((report) => {
    const { asset_type, vuln_class } = classifyReport(report);
    return { ...report, asset_type, vuln_class };
  });

  const classifiedCount = classifiedReports.filter((r) => r.vuln_class !== "other").length;
  console.log(`  Classified: ${classifiedCount} / ${allReports.length} (${Math.round(classifiedCount / allReports.length * 100)}%)`);

  console.log("Building calibration patterns...");
  const patterns = buildCalibrationPatterns(classifiedReports);
  const patternCount = Object.keys(patterns).length;
  console.log(`  Patterns: ${patternCount} (asset_type × vuln_class combinations)`);

  const syncedAt = new Date().toISOString();

  const payload = {
    meta: {
      synced_at: syncedAt,
      total_reports: allReports.length,
      classified_reports: classifiedCount
    },
    patterns,
    classified_reports: classifiedReports.map((r) => ({
      disclosed_key: r.disclosed_key,
      asset_type: r.asset_type,
      vuln_class: r.vuln_class
    }))
  };

  // Build report_behaviors: up to 20 reports per (asset_type, vuln_class) that have hacktivity_summary
  const behaviorsMap = {};
  for (const report of classifiedReports) {
    if (!report.hacktivity_summary) continue;
    const key = `${report.asset_type}::${report.vuln_class}`;
    if (!behaviorsMap[key]) behaviorsMap[key] = [];
    if (behaviorsMap[key].length >= 20) continue;
    behaviorsMap[key].push({
      behavior_key: [report.disclosed_key, "behavior"].join("::"),
      report_id: report.remote_id,
      program_handle: report.program_handle,
      title: report.title,
      severity_rating: report.severity_rating,
      hacktivity_summary: report.hacktivity_summary,
      url: report.url,
      disclosed_at: report.disclosed_at
    });
  }

  const behaviorClassCount = Object.keys(behaviorsMap).length;
  const behaviorTotal = Object.values(behaviorsMap).reduce((n, v) => n + v.length, 0);
  console.log(`  Behavior summaries: ${behaviorTotal} across ${behaviorClassCount} classes`);

  console.log("Persisting calibration patterns to database...");
  replaceCalibrationPatterns(db, payload);

  console.log("Persisting report behaviors to database...");
  replaceReportBehaviors(db, {
    meta: { synced_at: syncedAt },
    by_class: behaviorsMap
  });

  db.close();

  console.log("\nCalibration dataset synced.");
  console.log(`  Database: ${dbPath}`);
  console.log(`  Total reports: ${allReports.length}`);
  console.log(`  Classified: ${classifiedCount}`);
  console.log(`  Patterns generated: ${patternCount}`);

  // Print top 10 by count
  const topPatterns = Object.values(patterns)
    .sort((a, b) => b.total_count - a.total_count)
    .slice(0, 10);

  console.log("\nTop 10 patterns by volume:");
  for (const p of topPatterns) {
    const dominant = [
      p.critical_count && `${p.critical_count}×crit`,
      p.high_count && `${p.high_count}×high`,
      p.medium_count && `${p.medium_count}×med`
    ].filter(Boolean).join(" ");
    console.log(`  [${p.asset_type}] ${p.vuln_class.padEnd(30)} ${String(p.total_count).padStart(5)} reports  ${dominant}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
