#!/usr/bin/env node
"use strict";

/**
 * query-calibration.js
 *
 * CLI query tool for the calibration dataset.
 * Usable by humans and referenced by agent prompts via:
 *   node scripts/query-calibration.js --asset chromeext --vuln privilege_escalation_messages
 *   node scripts/query-calibration.js --asset webapp --vuln xss
 *   node scripts/query-calibration.js --asset chromeext
 *   node scripts/query-calibration.js --all
 *
 * Output: JSON to stdout (pipe-friendly) or human table (default).
 */

const path = require("node:path");
const {
  openDatabase,
  queryCalibrationDataset,
  queryReportBehaviors,
  resolveGlobalDatabasePath
} = require("./lib/db");

function parseArgs(argv) {
  const parsed = {
    outDir: path.resolve("data", "global-intelligence"),
    assetType: null,
    vulnClass: null,
    all: false,
    json: false,
    behaviors: false,
    limit: 10
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--asset" || arg === "-a") {
      parsed.assetType = argv[++i];
    } else if (arg.startsWith("--asset=")) {
      parsed.assetType = arg.split("=")[1];
    } else if (arg === "--vuln" || arg === "-v") {
      parsed.vulnClass = argv[++i];
    } else if (arg.startsWith("--vuln=")) {
      parsed.vulnClass = arg.split("=")[1];
    } else if (arg === "--all") {
      parsed.all = true;
    } else if (arg === "--json") {
      parsed.json = true;
    } else if (arg === "--behaviors") {
      parsed.behaviors = true;
    } else if (arg === "--limit") {
      parsed.limit = parseInt(argv[++i], 10) || 10;
    } else if (arg.startsWith("--limit=")) {
      parsed.limit = parseInt(arg.split("=")[1], 10) || 10;
    } else if (arg === "--out-dir") {
      parsed.outDir = path.resolve(argv[++i]);
    } else if (arg.startsWith("--out-dir=")) {
      parsed.outDir = path.resolve(arg.split("=")[1]);
    }
  }

  return parsed;
}

function formatTable(patterns) {
  if (patterns.length === 0) {
    return "No calibration data found for the specified filters.";
  }

  const lines = [
    "CALIBRATION DATASET QUERY RESULTS",
    "─".repeat(100),
    [
      "ASSET".padEnd(12),
      "VULN CLASS".padEnd(32),
      "TOTAL".padStart(6),
      "CRIT".padStart(5),
      "HIGH".padStart(5),
      "MED".padStart(5),
      "LOW".padStart(5),
      "  TYPICAL SEVERITY".padEnd(18),
      "TOP CWE"
    ].join("  "),
    "─".repeat(100)
  ];

  for (const p of patterns) {
    const sevBar = [
      p.counts.critical > 0 ? `${p.counts.critical}C` : "",
      p.counts.high > 0 ? `${p.counts.high}H` : "",
      p.counts.medium > 0 ? `${p.counts.medium}M` : "",
      p.counts.low > 0 ? `${p.counts.low}L` : ""
    ].filter(Boolean).join("/");

    lines.push(
      [
        p.asset_type.padEnd(12),
        p.vuln_class.padEnd(32),
        String(p.counts.total).padStart(6),
        String(p.counts.critical).padStart(5),
        String(p.counts.high).padStart(5),
        String(p.counts.medium).padStart(5),
        String(p.counts.low).padStart(5),
        `  ${(p.typical_severity || "—").padEnd(16)}`,
        p.typical_cwe || "—"
      ].join("  ")
    );

    if (p.sample_titles.length > 0) {
      lines.push(`  Sample titles:`);
      for (const t of p.sample_titles.slice(0, 3)) {
        lines.push(`    • ${t}`);
      }
    }
    if (p.top_programs.length > 0) {
      const prog = p.top_programs.slice(0, 3).map((x) => `${x.handle}(${x.count})`).join(", ");
      lines.push(`  Top programs: ${prog}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

function formatBehaviors(behaviors) {
  if (behaviors.length === 0) {
    return "No behavior summaries found for the specified filters.";
  }

  const lines = [];
  for (const row of behaviors) {
    lines.push(`[${row.asset_type}/${row.vuln_class}] ${row.title || "(no title)"}`);
    lines.push(`  Program: ${row.program_handle || "—"}  |  Severity: ${row.severity_rating || "—"}  |  Disclosed: ${(row.disclosed_at || "").slice(0, 10)}`);
    if (row.url) lines.push(`  URL: ${row.url}`);
    if (row.hacktivity_summary) {
      const summary = row.hacktivity_summary.replace(/\n/g, " ").slice(0, 400);
      lines.push(`  Summary: ${summary}${row.hacktivity_summary.length > 400 ? "…" : ""}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function main() {
  const args = parseArgs(process.argv);

  if (!args.assetType && !args.all) {
    console.error("Usage:");
    console.error("  node scripts/query-calibration.js --asset <type> [--vuln <class>] [--json]");
    console.error("  node scripts/query-calibration.js --asset <type> --vuln <class> --behaviors [--limit N] [--json]");
    console.error("  node scripts/query-calibration.js --all [--json]");
    console.error("");
    console.error("Asset types: webapp, mobileapp, chromeext, executable");
    console.error("Vuln classes: xss, sqli, ssrf, idor, csrf, rce, uxss, privilege_escalation_messages, ...");
    console.error("Flags: --behaviors  show real H1 report summaries (researcher/triager behavior examples)");
    process.exit(1);
  }

  const dbPath = resolveGlobalDatabasePath(args.outDir);

  let db;
  try {
    db = openDatabase(dbPath);
  } catch {
    console.error(`Could not open database: ${dbPath}`);
    console.error("Run 'npm run h1:disclosed' and 'npm run calibration:sync' first.");
    process.exit(1);
  }

  if (args.behaviors) {
    const behaviors = queryReportBehaviors(db, {
      assetType: args.all ? null : args.assetType,
      vulnClass: args.vulnClass,
      limit: args.limit
    });
    db.close();

    if (args.json) {
      console.log(JSON.stringify({ behaviors }, null, 2));
    } else {
      console.log(`Report behavior summaries (${behaviors.length} results):\n`);
      console.log(formatBehaviors(behaviors));
    }
    return;
  }

  const result = queryCalibrationDataset(db, {
    assetType: args.all ? null : args.assetType,
    vulnClass: args.vulnClass
  });
  db.close();

  if (!result.meta.synced_at) {
    console.error("Calibration dataset not found. Run 'npm run calibration:sync' first.");
    process.exit(1);
  }

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`Calibration data as of: ${result.meta.synced_at}`);
    console.log(`Reports analyzed: ${result.meta.total_reports} total, ${result.meta.classified_reports} classified\n`);
    console.log(formatTable(result.patterns));
  }
}

main();
