#!/usr/bin/env node
"use strict";

/**
 * render-poc-artifacts.js
 *
 * Extracts PoC code from a report_bundle.json into individual files and
 * writes a vulnerability summary in Markdown format.
 *
 * Usage:
 *   node scripts/render-poc-artifacts.js <bundle.json> --poc-dir <output-dir>
 *
 * Output:
 *   <poc-dir>/EXT-001_<slug>.<ext>   — one file per finding with poc_code
 *   <poc-dir>/summary.md             — full vulnerability summary
 */

const fs = require("node:fs");
const path = require("node:path");
const { readJson } = require("./lib/contracts");

const POC_EXTENSION = {
  html:         ".html",
  curl:         ".sh",
  python:       ".py",
  js_console:   ".js",
  burp_request: ".txt",
  gdb:          ".sh",
  other:        ".txt"
};

function slugify(str) {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_|_$/g, "")
    .substring(0, 40);
}

function severityBadge(sev) {
  switch ((sev || "").toLowerCase()) {
    case "critical": return "🔴 Critical";
    case "high":     return "🟠 High";
    case "medium":   return "🟡 Medium";
    case "low":      return "🟢 Low";
    default:         return `⚪ ${sev || "?"}`;
  }
}

function renderFindingDetail(f, lines) {
  const ext     = POC_EXTENSION[f.poc_type] || ".txt";
  const pocFile = `${f.report_id}_${slugify(f.finding_title)}${ext}`;

  lines.push(`### ${severityBadge(f.severity_claimed)} — [${f.report_id}] ${f.finding_title}`);
  lines.push(``);
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| CVSS score | **${f.cvss_score_claimed ?? "?"}** |`);
  lines.push(`| CVSS vector | \`${f.cvss_vector_claimed || "?"}\` |`);
  lines.push(`| CWE | ${f.cwe_claimed || "?"} |`);
  lines.push(`| Component | \`${f.affected_component || "?"}\` |`);
  lines.push(`| PoC type | ${f.poc_type || "?"} |`);
  if (f.poc_code) {
    lines.push(`| PoC file | [${pocFile}](./${pocFile}) |`);
  }
  if (f.confirmation_status === "unconfirmed" && f.reason_not_confirmed) {
    lines.push(`| Status | ⚠️ Unconfirmed — ${f.reason_not_confirmed} |`);
  }
  lines.push(``);
  lines.push(`**Summary**`);
  lines.push(``);
  lines.push(f.summary || "");
  lines.push(``);
  lines.push(`**Impact**`);
  lines.push(``);
  lines.push(f.impact_claimed || "");
  lines.push(``);
  lines.push(`**Steps to reproduce**`);
  lines.push(``);
  for (const step of (f.steps_to_reproduce || [])) {
    lines.push(step);
  }
  lines.push(``);
  lines.push(`**Remediation**`);
  lines.push(``);
  lines.push(f.remediation_suggested || "");
  lines.push(``);
  if (f.researcher_notes) {
    lines.push(`> **Researcher notes:** ${f.researcher_notes}`);
    lines.push(``);
  }
  lines.push(`**Observed result**`);
  lines.push(``);
  lines.push(f.observed_result || "");
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
}

function renderSummary(bundle, pocDir) {
  const meta         = bundle.meta || {};
  const findings     = bundle.findings || [];
  const candidates   = bundle.unconfirmed_candidates || [];
  const stats        = bundle.analysis_summary || {};

  const lines = [];

  lines.push(`# Security Research Summary`);
  lines.push(``);
  lines.push(`| | |`);
  lines.push(`|---|---|`);
  lines.push(`| **Target** | ${meta.target_name || "unknown"} |`);
  lines.push(`| **Asset type** | ${meta.asset_type || "?"} |`);
  lines.push(`| **Mode** | ${meta.analysis_mode || "?"} |`);
  lines.push(`| **Program** | ${meta.program_url || "?"} |`);
  lines.push(`| **Version** | ${meta.target_version || "?"} |`);
  lines.push(`| **Generated** | ${meta.generated_at || new Date().toISOString()} |`);
  lines.push(`| **Agent** | ${meta.researcher_agent || "?"} |`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // Stats
  lines.push(`## Analysis Stats`);
  lines.push(``);
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Files analyzed | ${stats.files_analyzed ?? "?"} |`);
  lines.push(`| Grep hits | ${stats.grep_hits_total ?? "?"} |`);
  lines.push(`| Candidates found | ${stats.candidates_found ?? "?"} |`);
  lines.push(`| Confirmed findings | **${stats.confirmed_findings ?? findings.length}** |`);
  lines.push(`| Unconfirmed candidates | **${candidates.length}** |`);
  lines.push(`| Time spent | ${stats.time_spent_minutes ?? "?"} min |`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // Findings overview table (confirmed + unconfirmed)
  const allFindings = [
    ...findings.map(f => ({ ...f, _status: "confirmed" })),
    ...candidates.map(f => ({ ...f, _status: "unconfirmed" })),
  ];

  lines.push(`## Findings Overview`);
  lines.push(``);
  lines.push(`| ID | Title | Severity | CVSS | Status | Component |`);
  lines.push(`|----|-------|----------|------|--------|-----------|`);
  for (const f of allFindings) {
    const status = f._status === "confirmed" ? "✅ Confirmed" : "⚠️ Unconfirmed";
    lines.push(`| ${f.report_id} | ${f.finding_title} | ${severityBadge(f.severity_claimed)} | ${f.cvss_score_claimed ?? "?"} | ${status} | \`${f.affected_component}\` |`);
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // Confirmed findings detail
  lines.push(`## Confirmed Findings`);
  lines.push(``);
  if (findings.length === 0) {
    lines.push(`No confirmed findings in this bundle.`);
    lines.push(``);
  } else {
    for (const f of findings) {
      renderFindingDetail(f, lines);
    }
  }

  // Unconfirmed candidates detail
  if (candidates.length > 0) {
    lines.push(`## Unconfirmed Candidates`);
    lines.push(``);
    lines.push(`> These findings could not be dynamically confirmed (e.g. missing test environment).`);
    lines.push(`> Static analysis suggests they are valid — review before dismissing.`);
    lines.push(``);
    for (const f of candidates) {
      renderFindingDetail(f, lines);
    }
  }

  return lines.join("\n");
}

function main() {
  let bundlePath = "";
  let pocDir = "";

  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === "--poc-dir") {
      pocDir = process.argv[++i];
    } else if (!bundlePath) {
      bundlePath = process.argv[i];
    }
  }

  if (!bundlePath) {
    console.error("Usage: node scripts/render-poc-artifacts.js <bundle.json> --poc-dir <output-dir>");
    process.exit(1);
  }

  if (!fs.existsSync(bundlePath)) {
    console.error(`Bundle not found: ${bundlePath}`);
    process.exit(1);
  }

  const bundle     = readJson(bundlePath);
  const findings   = bundle.findings || [];
  const candidates = bundle.unconfirmed_candidates || [];
  const allFindings = [...findings, ...candidates];

  // Default poc dir: targets/<name>/poc  (two levels up from findings/confirmed/)
  if (!pocDir) {
    pocDir = path.join(path.dirname(bundlePath), "..", "..", "poc");
  }
  fs.mkdirSync(pocDir, { recursive: true });

  // Write individual PoC files (confirmed + unconfirmed candidates)
  let pocCount = 0;
  for (const f of allFindings) {
    if (!f.poc_code) continue;
    const ext      = POC_EXTENSION[f.poc_type] || ".txt";
    const fileName = `${f.report_id}_${slugify(f.finding_title)}${ext}`;
    const filePath = path.join(pocDir, fileName);
    fs.writeFileSync(filePath, f.poc_code, "utf8");
    console.log(`  poc  ${fileName}`);
    pocCount++;
  }

  // Write summary.md
  const summaryPath = path.join(pocDir, "summary.md");
  fs.writeFileSync(summaryPath, renderSummary(bundle, pocDir), "utf8");
  console.log(`  md   summary.md`);
  console.log(`${pocCount} PoC file(s) + summary written to: ${pocDir}`);
}

main();
