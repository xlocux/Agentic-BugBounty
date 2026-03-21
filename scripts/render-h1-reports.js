#!/usr/bin/env node
"use strict";

const path = require("node:path");
const fs = require("node:fs");
const {
  ensureDir,
  readJson,
  renderH1ReportMarkdown,
  validateBundle,
  validateTriageResult
} = require("./lib/contracts");

const SEVERITY_ORDER = ["Informative", "Low", "Medium", "High", "Critical"];

const bundlePath = process.argv[2];
const triagePath = process.argv[3];
const outDir = process.argv[4] || "findings/h1_submission_ready";
const minSeverityArg = process.argv.find((a) => a.startsWith("--min-severity="));
const minSeverity = minSeverityArg ? minSeverityArg.split("=")[1] : "Informative";

if (!bundlePath || !triagePath) {
  console.error(
    "Usage: node scripts/render-h1-reports.js <report_bundle.json> <triage_result.json> [output_dir] [--min-severity=Low|Medium|High|Critical]"
  );
  process.exit(1);
}

if (!SEVERITY_ORDER.includes(minSeverity)) {
  console.error(
    `Invalid --min-severity value: ${minSeverity}. Must be one of: ${SEVERITY_ORDER.join(", ")}`
  );
  process.exit(1);
}

const minSeverityIndex = SEVERITY_ORDER.indexOf(minSeverity);

const bundle = readJson(bundlePath);
const bundleErrors = validateBundle(bundle);
if (bundleErrors.length > 0) {
  console.error("Cannot render reports from an invalid REPORT_BUNDLE:");
  for (const line of bundleErrors) console.error(`- ${line}`);
  process.exit(1);
}

const triageResult = readJson(triagePath);
const triageErrors = validateTriageResult(triageResult, bundle);
if (triageErrors.length > 0) {
  console.error("Cannot render reports from an invalid TRIAGE_RESULT:");
  for (const line of triageErrors) console.error(`- ${line}`);
  process.exit(1);
}

ensureDir(outDir);
const findingById = new Map(bundle.findings.map((finding) => [finding.report_id, finding]));
let rendered = 0;

for (const result of triageResult.results) {
  if (!result.ready_to_submit) continue;

  const severityIndex = SEVERITY_ORDER.indexOf(result.analyst_severity);
  if (severityIndex < minSeverityIndex) continue;

  const finding = findingById.get(result.report_id);
  if (!finding) {
    console.error(`No finding found for ready_to_submit result ${result.report_id}`);
    process.exit(1);
  }

  const markdown = renderH1ReportMarkdown(finding, result);
  const outputPath = path.join(outDir, `${result.report_id}.md`);
  fs.writeFileSync(outputPath, `${markdown}\n`, "utf8");
  rendered++;
}

console.log(
  `${rendered} H1 report(s) rendered to ${outDir}` +
    (minSeverity !== "Informative" ? ` (min-severity: ${minSeverity})` : "")
);
