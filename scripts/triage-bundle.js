#!/usr/bin/env node
"use strict";

const {
  deriveProgramHandle,
  loadProgramIntel,
  readJson,
  triageBundle,
  validateBundle,
  validateTriageResult,
  writeJson
} = require("./lib/contracts");

const bundlePath = process.argv[2];
const outputPath = process.argv[3] || "findings/triage_result.json";
const intelligenceDirFlagIndex = process.argv.indexOf("--intelligence-dir");
const intelligenceDir =
  intelligenceDirFlagIndex >= 0 ? process.argv[intelligenceDirFlagIndex + 1] : null;

if (!bundlePath) {
  console.error(
    "Usage: node scripts/triage-bundle.js <report_bundle.json> [triage_result.json] [--intelligence-dir <dir>]"
  );
  process.exit(1);
}

const bundle = readJson(bundlePath);
const bundleErrors = validateBundle(bundle);
if (bundleErrors.length > 0) {
  console.error("Cannot triage an invalid REPORT_BUNDLE:");
  for (const line of bundleErrors) {
    console.error(`- ${line}`);
  }
  process.exit(1);
}

const programHandle = deriveProgramHandle({ program_url: bundle.meta.program_url });
const intelligence = intelligenceDir ? loadProgramIntel(intelligenceDir, programHandle) : null;
const triageResult = triageBundle(bundle, { intelligence });
const triageErrors = validateTriageResult(triageResult, bundle);
if (triageErrors.length > 0) {
  console.error("Generated TRIAGE_RESULT is invalid:");
  for (const line of triageErrors) {
    console.error(`- ${line}`);
  }
  process.exit(1);
}

writeJson(outputPath, triageResult);
console.log(`TRIAGE_RESULT written to ${outputPath}`);
