#!/usr/bin/env node
"use strict";

const { readJson, validateBundle, validateTriageResult } = require("./lib/contracts");

const triagePath = process.argv[2];
const bundlePath = process.argv[3];

if (!triagePath) {
  console.error("Usage: node scripts/validate-triage-result.js <triage_result.json> [report_bundle.json]");
  process.exit(1);
}

const triageResult = readJson(triagePath);
let bundle = null;

if (bundlePath) {
  bundle = readJson(bundlePath);
  const bundleErrors = validateBundle(bundle);
  if (bundleErrors.length > 0) {
    console.error(`Reference REPORT_BUNDLE is invalid: ${bundlePath}`);
    for (const line of bundleErrors) {
      console.error(`- ${line}`);
    }
    process.exit(1);
  }
}

const errors = validateTriageResult(triageResult, bundle);

if (errors.length > 0) {
  console.error(`TRIAGE_RESULT validation failed for ${triagePath}`);
  for (const line of errors) {
    console.error(`- ${line}`);
  }
  process.exit(1);
}

console.log(`TRIAGE_RESULT valid: ${triagePath}`);
