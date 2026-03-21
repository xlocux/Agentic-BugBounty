#!/usr/bin/env node
"use strict";

const { readJson, validateBundle } = require("./lib/contracts");

const bundlePath = process.argv[2];

if (!bundlePath) {
  console.error("Usage: node scripts/validate-bundle.js <report_bundle.json>");
  process.exit(1);
}

const bundle = readJson(bundlePath);
const errors = validateBundle(bundle);

if (errors.length > 0) {
  console.error(`REPORT_BUNDLE validation failed for ${bundlePath}`);
  for (const line of errors) {
    console.error(`- ${line}`);
  }
  process.exit(1);
}

console.log(`REPORT_BUNDLE valid: ${bundlePath}`);
