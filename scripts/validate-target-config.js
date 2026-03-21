#!/usr/bin/env node
"use strict";

const { readJson, resolveTargetConfigPath, validateTargetConfig } = require("./lib/contracts");

const targetArg = process.argv[2];

if (!targetArg) {
  console.error("Usage: node scripts/validate-target-config.js <target.json|target-dir|target-name>");
  process.exit(1);
}

const configPath = resolveTargetConfigPath(targetArg);
const config = readJson(configPath);
const errors = validateTargetConfig(config);

if (errors.length > 0) {
  console.error(`Target config validation failed for ${configPath}`);
  for (const line of errors) {
    console.error(`- ${line}`);
  }
  process.exit(1);
}

console.log(`Target config valid: ${configPath}`);
