#!/usr/bin/env node
"use strict";

const path = require("node:path");
const {
  deriveProgramHandle,
  resolveDatabasePath,
  readJson,
  resolveTargetConfigPath,
  validateTargetConfig
} = require("./lib/contracts");

const targetArg = process.argv[2];

if (!targetArg) {
  console.error("Usage: node scripts/resolve-target-config.js <target.json|target-dir|target-name>");
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

const targetDir = path.dirname(configPath);
const payload = {
  configPath,
  targetDir,
  targetName: config.target_name,
  assetType: config.asset_type,
  defaultMode: config.default_mode,
  allowedModes: config.allowed_modes,
  programUrl: config.program_url,
  sourcePath: path.resolve(targetDir, config.source_path),
  findingsDir: path.resolve(targetDir, config.findings_dir),
  h1ReportsDir: path.resolve(targetDir, config.h1_reports_dir),
  logsDir: path.resolve(targetDir, config.logs_dir),
  intelligenceDir: path.resolve(targetDir, config.intelligence_dir || "./intelligence"),
  databasePath: resolveDatabasePath(path.resolve(targetDir, config.intelligence_dir || "./intelligence")),
  hackerone: {
    programHandle: deriveProgramHandle(config),
    syncEnabled: config.hackerone?.sync_enabled ?? true
  }
};

process.stdout.write(`${JSON.stringify(payload)}\n`);
