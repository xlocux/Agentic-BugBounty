#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const {
  ensureDir,
  initDatabase,
  openDatabase,
  readJson,
  writeJson,
  resolveDatabasePath,
  resolveTargetConfigPath,
  validateTargetConfig
} = require("./lib/contracts");
const { detectAssetsInSrcDir } = require("./lib/detect-assets");

function parseArgs(argv) {
  const args = { targetRef: "", detect: false };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--detect") args.detect = true;
    else if (!args.targetRef) args.targetRef = argv[i];
  }
  return args;
}

function buildDefaultConfig(targetName, assets, targetDir) {
  const primary = assets[0];
  const additional = assets.slice(1);

  const config = {
    schema_version: "1.0",
    target_name: targetName,
    asset_type: primary.asset_type,
    default_mode: "whitebox",
    allowed_modes: ["whitebox", "blackbox"],
    program_url: "https://hackerone.com/[INSERT-PROGRAM]",
    source_path: primary.source_path,
    findings_dir: "./findings",
    h1_reports_dir: "./findings/h1_submission_ready",
    logs_dir: "./logs",
    intelligence_dir: "./intelligence",
    target_version_hint: "[check source after cloning]",
    hackerone: {
      program_handle: "[INSERT-PROGRAM-HANDLE]",
      sync_enabled: false
    },
    scope: {
      in_scope: ["[INSERT IN-SCOPE ASSETS]"],
      out_of_scope: ["Self-XSS", "DoS", "Known vulnerable libraries without PoC"]
    },
    rules: [
      "Never modify files in ./src",
      "Never test against production",
      "Confirm every finding dynamically before reporting"
    ]
  };

  if (additional.length > 0) {
    config.additional_assets = additional;
  }

  return config;
}

function main() {
  const args = parseArgs(process.argv);
  if (!args.targetRef) {
    console.error("Usage: node scripts/setup-target.js <target-name|target-dir|target.json> [--detect]");
    process.exit(1);
  }

  // Resolve target dir — tolerate non-existent target.json when --detect is used
  let configPath;
  let targetDir;
  try {
    configPath = resolveTargetConfigPath(args.targetRef);
    targetDir = path.dirname(configPath);
  } catch {
    // Treat targetRef as a directory name under targets/
    targetDir = path.resolve("targets", args.targetRef);
    configPath = path.join(targetDir, "target.json");
  }

  // --detect: scan src dir and create/update target.json
  if (args.detect) {
    const srcDir = path.join(targetDir, "src");

    if (!fs.existsSync(srcDir)) {
      console.error(`src directory not found: ${srcDir}`);
      console.error("Clone/copy your target source into that directory first.");
      process.exit(1);
    }

    const detected = detectAssetsInSrcDir(srcDir, targetDir);
    if (detected.length === 0) {
      console.error(`No assets detected in ${srcDir}`);
      process.exit(1);
    }

    console.log(`Detected ${detected.length} asset(s) in ${srcDir}:`);
    for (const a of detected) {
      console.log(`  - ${a.asset_type}  ${a.source_path}`);
    }

    // If target.json already exists, merge only the detected fields
    let config;
    if (fs.existsSync(configPath)) {
      config = readJson(configPath);
      config.asset_type = detected[0].asset_type;
      config.source_path = detected[0].source_path;
      if (detected.length > 1) {
        config.additional_assets = detected.slice(1);
      } else {
        delete config.additional_assets;
      }
      console.log(`Updated existing target.json: ${configPath}`);
    } else {
      // Create all required dirs
      for (const rel of ["findings/confirmed", "findings/unconfirmed", "findings/h1_submission_ready", "logs", "intelligence"]) {
        ensureDir(path.join(targetDir, rel));
      }
      const targetName = path.basename(targetDir);
      config = buildDefaultConfig(targetName, detected, targetDir);
      writeJson(configPath, config);
      console.log(`Created target.json: ${configPath}`);
      console.log("Edit it to fill in program_url, program_handle, and scope details.");
    }

    // Write back if merging into existing
    if (fs.existsSync(configPath)) {
      writeJson(configPath, config);
    }
  }

  // Validate config (skip strict validation if --detect just created a placeholder)
  const config = readJson(configPath);
  const errors = validateTargetConfig(config);
  if (errors.length > 0) {
    if (args.detect) {
      console.warn("target.json has placeholder values — fill them in before running the pipeline:");
      for (const line of errors) console.warn(`  - ${line}`);
    } else {
      console.error(`Target config validation failed for ${configPath}`);
      for (const line of errors) console.error(`  - ${line}`);
      process.exit(1);
    }
  }

  // Init SQLite database
  const intelligenceDir = path.resolve(targetDir, config.intelligence_dir || "./intelligence");
  ensureDir(intelligenceDir);
  const dbPath = resolveDatabasePath(intelligenceDir);
  const db = openDatabase(dbPath);
  initDatabase(db);
  db.close();

  console.log(`Target setup complete: ${targetDir}`);
  console.log(`- sqlite database ready: ${dbPath}`);
  console.log(`- primary asset: ${config.asset_type}  ${path.resolve(targetDir, config.source_path)}`);
  if (config.additional_assets && config.additional_assets.length > 0) {
    for (const a of config.additional_assets) {
      console.log(`- additional asset: ${a.asset_type}  ${path.resolve(targetDir, a.source_path)}`);
    }
  }
}

main();
