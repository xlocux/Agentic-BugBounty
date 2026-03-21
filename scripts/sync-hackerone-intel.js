#!/usr/bin/env node
"use strict";

const {
  persistProgramIntel,
  readJson,
  resolveTargetConfigPath,
  syncProgramIntel,
  validateTargetConfig,
} = require("./lib/contracts");

function parseArgs(argv) {
  const parsed = {
    target: null,
    maxPages: undefined
  };

  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--target") {
      parsed.target = argv[index + 1];
      index += 1;
    } else if (value.startsWith("--target=")) {
      parsed.target = value.split("=")[1];
    } else if (value.startsWith("--max-pages=")) {
      parsed.maxPages = Number(value.split("=")[1]);
    }
  }

  return parsed;
}

async function main() {
  const args = parseArgs(process.argv);
  if (!args.target) {
    console.error(
      "Usage: node scripts/sync-hackerone-intel.js --target <target-name|target-dir|target.json> [--max-pages=5]"
    );
    process.exit(1);
  }

  const configPath = resolveTargetConfigPath(args.target);
  const config = readJson(configPath);
  const errors = validateTargetConfig(config);
  if (errors.length > 0) {
    console.error(`Target config validation failed for ${configPath}`);
    for (const line of errors) {
      console.error(`- ${line}`);
    }
    process.exit(1);
  }

  const programHandle =
    config.hackerone?.program_handle ||
    new URL(config.program_url).pathname.replace(/^\/+|\/+$/g, "");

  if (!programHandle) {
    console.error("Unable to determine HackerOne program handle from target config.");
    process.exit(1);
  }

  const targetDir = require("node:path").dirname(configPath);
  const intelligenceDir = require("node:path").resolve(
    targetDir,
    config.intelligence_dir || "./intelligence"
  );

  const intel = await syncProgramIntel(programHandle, { maxPages: args.maxPages });
  const databasePath = persistProgramIntel(config, intelligenceDir, intel);

  console.log(`HackerOne intelligence synced for ${programHandle}`);
  console.log(`- scope snapshot: ${intelligenceDir}\\h1_scope_snapshot.json`);
  console.log(`- vulnerability history: ${intelligenceDir}\\h1_vulnerability_history.json`);
  console.log(`- skill suggestions: ${intelligenceDir}\\h1_skill_suggestions.json`);
  console.log(`- sqlite database: ${databasePath}`);
  console.log(
    `- counts: scopes=${intel.meta.sources.scopes}, hacktivity=${intel.meta.sources.hacktivity}, reports=${intel.meta.sources.reports}`
  );
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
