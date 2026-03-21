#!/usr/bin/env node
"use strict";

const path = require("node:path");
const {
  buildResearchBrief,
  deriveProgramHandle,
  loadDisclosedDataset,
  loadProgramIntel,
  readJson,
  resolveTargetConfigPath,
  validateTargetConfig,
  writeJson
} = require("./lib/contracts");

function parseArgs(argv) {
  const parsed = {
    target: null,
    globalDir: path.resolve("data", "global-intelligence"),
    out: null
  };

  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--target") parsed.target = argv[++index];
    else if (value.startsWith("--target=")) parsed.target = value.split("=")[1];
    else if (value === "--global-dir") parsed.globalDir = path.resolve(argv[++index]);
    else if (value.startsWith("--global-dir=")) parsed.globalDir = path.resolve(value.split("=")[1]);
    else if (value === "--out") parsed.out = path.resolve(argv[++index]);
    else if (value.startsWith("--out=")) parsed.out = path.resolve(value.split("=")[1]);
  }

  return parsed;
}

function main() {
  const args = parseArgs(process.argv);
  if (!args.target) {
    console.error("Usage: node scripts/build-research-brief.js --target <target-name|target-dir|target.json>");
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

  const targetDir = path.dirname(configPath);
  const intelligenceDir = path.resolve(targetDir, config.intelligence_dir || "./intelligence");
  const programHandle = deriveProgramHandle(config);
  const intelligence = loadProgramIntel(intelligenceDir, programHandle);
  const disclosed = loadDisclosedDataset(args.globalDir);
  const brief = buildResearchBrief(config, intelligence, disclosed);

  if (args.out) {
    writeJson(args.out, brief);
  } else {
    writeJson(path.join(intelligenceDir, "research_brief.json"), brief);
  }

  process.stdout.write(`${JSON.stringify(brief, null, 2)}\n`);
}

main();
