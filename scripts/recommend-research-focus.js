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
  validateTargetConfig
} = require("./lib/contracts");

function parseArgs(argv) {
  const parsed = { target: null };

  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--target") {
      parsed.target = argv[index + 1];
      index += 1;
    } else if (value.startsWith("--target=")) {
      parsed.target = value.split("=")[1];
    }
  }

  return parsed;
}

function main() {
  const args = parseArgs(process.argv);
  if (!args.target) {
    console.error("Usage: node scripts/recommend-research-focus.js --target <target-name|target-dir|target.json>");
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
  const intelligence = loadProgramIntel(intelligenceDir, deriveProgramHandle(config));
  const disclosed = loadDisclosedDataset();
  const researchBrief = buildResearchBrief(config, intelligence, disclosed);
  const suggestions = intelligence?.skillSnapshot?.skill_suggestions || [];

  const payload = {
    target_name: config.target_name,
    asset_type: config.asset_type,
    research_overview: researchBrief.overview,
    starting_points: researchBrief.recommended_starting_points,
    uncovered_assets: researchBrief.uncovered_assets,
    recommended_modules: suggestions.map((item) => ({
      module_hint: item.skill,
      evidence_count: item.evidence_count,
      reason: item.reason,
      sample_titles: item.sample_titles
    })),
    same_program_disclosed_top_weaknesses: researchBrief.same_program_disclosed_top_weaknesses,
    local_top_weaknesses: researchBrief.local_top_weaknesses
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main();
