#!/usr/bin/env node
"use strict";

const path = require("node:path");
const {
  deriveProgramHandle,
  loadProgramIntel,
  readJson,
  resolveTargetConfigPath,
  validateTargetConfig,
  writeJson
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

function summarizeHistory(history) {
  const byWeakness = new Map();
  const bySeverity = new Map();

  for (const item of history) {
    const weakness = item.weakness || item.cwe || "Unknown";
    byWeakness.set(weakness, (byWeakness.get(weakness) || 0) + 1);

    const severity = item.severity_rating || "unknown";
    bySeverity.set(severity, (bySeverity.get(severity) || 0) + 1);
  }

  return {
    top_weaknesses: [...byWeakness.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, 10)
      .map(([name, count]) => ({ name, count })),
    severity_distribution: [...bySeverity.entries()]
      .sort((left, right) => right[1] - left[1])
      .map(([name, count]) => ({ name, count }))
  };
}

function buildProfile(config, intelligence) {
  const scopes = intelligence?.scopeSnapshot?.scopes || [];
  const history = intelligence?.historySnapshot?.history || [];
  const skillSuggestions = intelligence?.skillSnapshot?.skill_suggestions || [];

  return {
    meta: {
      generated_at: new Date().toISOString(),
      target_name: config.target_name,
      asset_type: config.asset_type,
      program_url: config.program_url
    },
    target: {
      default_mode: config.default_mode,
      allowed_modes: config.allowed_modes,
      source_path: config.source_path,
      findings_dir: config.findings_dir,
      intelligence_dir: config.intelligence_dir || "./intelligence",
      rules: config.rules,
      scope: config.scope
    },
    intelligence: {
      has_snapshot: Boolean(intelligence),
      eligible_scope_count: scopes.filter((item) => item.eligible_for_submission === true).length,
      ineligible_scope_count: scopes.filter((item) => item.eligible_for_submission === false).length,
      history_count: history.length,
      history_summary: summarizeHistory(history),
      skill_suggestions: skillSuggestions
    }
  };
}

function main() {
  const args = parseArgs(process.argv);
  if (!args.target) {
    console.error("Usage: node scripts/build-target-profile.js --target <target-name|target-dir|target.json>");
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
  const profile = buildProfile(config, intelligence);
  const outputPath = path.join(intelligenceDir, "target_profile.json");

  writeJson(outputPath, profile);
  console.log(`Target profile written to ${outputPath}`);
}

main();
