#!/usr/bin/env node
"use strict";

/**
 * export-training-data.js
 *
 * Exports the training dataset from accumulated framework sessions.
 * Supports all asset types: webapp, mobileapp, browserext, executable, domains.
 *
 * Usage:
 *   # Export from a specific target
 *   node scripts/export-training-data.js --target <n>
 *
 *   # Export from all targets
 *   node scripts/export-training-data.js --all
 *
 *   # Export from a specific bundle
 *   node scripts/export-training-data.js --bundle path/to/report_bundle.json --asset webapp
 *
 *   # Overwrite instead of appending
 *   node scripts/export-training-data.js --all --no-append
 *
 *   # Specify output directory
 *   node scripts/export-training-data.js --all --out data/my-dataset
 *
 *   # Show stats without exporting
 *   node scripts/export-training-data.js --stats
 */

const fs   = require("node:fs");
const path = require("node:path");
const { exportDataset } = require("./lib/dataset");

// ─── Colors ───────────────────────────────────────────────────────────────────

const C = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  cyan:    "\x1b[36m",
  yellow:  "\x1b[33m",
  green:   "\x1b[32m",
  red:     "\x1b[31m",
  magenta: "\x1b[35m",
};

function log(msg)  { process.stdout.write(`${msg}\n`); }
function ok(msg)   { log(`  ${C.green}+${C.reset}  ${msg}`); }
function warn(msg) { log(`  ${C.yellow}!${C.reset}  ${msg}`); }
function err(msg)  { log(`  ${C.red}x${C.reset}  ${msg}`); }
function dim(msg)  { log(`  ${C.dim}${msg}${C.reset}`); }

// ─── Arg parsing ──────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const parsed = {
    target:   null,
    all:      false,
    bundle:   null,
    asset:    null,
    out:      path.resolve("data", "training"),
    append:   true,
    stats:    false,
    help:     false,
  };

  for (let i = 2; i < argv.length; i++) {
    const v = argv[i];
    if (v === "--target")      parsed.target   = argv[++i];
    else if (v === "--all")    parsed.all      = true;
    else if (v === "--bundle") parsed.bundle   = argv[++i];
    else if (v === "--asset")  parsed.asset    = argv[++i];
    else if (v === "--out")    parsed.out      = path.resolve(argv[++i]);
    else if (v === "--no-append") parsed.append = false;
    else if (v === "--stats")  parsed.stats    = true;
    else if (v === "--help")   parsed.help     = true;
  }

  return parsed;
}

// ─── Resolvers ────────────────────────────────────────────────────────────────

function resolveTargetDir(targetRef) {
  // Try as integer (targets/1/), as direct path, or as name
  const asInt = parseInt(targetRef, 10);
  if (!isNaN(asInt)) {
    return path.resolve("targets", String(asInt));
  }
  if (fs.existsSync(targetRef)) return path.resolve(targetRef);
  return path.resolve("targets", targetRef);
}

function resolveTargetConfig(targetDir) {
  const configPath = path.join(targetDir, "target.json");
  if (!fs.existsSync(configPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return null;
  }
}

function collectSessionsFromTarget(targetDir) {
  const sessions = [];
  const config = resolveTargetConfig(targetDir);
  const assetType = config?.asset_type || "webapp";
  const findingsBase = path.join(targetDir, "findings");

  // Main bundle
  const bundlePath = path.join(findingsBase, "confirmed", "report_bundle.json");
  const triagePath = path.join(findingsBase, "triage_result.json");
  const intelligenceDir = path.join(targetDir, "intelligence");

  if (fs.existsSync(bundlePath)) {
    sessions.push({ bundlePath, triagePath, intelligenceDir, assetType, targetDir });
  }

  return sessions;
}

function collectAllTargets() {
  const targetsDir = path.resolve("targets");
  if (!fs.existsSync(targetsDir)) return [];

  return fs.readdirSync(targetsDir)
    .map((name) => path.join(targetsDir, name))
    .filter((p) => fs.statSync(p).isDirectory())
    .flatMap((targetDir) => collectSessionsFromTarget(targetDir));
}

// ─── Stats display ────────────────────────────────────────────────────────────

function showStats(outputDir) {
  const manifestPath = path.join(outputDir, "manifest.json");

  if (!fs.existsSync(manifestPath)) {
    warn("No manifest found. Run an export first.");
    return;
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const separator = "─".repeat(60);

  log(`\n${C.bold}${C.cyan}TRAINING DATASET STATS${C.reset}`);
  log(separator);
  log(`  Output dir    : ${outputDir}`);
  log(`  Last updated  : ${manifest.last_updated || "unknown"}`);
  log(`  Total examples: ${C.bold}${manifest.total_examples || 0}${C.reset}`);
  log(``);
  log(`  ${C.bold}By type:${C.reset}`);
  for (const [type, count] of Object.entries(manifest.by_type || {})) {
    log(`    ${type.padEnd(25)} ${C.yellow}${count}${C.reset} examples`);
  }
  log(``);
  log(`  ${C.bold}By asset type:${C.reset}`);
  for (const [asset, count] of Object.entries(manifest.by_asset_type || {})) {
    log(`    ${asset.padEnd(25)} ${C.yellow}${count}${C.reset} examples`);
  }
  log(``);
  log(`  ${C.bold}Sessions exported:${C.reset} ${(manifest.sessions || []).length}`);

  // Show file sizes
  log(``);
  log(`  ${C.bold}Files:${C.reset}`);
  const files = [
    "surface_extraction.jsonl",
    "candidate_triage.jsonl",
    "chain_hypothesis.jsonl",
    "combined.jsonl",
  ];
  for (const file of files) {
    const filePath = path.join(outputDir, file);
    if (fs.existsSync(filePath)) {
      const size = fs.statSync(filePath).size;
      const lines = fs.readFileSync(filePath, "utf8").split("\n").filter(Boolean).length;
      log(`    ${file.padEnd(30)} ${lines} rows, ${(size / 1024).toFixed(1)} KB`);
    } else {
      log(`    ${file.padEnd(30)} ${C.dim}(not yet generated)${C.reset}`);
    }
  }

  log(`\n  ${C.dim}LM Studio: load combined.jsonl as fine-tuning dataset${C.reset}`);
  log(`  ${C.dim}Axolotl:   set dataset_type: chat_template, format: chatml${C.reset}`);
  log(separator + "\n");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    log(`\n${C.bold}export-training-data.js${C.reset} — Export fine-tuning dataset from pipeline sessions\n`);
    log(`Usage:`);
    log(`  node scripts/export-training-data.js --target <n>        Export from target N`);
    log(`  node scripts/export-training-data.js --all               Export from all targets`);
    log(`  node scripts/export-training-data.js --bundle <path> --asset <type>`);
    log(`  node scripts/export-training-data.js --stats             Show dataset stats`);
    log(`  node scripts/export-training-data.js --all --no-append   Overwrite existing dataset`);
    log(`  node scripts/export-training-data.js --all --out <dir>   Custom output directory\n`);
    log(`Asset types: webapp | mobileapp | browserext | executable | domains\n`);
    return;
  }

  if (args.stats) {
    showStats(args.out);
    return;
  }

  const separator = "═".repeat(60);
  log(`\n${C.magenta}${separator}${C.reset}`);
  log(`${C.bold}${C.magenta}TRAINING DATASET EXPORT${C.reset}`);
  log(`${C.magenta}${separator}${C.reset}\n`);
  log(`  Output dir : ${args.out}`);
  log(`  Mode       : ${args.append ? "append" : "overwrite"}\n`);

  let sessions = [];

  if (args.bundle) {
    // Export from specific bundle
    if (!args.asset) {
      err("--bundle requires --asset <type>");
      process.exit(1);
    }
    const triagePath = path.join(path.dirname(path.dirname(args.bundle)), "triage_result.json");
    const intelligenceDir = path.join(path.dirname(path.dirname(args.bundle)), "intelligence");
    sessions = [{ bundlePath: path.resolve(args.bundle), triagePath, intelligenceDir, assetType: args.asset }];

  } else if (args.target) {
    const targetDir = resolveTargetDir(args.target);
    if (!fs.existsSync(targetDir)) {
      err(`Target directory not found: ${targetDir}`);
      process.exit(1);
    }
    sessions = collectSessionsFromTarget(targetDir);

  } else if (args.all) {
    sessions = collectAllTargets();

  } else {
    err("Specify --target <n>, --all, or --bundle <path> --asset <type>");
    err("Use --help for usage information.");
    process.exit(1);
  }

  if (sessions.length === 0) {
    warn("No sessions found with confirmed findings. Run the pipeline first.");
    return;
  }

  log(`  Found ${C.bold}${sessions.length}${C.reset} session(s) to export\n`);

  let totalSurface = 0;
  let totalTriage  = 0;
  let totalChain   = 0;

  for (const session of sessions) {
    const label = path.relative(process.cwd(), session.bundlePath);
    process.stdout.write(`  Exporting ${C.dim}${label}${C.reset} [${session.assetType}]... `);

    try {
      const result = exportDataset({
        bundlePath:      session.bundlePath,
        triagePath:      session.triagePath,
        intelligenceDir: session.intelligenceDir,
        assetType:       session.assetType,
        outputDir:       args.out,
        append:          args.append,
      });

      process.stdout.write(
        `${C.green}+${C.reset} +${result.surfaceCount}A +${result.triageCount}B +${result.chainCount}C\n`
      );

      totalSurface += result.surfaceCount;
      totalTriage  += result.triageCount;
      totalChain   += result.chainCount;

    } catch (e) {
      process.stdout.write(`${C.red}x${C.reset} ${e.message}\n`);
    }
  }

  const total = totalSurface + totalTriage + totalChain;

  log(`\n${"─".repeat(60)}`);
  log(`${C.bold}Export complete${C.reset}`);
  log(`  Surface extraction (A) : ${C.yellow}${totalSurface}${C.reset} examples`);
  log(`  Candidate triage   (B) : ${C.yellow}${totalTriage}${C.reset} examples`);
  log(`  Chain hypothesis   (C) : ${C.yellow}${totalChain}${C.reset} examples`);
  log(`  Total                  : ${C.bold}${C.yellow}${total}${C.reset} examples`);
  log(``);
  log(`  ${C.bold}Output files:${C.reset}`);
  log(`    ${args.out}/surface_extraction.jsonl`);
  log(`    ${args.out}/candidate_triage.jsonl`);
  log(`    ${args.out}/chain_hypothesis.jsonl`);
  log(`    ${args.out}/combined.jsonl        <- use this for LM Studio`);
  log(`    ${args.out}/manifest.json`);
  log(``);
  log(`  ${C.dim}LM Studio: File -> Open Dataset -> combined.jsonl${C.reset}`);
  log(`  ${C.dim}Axolotl:   dataset_type: chat_template, format: chatml${C.reset}`);
  log(`  ${C.dim}Unsloth:   from datasets import load_dataset; load_dataset("json", data_files="combined.jsonl")${C.reset}`);
  log(`${"─".repeat(60)}\n`);
}

main().catch((e) => {
  process.stderr.write(`Error: ${e.message}\n`);
  process.exit(1);
});
