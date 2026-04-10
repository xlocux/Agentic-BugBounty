#!/usr/bin/env node
"use strict";

/**
 * reset-target.js
 *
 * Resets a target workspace back to a clean state, preserving:
 *   - target.json
 *   - CLAUDE.md
 *   - run.sh / run.cmd
 *   - src/  (all source files)
 *
 * Deletes and recreates:
 *   - findings/confirmed/
 *   - findings/unconfirmed/
 *   - findings/h1_submission_ready/
 *   - findings/triage_result.json
 *   - poc/
 *   - logs/
 *   - intelligence/  (DB + synced intel — re-run h1:sync to repopulate)
 *
 * Usage:
 *   node scripts/reset-target.js <target-name> [--yes]
 */

const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");

function parseArgs(argv) {
  const parsed = { target: null, yes: false };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--yes" || arg === "-y") {
      parsed.yes = true;
    } else if (arg === "--target" && argv[i + 1]) {
      parsed.target = argv[++i];
    } else if (!arg.startsWith("--") && !parsed.target) {
      parsed.target = arg;
    }
  }
  return parsed;
}

function rmrf(dirPath) {
  if (!fs.existsSync(dirPath)) return;
  fs.rmSync(dirPath, { recursive: true, force: true });
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function confirm(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

async function main() {
  const args = parseArgs(process.argv);

  if (!args.target) {
    console.error("Usage: node scripts/reset-target.js --target <name> [--yes]");
    process.exit(1);
  }

  const targetDir = path.resolve("targets", args.target);

  if (!fs.existsSync(targetDir)) {
    console.error(`Target '${args.target}' not found at ${targetDir}`);
    process.exit(1);
  }

  if (!fs.existsSync(path.join(targetDir, "target.json"))) {
    console.error(`${targetDir} does not look like a target workspace (missing target.json)`);
    process.exit(1);
  }

  const toDelete = [
    "findings/confirmed",
    "findings/unconfirmed",
    "findings/h1_submission_ready",
    "findings/triage_result.json",
    "poc",
    "logs",
    "intelligence",
    "scan_manifest.json",
    "session.json",
    "session-response.json"
  ];

  const toRecreate = [
    "findings/confirmed",
    "findings/unconfirmed",
    "findings/h1_submission_ready",
    "poc",
    "logs",
    "intelligence"
  ];

  console.log(`\nTarget: ${args.target}`);
  console.log(`Path:   ${targetDir}\n`);
  console.log("Will DELETE:");
  for (const rel of toDelete) {
    const full = path.join(targetDir, rel);
    const exists = fs.existsSync(full);
    console.log(`  ${exists ? "✓" : "·"} ${rel}`);
  }
  console.log("\nWill PRESERVE:");
  for (const rel of ["target.json", "CLAUDE.md", "run.sh", "run.cmd", "src/"]) {
    const full = path.join(targetDir, rel);
    if (fs.existsSync(full)) {
      console.log(`  ✓ ${rel}`);
    }
  }
  console.log();

  if (!args.yes) {
    const answer = await confirm("Reset this target? [y/N] ");
    if (answer !== "y" && answer !== "yes") {
      console.log("Aborted.");
      process.exit(0);
    }
  }

  for (const rel of toDelete) {
    rmrf(path.join(targetDir, rel));
  }

  for (const rel of toRecreate) {
    ensureDir(path.join(targetDir, rel));
  }

  console.log(`\nTarget '${args.target}' reset.`);
  console.log("  src/ and target.json preserved.");
  console.log("  Run the pipeline to start fresh:\n");
  console.log(`    node scripts/run-pipeline.js --target ${args.target} --cli claude\n`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
