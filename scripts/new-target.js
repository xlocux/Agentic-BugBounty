#!/usr/bin/env node
"use strict";

const path = require("node:path");
const { ensureDir, writeJson, resolveDatabasePath, openDatabase, initDatabase } = require("./lib/contracts");

const targetName = process.argv[2];

if (!targetName) {
  console.error("Usage: node scripts/new-target.js <target-name>");
  process.exit(1);
}

const targetDir = path.resolve("targets", targetName);
if (require("node:fs").existsSync(targetDir)) {
  console.error(`Target '${targetName}' already exists at ${targetDir}`);
  process.exit(1);
}

for (const relativeDir of [
  "findings/confirmed",
  "findings/unconfirmed",
  "findings/h1_submission_ready",
  "src",
  "logs",
  "intelligence"
]) {
  ensureDir(path.join(targetDir, relativeDir));
}

writeJson(path.join(targetDir, "target.json"), {
  schema_version: "1.0",
  target_name: targetName,
  asset_type: "webapp",
  default_mode: "whitebox",
  allowed_modes: ["whitebox", "blackbox"],
  program_url: "https://hackerone.com/[INSERT-PROGRAM]",
  source_path: "./src",
  findings_dir: "./findings",
  h1_reports_dir: "./findings/h1_submission_ready",
  logs_dir: "./logs",
  intelligence_dir: "./intelligence",
  target_version_hint: "[INSERT VERSION OR WHERE TO READ IT]",
  hackerone: {
    program_handle: "[INSERT PROGRAM HANDLE]",
    sync_enabled: true
  },
  scope: {
    in_scope: ["[INSERT IN-SCOPE ASSETS]"],
    out_of_scope: ["[INSERT OUT-OF-SCOPE EXCLUSIONS]"]
  },
  rules: [
    "Never modify files in ./src",
    "Never test against production",
    "Confirm every finding dynamically before reporting"
  ],
  setup: ["git clone [source] ./src"]
});

require("node:fs").writeFileSync(
  path.join(targetDir, "CLAUDE.md"),
  `# Target: ${targetName}
# Bug Bounty Agent Framework - Target Workspace

## Invocation
\`\`\`
/researcher --asset [webapp|mobileapp|chromeext|executable] --mode [whitebox|blackbox] ./src
/triager --asset [webapp|mobileapp|chromeext|executable]
\`\`\`

## Target details
Program URL:    [INSERT HACKERONE PROGRAM URL]
Asset type:     [INSERT ASSET TYPE]
Source path:    ./src
Target version: [INSERT VERSION]
Machine config: ./target.json
Intelligence dir: ./intelligence

## Scope notes
In scope:    [list in-scope assets]
Out of scope: [list exclusions from program page]

## Output paths
findings/confirmed/report_bundle.json
findings/unconfirmed/candidates.json
findings/triage_result.json
findings/h1_submission_ready/
logs/

## Rules
- Never modify files in ./src
- Never test against production
- Confirm every finding dynamically before reporting
- Keep ./target.json updated so the pipeline can validate scope and paths automatically
- Sync HackerOne scope/history into ./intelligence before large research sessions when API access is available
`,
  "utf8"
);

require("node:fs").writeFileSync(
  path.join(targetDir, "run.sh"),
  `#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
node ../../scripts/run-pipeline.js --target . "$@"
`,
  "utf8"
);
require("node:fs").writeFileSync(
  path.join(targetDir, "run.cmd"),
  `@echo off\r\ncd /d "%~dp0"\r\nnode ..\\..\\scripts\\run-pipeline.js --target . %*\r\n`,
  "utf8"
);

const databasePath = resolveDatabasePath(path.join(targetDir, "intelligence"));
const db = openDatabase(databasePath);
initDatabase(db);
db.close();

console.log(`Target workspace created: ${targetDir}`);
console.log(`- database initialized: ${databasePath}`);
console.log("Next steps:");
console.log(`  1. Clone/copy source into: ${path.join(targetDir, "src")}`);
console.log(`  2. Edit ${path.join(targetDir, "target.json")}`);
console.log("  3. Run on Linux/macOS: ./targets/<name>/run.sh");
console.log("  4. Run on Windows: targets\\<name>\\run.cmd");
