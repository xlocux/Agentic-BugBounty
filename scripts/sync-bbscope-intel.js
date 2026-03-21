#!/usr/bin/env node
"use strict";

/**
 * sync-bbscope-intel.js
 *
 * Syncs scope data from bbscope.com for a specific bug bounty program.
 * No API credentials required — bbscope is a public API.
 *
 * Usage:
 *   node scripts/sync-bbscope-intel.js --target <name> [--platform h1|bc|it|ywh]
 *   node scripts/sync-bbscope-intel.js --handle <slug> --platform <h1|bc|it|ywh> --target <name>
 *
 * Writes to targets/<name>/intelligence/:
 *   bbscope_scope_snapshot.json
 *   agentic-bugbounty.db  (shared with H1 sync)
 */

const path = require("node:path");
const { readJson, resolveTargetConfigPath, validateTargetConfig } = require("./lib/contracts");
const { persistBbscopeIntel, syncBbscopeProgramIntel, PLATFORM_LABELS } = require("./lib/bbscope");

function parseArgs(argv) {
  const parsed = {
    target: null,
    handle: null,
    platform: null,
    scope: "in"
  };

  for (let i = 2; i < argv.length; i += 1) {
    const v = argv[i];
    if (v === "--target") { parsed.target = argv[++i]; }
    else if (v.startsWith("--target=")) { parsed.target = v.split("=")[1]; }
    else if (v === "--handle") { parsed.handle = argv[++i]; }
    else if (v.startsWith("--handle=")) { parsed.handle = v.split("=")[1]; }
    else if (v === "--platform") { parsed.platform = argv[++i]; }
    else if (v.startsWith("--platform=")) { parsed.platform = v.split("=")[1]; }
    else if (v === "--scope") { parsed.scope = argv[++i]; }
    else if (v.startsWith("--scope=")) { parsed.scope = v.split("=")[1]; }
  }

  return parsed;
}

// Guess platform from program_url if not provided
function guessPlatform(config) {
  const url = (config.program_url || "").toLowerCase();
  if (url.includes("hackerone.com")) return "h1";
  if (url.includes("intigriti.com")) return "it";
  if (url.includes("yeswehack.com")) return "ywh";
  // bbscope URL format: https://bbscope.com/programs/h1/handle
  const bbscopeMatch = url.match(/bbscope\.com\/programs\/(h1|bc|it|ywh)\//);
  if (bbscopeMatch) return bbscopeMatch[1];
  return null;
}

// Extract program handle from target config or program_url
function resolveHandle(config, argHandle) {
  if (argHandle) return argHandle;
  if (config.hackerone?.program_handle) return config.hackerone.program_handle;
  if (config.program_handle) return config.program_handle;
  try {
    const url = new URL(config.program_url);
    // bbscope URL: /programs/h1/<handle>
    const bbscopeMatch = url.pathname.match(/\/programs\/(?:h1|bc|it|ywh)\/([^/]+)/);
    if (bbscopeMatch) return bbscopeMatch[1];
    return url.pathname.replace(/^\/+|\/+$/g, "").split("/").pop();
  } catch {
    return null;
  }
}

async function main() {
  const args = parseArgs(process.argv);

  if (!args.target) {
    console.error(
      "Usage: node scripts/sync-bbscope-intel.js --target <name> [--platform h1|it|ywh] [--handle <slug>]"
    );
    process.exit(1);
  }

  const configPath = resolveTargetConfigPath(args.target);
  const config = readJson(configPath);
  const errors = validateTargetConfig(config);
  if (errors.length > 0) {
    console.error(`Target config validation failed for ${configPath}`);
    for (const line of errors) console.error(`  - ${line}`);
    process.exit(1);
  }

  const platform = args.platform || guessPlatform(config);
  if (!platform) {
    console.error(
      "Cannot determine platform. Use --platform h1|it|ywh or set program_url in target.json."
    );
    process.exit(1);
  }

  const handle = resolveHandle(config, args.handle);
  if (!handle) {
    console.error(
      "Cannot determine program handle. Use --handle <slug> or set hackerone.program_handle / program_url in target.json."
    );
    process.exit(1);
  }

  const targetDir = path.dirname(configPath);
  const intelligenceDir = path.resolve(targetDir, config.intelligence_dir || "./intelligence");

  console.log(`bbscope sync: ${handle} (${PLATFORM_LABELS[platform] || platform})`);
  console.log(`Fetching ${args.scope}-scope targets from bbscope.com...`);

  const intel = await syncBbscopeProgramIntel(platform, handle, { scope: args.scope });
  const dbPath = persistBbscopeIntel(config, intelligenceDir, intel);

  console.log(`\nbbscope intelligence synced for ${handle}`);
  console.log(`  platform : ${intel.meta.platform_label}`);
  console.log(`  scopes   : ${intel.meta.sources.scopes}`);
  console.log(`  snapshot : ${path.join(intelligenceDir, "bbscope_scope_snapshot.json")}`);
  console.log(`  database : ${dbPath}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
