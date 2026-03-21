#!/usr/bin/env node
"use strict";

/**
 * bbscope-doctor.js
 *
 * Health check for bbscope API connectivity.
 * No credentials required.
 *
 * Usage:
 *   node scripts/bbscope-doctor.js
 *   npm run bbscope:doctor
 */

const { fetchAllPrograms, fetchProgramScope, PLATFORM_LABELS } = require("./lib/bbscope");

async function main() {
  console.log("bbscope Doctor");
  console.log("  API base : https://bbscope.com/api/v1");
  console.log("  Auth     : none required");
  console.log("");

  // Check 1: /programs endpoint
  try {
    const programs = await fetchAllPrograms({ platform: "h1" });
    console.log("Programs endpoint (h1): OK");
    console.log(`  programs returned : ${programs.length}`);
    if (programs.length > 0) {
      const sample = programs[0];
      const handle = sample.handle || sample.slug || sample.name || "(unknown)";
      console.log(`  sample handle     : ${handle}`);
    }
  } catch (err) {
    console.log("Programs endpoint (h1): FAILED");
    console.log(`  error: ${err.message}`);
    process.exit(1);
  }

  console.log("");

  // Check 2: /programs/{platform}/{handle} — fetch scope for a known public program
  const testPlatform = "h1";
  const testHandle = "security";   // HackerOne's own program, always public
  try {
    const scopes = await fetchProgramScope(testPlatform, testHandle);
    console.log(`Scope endpoint (${testPlatform}/${testHandle}): OK`);
    console.log(`  scope targets returned : ${scopes.length}`);
    if (scopes.length > 0) {
      console.log(`  sample target          : ${scopes[0].asset_identifier || "(none)"}`);
    }
  } catch (err) {
    console.log(`Scope endpoint (${testPlatform}/${testHandle}): FAILED`);
    console.log(`  error: ${err.message}`);
    process.exit(1);
  }

  console.log("");
  console.log("Platforms supported:");
  for (const [code, label] of Object.entries(PLATFORM_LABELS)) {
    console.log(`  ${code.padEnd(4)} → ${label}`);
  }

  console.log("");
  console.log("Diagnosis: bbscope API is reachable and responding correctly.");
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
