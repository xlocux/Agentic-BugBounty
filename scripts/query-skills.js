#!/usr/bin/env node
"use strict";

const { openDatabase, resolveGlobalDatabasePath, querySkills } = require("./lib/db");

function parseArgs() {
  const args = process.argv.slice(2);
  const out = { asset: null, vuln: null, program: null, limit: 10, json: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--asset") out.asset = args[++i];
    else if (args[i] === "--vuln") out.vuln = args[++i];
    else if (args[i] === "--program") out.program = args[++i];
    else if (args[i] === "--limit") out.limit = parseInt(args[++i], 10);
    else if (args[i] === "--json") out.json = true;
  }
  return out;
}

function formatSkills(skills) {
  if (skills.length === 0) return "No skills found. Run: npm run calibration:extract-skills\n";
  return skills.map((s, i) => {
    const tag = s.program_handle ? `[${s.program_handle}]` : "[global]";
    const chain = s.chain_steps.length > 0 ? `\n  Chain: ${s.chain_steps.join(" → ")}` : "";
    const insight = s.insight ? `\n  Insight: ${s.insight}` : "";
    const bypass = s.bypass_of ? `\n  Bypasses: ${s.bypass_of}` : "";
    return `[${i + 1}] ${tag} [${s.asset_type}/${s.vuln_class}] ${s.severity_achieved || "?"} — ${s.title}\n  ${s.technique}${chain}${insight}${bypass}`;
  }).join("\n\n") + "\n";
}

function main() {
  const args = parseArgs();
  const db = openDatabase(resolveGlobalDatabasePath());
  const skills = querySkills(db, {
    asset_type: args.asset,
    program_handle: args.program,
    vuln_class: args.vuln,
    limit: args.limit
  });
  db.close();
  if (args.json) {
    process.stdout.write(JSON.stringify({ skills }, null, 2) + "\n");
  } else {
    process.stdout.write(formatSkills(skills));
  }
}

main();
