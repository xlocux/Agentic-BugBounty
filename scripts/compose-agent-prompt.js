#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const {
  buildResearchBrief,
  deriveProgramHandle,
  loadDisclosedDataset,
  loadProgramIntel,
  openDatabase,
  queryCveIntel,
  querySkills,
  readJson,
  resolveGlobalDatabasePath,
  resolveTargetConfigPath
} = require("./lib/contracts");

const ROOT = path.resolve(__dirname, "..");
const COMMANDS_DIR = path.join(ROOT, ".claude", "commands");

const RESEARCHER_VULN_MAP = {
  graphql: "asset/webapp/vuln/graphql.md",
  pp: "asset/webapp/vuln/prototype_pollution.md",
  postmessage: "asset/%asset%/vuln/postmessage.md",
  wcp: "asset/webapp/vuln/web_cache_poisoning.md",
  smuggling: "asset/webapp/vuln/http_smuggling.md",
  cors: "asset/webapp/vuln/cors.md",
  supplychain: "shared/vuln/supply_chain.md"
};

const RESEARCHER_BYPASS_MAP = {
  encoding: "shared/bypass/encoding.md",
  xss: "shared/bypass/xss_filter_evasion.md",
  sqli: "shared/bypass/sqli_filter_evasion.md",
  ssrf: "shared/bypass/ssrf_filter_evasion.md",
  auth: "shared/bypass/auth_bypass.md",
  waf: "shared/bypass/waf_evasion.md"
};

function parseArgs(argv) {
  const args = {
    role: null,
    asset: null,
    mode: null,
    target: null,
    sourceName: null,
    vuln: [],
    bypass: []
  };

  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (!args.role && !value.startsWith("--")) {
      args.role = value;
    } else if (value === "--asset") {
      args.asset = argv[++index];
    } else if (value === "--mode") {
      args.mode = argv[++index];
    } else if (value === "--target") {
      args.target = argv[++index];
    } else if (value === "--source-name") {
      args.sourceName = argv[++index];
    } else if (value === "--vuln") {
      args.vuln = String(argv[++index]).split(",").filter(Boolean);
    } else if (value === "--bypass") {
      args.bypass = String(argv[++index]).split(",").filter(Boolean);
    }
  }

  return args;
}

function readModule(relativePath) {
  const fullPath = path.join(COMMANDS_DIR, relativePath);
  if (!fs.existsSync(fullPath)) {
    return null;
  }
  return `\n\n# FILE: ${relativePath}\n\n${fs.readFileSync(fullPath, "utf8")}`;
}

function resolveTargetContext(targetArg) {
  if (!targetArg) {
    return null;
  }

  try {
    const configPath = resolveTargetConfigPath(targetArg);
    const config = readJson(configPath);
    const targetDir = path.dirname(configPath);
    const claudePath = path.join(targetDir, "CLAUDE.md");
    const intelligenceDir = path.resolve(targetDir, config.intelligence_dir || "./intelligence");
    const programHandle = deriveProgramHandle(config);
    const intelligence = loadProgramIntel(intelligenceDir, programHandle);
    const disclosedDataset = loadDisclosedDataset();
    return {
      configPath,
      config,
      claudeMd: fs.existsSync(claudePath) ? fs.readFileSync(claudePath, "utf8") : null,
      researchBrief: buildResearchBrief(config, intelligence, disclosedDataset)
    };
  } catch {
    return null;
  }
}

/**
 * Build an intelligence brief from skill_library + cve_intel for the given asset + target.
 * Opens and closes the global DB internally. Returns null if DB unavailable or empty.
 */
function buildIntelligenceBrief(asset, targetName) {
  let db = null;
  try {
    db = openDatabase(resolveGlobalDatabasePath());
    const skills = querySkills(db, { asset_type: asset, limit: 10 });
    const cves = targetName ? queryCveIntel(db, targetName, { limit: 10 }) : [];
    if (skills.length === 0 && cves.length === 0) return null;

    const skillLines = skills.slice(0, 5).map((s) => {
      const bypass = s.bypass_of ? ` (bypasses ${s.bypass_of})` : "";
      return `  - [${s.asset_type}/${s.vuln_class}] ${s.title}${bypass}: ${s.technique.slice(0, 120)}...`;
    }).join("\n");

    const cveLines = cves.slice(0, 5).map((c) => {
      const hints = c.variant_hints ? `\n    Variant hints: ${c.variant_hints.slice(0, 150)}` : "";
      return `  - ${c.cve_id} CVSS:${c.cvss_score || "?"} — ${(c.description || "").slice(0, 100)}${hints}`;
    }).join("\n");

    return [
      `## Extracted Hacker Skills (${skills.length} for ${asset})`,
      skillLines || "  (none yet — run: npm run calibration:extract-skills)",
      `\n## CVE Intel for ${targetName || "target"} (${cves.length} CVEs)`,
      cveLines || `  (none yet — run: npm run cve:sync -- --target ${targetName || "name"})`,
      "\nApply this intelligence in Phase 0 steps 0.5–0.8."
    ].join("\n");
  } catch {
    return null; // DB unavailable — skip silently
  } finally {
    if (db) db.close();
  }
}

function composeResearcherPrompt(args) {
  if (!args.asset || !args.mode) {
    throw new Error("Researcher prompt requires --asset and --mode.");
  }

  const sections = [
    readModule("shared/core.md"),
    readModule(`shared/researcher_${args.mode === "blackbox" ? "bb" : "wb"}.md`),
    readModule(`asset/${args.asset}/module.md`)
  ];

  for (const vuln of args.vuln) {
    const template = RESEARCHER_VULN_MAP[vuln];
    if (!template) continue;
    sections.push(readModule(template.replace("%asset%", args.asset)));
  }

  const bypasses = args.bypass.includes("all")
    ? Object.keys(RESEARCHER_BYPASS_MAP)
    : args.bypass;
  for (const bypass of bypasses) {
    const modulePath = RESEARCHER_BYPASS_MAP[bypass];
    if (!modulePath) continue;
    sections.push(readModule(modulePath));
  }

  const targetContext = resolveTargetContext(args.target);
  if (targetContext) {
    sections.push(`\n\n# TARGET CONFIG\n\n${JSON.stringify(targetContext.config, null, 2)}`);
    if (targetContext.claudeMd) {
      sections.push(`\n\n# TARGET NOTES (CLAUDE.md)\n\n${targetContext.claudeMd}`);
    }
    if (targetContext.researchBrief) {
      sections.push(`\n\n# TARGET INTELLIGENCE BRIEF\n\n${JSON.stringify(targetContext.researchBrief, null, 2)}`);
      sections.push(`

# RESEARCH PRIORITIZATION

Before starting broad exploration:
- read the target intelligence brief
- start from the top recommended starting points first
- prioritize uncovered assets before revisiting already-covered surfaces
- use priority bug families and disclosed-history signal to decide which modules to load first
- explicitly note when you are exploring a new asset not previously covered by local history
`);
    }
  }

  sections.push(`

# EXECUTION CONTEXT

- role: researcher
- asset: ${args.asset}
- mode: ${args.mode}
- target: ${args.target || "(not provided)"}${args.sourceName ? `\n- source_name: ${args.sourceName}` : ""}
- vuln modules: ${args.vuln.join(", ") || "(none)"}
- bypass modules: ${args.bypass.join(", ") || "(none)"}

Produce:
- findings/confirmed/report_bundle.json
- findings/unconfirmed/candidates.json
`);

  // Intelligence brief — skill_library + cve_intel (silently skipped if DB not populated)
  const targetName = targetContext?.config?.target_name || null;
  const brief = buildIntelligenceBrief(args.asset, targetName);
  if (brief) {
    sections.push(`\n# INTELLIGENCE BRIEF\n\n${brief}\n`);
  }

  return sections.filter(Boolean).join("\n");
}

function composeTriagerPrompt(args) {
  if (!args.asset) {
    throw new Error("Triager prompt requires --asset.");
  }

  const sections = [
    readModule("shared/core.md"),
    readModule("shared/triager_base.md"),
    readModule(`triager/calibration/${args.asset}.md`)
  ];

  const targetContext = resolveTargetContext(args.target);
  if (targetContext) {
    sections.push(`\n\n# TARGET CONFIG\n\n${JSON.stringify(targetContext.config, null, 2)}`);
    if (targetContext.claudeMd) {
      sections.push(`\n\n# TARGET NOTES (CLAUDE.md)\n\n${targetContext.claudeMd}`);
    }
  }

  sections.push(`

# EXECUTION CONTEXT

- role: triager
- asset: ${args.asset}
- target: ${args.target || "(not provided)"}

Read:
- findings/confirmed/report_bundle.json

Produce:
- findings/triage_result.json
- findings/h1_submission_ready/*.md
`);

  return sections.filter(Boolean).join("\n");
}

function main() {
  const args = parseArgs(process.argv);
  if (!args.role || !["researcher", "triager"].includes(args.role)) {
    throw new Error(
      "Usage: node scripts/compose-agent-prompt.js <researcher|triager> [--asset <type>] [--mode <whitebox|blackbox>] [--target <target>] [--vuln a,b] [--bypass a,b]"
    );
  }

  const prompt =
    args.role === "researcher" ? composeResearcherPrompt(args) : composeTriagerPrompt(args);
  process.stdout.write(prompt);
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
