#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const { openDatabase, resolveGlobalDatabasePath, replaceSkills } = require("./lib/db");
const { callLLMJson } = require("./lib/llm");

const BATCH_SIZE = 30;
const MIN_SUMMARY_LEN = 80;

function makeSkillId(sourceKey, vulnClass, title) {
  return "SK-" + crypto
    .createHash("sha1")
    .update(`${sourceKey}|${vulnClass}|${title}`)
    .digest("hex")
    .slice(0, 12);
}

const EXTRACTION_PROMPT = (reports) => `You are an expert security researcher analyzing HackerOne disclosed vulnerability reports.

For each report with sufficient technical detail, extract a reusable "skill" — a concrete, reproducible technique another researcher could apply.

Rules:
- Only extract skills from reports with meaningful technical content.
- Focus on the exact attack vector, what makes it work, and any non-obvious insight.
- "insight" = the non-obvious part that makes this exploit work (the hacker moment).
- vuln_class must be one of: xss, sqli, ssrf, xxe, idor, auth_bypass, privilege_escalation, rce, open_redirect, csrf, postmessage, prototype_pollution, race_condition, business_logic, info_disclosure, data_leak, deep_link_injection, supply_chain, deserialization, other
- asset_type must be one of: webapp, chromeext, mobileapp, executable

Reports:
${reports.map((r, i) =>
  `[${i + 1}] key:${r.disclosed_key} program:${r.program_handle || "?"} severity:${r.severity_rating || "?"} weakness:${r.weakness || "?"}\nTitle: ${r.title}\nSummary: ${r.hacktivity_summary}`
).join("\n\n")}

Respond with a JSON object with one key "skills" containing an array of skill objects (empty array if nothing is extractable):
{
  "skills": [
    {
      "title": "short descriptive title",
      "technique": "detailed explanation of the attack (2-5 sentences, specific enough to replicate)",
      "chain_steps": ["step 1", "step 2"],
      "insight": "the non-obvious part",
      "vuln_class": "...",
      "asset_type": "...",
      "program_handle": "from source report",
      "severity_achieved": "Critical|High|Medium|Low",
      "source_report_key": "the disclosed_key of the source report",
      "bypass_of": null
    }
  ]
}`;

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const forceAll = args.includes("--force");

  const db = openDatabase(resolveGlobalDatabasePath());

  // Collect already-processed source report keys for incremental processing
  const processed = new Set();
  if (!forceAll) {
    const rows = db.prepare("SELECT source_reports_json FROM skill_library").all();
    for (const row of rows) {
      for (const key of JSON.parse(row.source_reports_json || "[]")) {
        processed.add(key);
      }
    }
  }

  const reports = db.prepare(`
    SELECT disclosed_key, program_handle, title, severity_rating, weakness, hacktivity_summary
    FROM disclosed_reports
    WHERE hacktivity_summary IS NOT NULL
      AND length(hacktivity_summary) >= ${MIN_SUMMARY_LEN}
    ORDER BY disclosed_at DESC
  `).all().filter((r) => !processed.has(r.disclosed_key));

  process.stdout.write(`Unprocessed reports with sufficient summaries: ${reports.length}\n`);
  if (reports.length === 0) {
    process.stdout.write("Nothing to process. Run h1:bootstrap + calibration:sync first.\n");
    db.close();
    return;
  }

  let totalSkills = 0;
  const batches = Math.ceil(reports.length / BATCH_SIZE);

  for (let i = 0; i < reports.length; i += BATCH_SIZE) {
    const batch = reports.slice(i, i + BATCH_SIZE);
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    process.stdout.write(`Batch ${batchNum}/${batches} (${batch.length} reports)... `);

    try {
      const result = await callLLMJson(EXTRACTION_PROMPT(batch));
      const rawSkills = Array.isArray(result.skills) ? result.skills : [];
      const now = new Date().toISOString();
      const skills = rawSkills
        .filter((s) => s.title && s.technique && s.vuln_class && s.asset_type)
        .map((s) => ({
          ...s,
          skill_id: makeSkillId(s.source_report_key || batch[0].disclosed_key, s.vuln_class, s.title),
          source_reports: [s.source_report_key].filter(Boolean),
          created_at: now,
          manual: 0
        }));

      if (!dryRun && skills.length > 0) {
        replaceSkills(db, skills);
      }
      totalSkills += skills.length;
      process.stdout.write(`${skills.length} skills${dryRun ? " (dry-run)" : ""}.\n`);
    } catch (e) {
      process.stdout.write(`FAILED: ${e.message}\n`);
    }
  }

  db.close();
  process.stdout.write(`Done. Total skills extracted: ${totalSkills}\n`);
}

main().catch((e) => { process.stderr.write(`${e.stack}\n`); process.exit(1); });
