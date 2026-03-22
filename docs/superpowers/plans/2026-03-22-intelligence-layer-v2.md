# Intelligence Layer v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the researcher a persistent, auto-growing intelligence layer: distilled hacker skills from H1 disclosed reports + CVE lookup with variant-hunting analysis, all surfaced in Phase 0 before the researcher touches the target. A second parallel researcher (different model) then cross-validates findings and adds creative attack angle diversity.

**Architecture:**
- **Offline:** `extract-skills.js` + `sync-cve-intel.js` populate `skill_library` and `cve_intel` DB tables using free LLMs (Gemini 2.5 Flash → OpenRouter fallback chain).
- **Online:** researcher Phase 0 queries both tables via new CLI tools; EXECUTION CONTEXT receives a pre-built intelligence brief.
- **Dual-researcher:** pipeline spawns two researcher passes (Claude Sonnet + GPT-4.5 via OpenRouter) that share the same `report_bundle.json`, deduplicating findings by `affected_component` before triage.
- **Feedback loop:** researcher-extracted skills are persisted back to `skill_library` after each session.

**Tech Stack:** Node.js, `node:sqlite` (DatabaseSync — synchronous throughout), NVD REST API v2 (no key required), Exploit-DB JSON endpoint, OpenRouter API (`OPENROUTER_API_KEY` env var — new), ccw cli (Gemini already configured), existing `detect-assets.js`.

**Environment variables (new):**
- `OPENROUTER_API_KEY` — required for OpenRouter fallback in LLM calls and for GPT-4.5 dual-researcher. Set in `.env` or shell profile.

---

## Scope Map

```
subsystem A — Skill Library
  scripts/lib/db.js                    ADD: skill_library table, replaceSkills, querySkills
  scripts/extract-skills.js            NEW: batch LLM skill extraction from disclosed_reports
  scripts/query-skills.js              NEW: CLI query for researcher + humans
  scripts/lib/llm.js                   NEW: free-model sync+async fallback chain

subsystem B — CVE Intel
  scripts/lib/db.js                    ADD: cve_intel table, replaceCveIntel, queryCveIntel
  scripts/lib/nvd.js                   NEW: NVD REST API v2 client
  scripts/lib/exploit-db.js            NEW: Exploit-DB CVE search
  scripts/sync-cve-intel.js            NEW: NVD + Exploit-DB + LLM patch analysis
  scripts/query-cve-intel.js           NEW: CLI query for researcher

subsystem C — Researcher Integration
  .claude/commands/shared/core.md      MODIFY: document new tools in CALIBRATION DATASET
  .claude/commands/shared/researcher_wb.md  MODIFY: Phase 0 steps 0.5–0.8
  scripts/compose-agent-prompt.js      MODIFY: inject intelligence brief in EXECUTION CONTEXT
  scripts/lib/contracts.js             MODIFY: re-export new db.js functions + persistExtractedSkills
  scripts/run-pipeline.js              MODIFY: auto cve:sync + dual-researcher pass + skill persist

subsystem D — Dual Researcher
  scripts/lib/llm.js                   ADD: callGptResearcher() for GPT-4.5 via OpenRouter
  scripts/run-pipeline.js              MODIFY: second researcher pass + finding merge

package.json                           ADD: 4 new npm scripts
.env.example                           ADD: OPENROUTER_API_KEY documentation
```

---

## Task 1: `skill_library` table + CRUD in `db.js`

**Files:**
- Modify: `scripts/lib/db.js`

- [ ] **Step 1: Add `skill_library` CREATE TABLE inside `initDatabase()`**

In `scripts/lib/db.js`, inside the backtick string passed to `db.exec()` in `initDatabase()`, add after the `report_behaviors` table block:

```sql
CREATE TABLE IF NOT EXISTS skill_library (
  skill_id TEXT PRIMARY KEY,
  asset_type TEXT NOT NULL,
  vuln_class TEXT NOT NULL,
  program_handle TEXT,
  title TEXT NOT NULL,
  technique TEXT NOT NULL,
  chain_steps_json TEXT NOT NULL DEFAULT '[]',
  insight TEXT,
  bypass_of TEXT,
  source_reports_json TEXT NOT NULL DEFAULT '[]',
  severity_achieved TEXT,
  confirmed_programs_json TEXT NOT NULL DEFAULT '[]',
  manual INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

- [ ] **Step 2: Add `replaceSkills(db, skills)` — follows existing upsert pattern**

Add after `replaceReportBehaviors`:

```javascript
function replaceSkills(db, skills) {
  const upsert = db.prepare(`
    INSERT INTO skill_library (
      skill_id, asset_type, vuln_class, program_handle, title, technique,
      chain_steps_json, insight, bypass_of, source_reports_json,
      severity_achieved, confirmed_programs_json, manual, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(skill_id) DO UPDATE SET
      title = excluded.title,
      technique = excluded.technique,
      chain_steps_json = excluded.chain_steps_json,
      insight = excluded.insight,
      bypass_of = excluded.bypass_of,
      source_reports_json = excluded.source_reports_json,
      severity_achieved = excluded.severity_achieved,
      confirmed_programs_json = excluded.confirmed_programs_json,
      updated_at = excluded.updated_at
  `);
  const now = new Date().toISOString();
  db.exec("BEGIN");
  try {
    for (const s of skills) {
      upsert.run(
        s.skill_id, s.asset_type, s.vuln_class, s.program_handle || null,
        s.title, s.technique,
        JSON.stringify(s.chain_steps || []),
        s.insight || null, s.bypass_of || null,
        JSON.stringify(s.source_reports || []),
        s.severity_achieved || null,
        JSON.stringify(s.confirmed_programs || []),
        s.manual ? 1 : 0,
        s.created_at || now, now
      );
    }
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}
```

- [ ] **Step 3: Add `querySkills(db, opts)` — program-specific skills ranked first**

```javascript
function querySkills(db, { asset_type, program_handle, vuln_class, limit = 20 } = {}) {
  const conditions = [];
  const params = [];
  if (asset_type) { conditions.push("asset_type = ?"); params.push(asset_type); }
  if (program_handle) {
    conditions.push("(program_handle = ? OR program_handle IS NULL)");
    params.push(program_handle);
  }
  if (vuln_class) { conditions.push("vuln_class = ?"); params.push(vuln_class); }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const rows = db.prepare(`
    SELECT * FROM skill_library ${where}
    ORDER BY CASE WHEN program_handle IS NOT NULL THEN 0 ELSE 1 END,
             manual DESC, created_at DESC
    LIMIT ?
  `).all(...params, limit);
  return rows.map((r) => ({
    ...r,
    chain_steps: JSON.parse(r.chain_steps_json || "[]"),
    source_reports: JSON.parse(r.source_reports_json || "[]"),
    confirmed_programs: JSON.parse(r.confirmed_programs_json || "[]")
  }));
}
```

- [ ] **Step 4: Export `replaceSkills` and `querySkills` from `module.exports`**

- [ ] **Step 5: Run tests — must still pass**

```bash
node --test --test-isolation=none tests/contracts.test.js
```
Expected: 18 pass, 0 fail.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/db.js
git commit -m "feat(db): add skill_library table + replaceSkills/querySkills"
```

---

## Task 2: `cve_intel` table + CRUD in `db.js`

**Files:**
- Modify: `scripts/lib/db.js`

- [ ] **Step 1: Add `cve_intel` CREATE TABLE in `initDatabase()`**

After `skill_library`, add:

```sql
CREATE TABLE IF NOT EXISTS cve_intel (
  cve_id TEXT NOT NULL,
  target_ref TEXT NOT NULL,
  description TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  affected_versions_json TEXT NOT NULL DEFAULT '[]',
  cwe_id TEXT,
  exploitdb_id TEXT,
  poc_urls_json TEXT NOT NULL DEFAULT '[]',
  patch_commit TEXT,
  patch_diff_url TEXT,
  patch_analysis TEXT,
  variant_hints TEXT,
  published_date TEXT,
  synced_at TEXT NOT NULL,
  PRIMARY KEY (cve_id, target_ref)
);
```

- [ ] **Step 2: Add `replaceCveIntel(db, targetRef, cves)`**

```javascript
function replaceCveIntel(db, targetRef, cves) {
  const upsert = db.prepare(`
    INSERT INTO cve_intel (
      cve_id, target_ref, description, cvss_score, cvss_vector,
      affected_versions_json, cwe_id, exploitdb_id, poc_urls_json,
      patch_commit, patch_diff_url, patch_analysis, variant_hints,
      published_date, synced_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(cve_id, target_ref) DO UPDATE SET
      description = excluded.description,
      cvss_score = excluded.cvss_score,
      cvss_vector = excluded.cvss_vector,
      affected_versions_json = excluded.affected_versions_json,
      cwe_id = excluded.cwe_id,
      exploitdb_id = excluded.exploitdb_id,
      poc_urls_json = excluded.poc_urls_json,
      patch_commit = excluded.patch_commit,
      patch_diff_url = excluded.patch_diff_url,
      patch_analysis = excluded.patch_analysis,
      variant_hints = excluded.variant_hints,
      published_date = excluded.published_date,
      synced_at = excluded.synced_at
  `);
  const now = new Date().toISOString();
  db.exec("BEGIN");
  try {
    for (const cve of cves) {
      upsert.run(
        cve.cve_id, targetRef,
        cve.description || null, cve.cvss_score || null, cve.cvss_vector || null,
        JSON.stringify(cve.affected_versions || []),
        cve.cwe_id || null, cve.exploitdb_id || null,
        JSON.stringify(cve.poc_urls || []),
        cve.patch_commit || null, cve.patch_diff_url || null,
        cve.patch_analysis || null, cve.variant_hints || null,
        cve.published_date || null, now
      );
    }
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}
```

- [ ] **Step 3: Add `queryCveIntel(db, targetRef, opts)`**

```javascript
function queryCveIntel(db, targetRef, { limit = 50 } = {}) {
  // NULLS LAST is SQLite 3.30.0+ (Node 18+ ships a newer SQLite — safe)
  const rows = db.prepare(`
    SELECT * FROM cve_intel
    WHERE target_ref = ?
    ORDER BY cvss_score DESC NULLS LAST, published_date DESC
    LIMIT ?
  `).all(targetRef, limit);
  return rows.map((r) => ({
    ...r,
    affected_versions: JSON.parse(r.affected_versions_json || "[]"),
    poc_urls: JSON.parse(r.poc_urls_json || "[]")
  }));
}
```

- [ ] **Step 4: Export `replaceCveIntel` and `queryCveIntel` from `module.exports`**

- [ ] **Step 5: Run tests**

```bash
node --test --test-isolation=none tests/contracts.test.js
```
Expected: 18 pass.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/db.js
git commit -m "feat(db): add cve_intel table + replaceCveIntel/queryCveIntel"
```

---

## Task 3: Update `contracts.js` barrel re-exports

**Files:**
- Modify: `scripts/lib/contracts.js`

`contracts.js` is the single import point for `run-pipeline.js` and `compose-agent-prompt.js`. All new DB functions must be re-exported here.

- [ ] **Step 1: Add new functions to the destructured `require("./db")` at the top of `contracts.js`**

Find the existing line:
```javascript
const {
  openDatabase,
  resolveGlobalDatabasePath,
  // ...other existing exports
} = require("./db");
```

Add: `querySkills`, `queryCveIntel`, `replaceSkills`, `replaceCveIntel`.

- [ ] **Step 2: Add `persistExtractedSkills(db, bundle, targetRef)` function**

Note: receives `db` as parameter (caller manages the handle — no inline require).

```javascript
function persistExtractedSkills(db, bundle, targetRef) {
  const now = new Date().toISOString();
  const skills = (bundle.findings || [])
    .map((f) => f.extracted_skill)
    .filter(Boolean)
    .map((s, i) => ({
      ...s,
      skill_id: s.skill_id || `SK-researcher-${targetRef}-${now}-${i}`,
      program_handle: s.program_handle || targetRef,
      created_at: now,
      manual: 0
    }));
  if (skills.length === 0) return 0;
  replaceSkills(db, skills);
  return skills.length;
}
```

- [ ] **Step 3: Add all new functions to `module.exports` of `contracts.js`**

Add: `querySkills`, `queryCveIntel`, `replaceSkills`, `replaceCveIntel`, `persistExtractedSkills`.

- [ ] **Step 4: Run tests**

```bash
node --test --test-isolation=none tests/contracts.test.js
```
Expected: 18 pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/contracts.js
git commit -m "feat(contracts): re-export new db functions + persistExtractedSkills"
```

---

## Task 4: LLM fallback client (`scripts/lib/llm.js`)

**Files:**
- Create: `scripts/lib/llm.js`

**Design decisions from review:**
- `callGeminiCli` uses `spawnSync` with args array (NOT `execSync` with shell string) — avoids Windows quoting issues entirely.
- `extractJson` uses brace-matching, not regex stripping — handles multi-block responses.
- The function is intentionally **synchronous at the Gemini layer** and **async at the OpenRouter layer** — callers must `await callLLMJson(...)`.

- [ ] **Step 1: Create `scripts/lib/llm.js`**

```javascript
"use strict";

const { spawnSync } = require("node:child_process");

const OPENROUTER_MODELS = [
  "meta-llama/llama-4-scout:free",
  "qwen/qwen3-4b:free",
  "google/gemini-2.5-flash-preview:free"
];

/**
 * Call a free LLM with the given prompt, expecting a JSON object back.
 * Falls back: Gemini CLI (sync) → OpenRouter model chain (async).
 * Always returns a parsed JS object or throws if all attempts fail.
 *
 * NOTE: callGeminiCli is intentionally synchronous (uses spawnSync).
 * Do NOT convert it to async — the sync call is correct for script contexts.
 */
async function callLLMJson(prompt, { timeoutMs = 120000 } = {}) {
  const fullPrompt = `${prompt}\n\nRespond ONLY with a valid JSON object. No markdown, no explanation, no code fences.`;

  // 1. Try Gemini via ccw cli (sync — blocks event loop, fine for scripts)
  try {
    return callGeminiCli(fullPrompt, timeoutMs);
  } catch (e) {
    process.stderr.write(`[llm] Gemini CLI failed: ${e.message}\n`);
  }

  // 2. Try OpenRouter models in order
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    throw new Error(
      "All LLM backends failed. Gemini CLI unavailable and OPENROUTER_API_KEY is not set."
    );
  }
  for (const model of OPENROUTER_MODELS) {
    try {
      return await callOpenRouter(fullPrompt, model, apiKey, timeoutMs);
    } catch (e) {
      process.stderr.write(`[llm] OpenRouter ${model} failed: ${e.message}\n`);
    }
  }

  throw new Error("All LLM backends exhausted (Gemini + all OpenRouter models).");
}

/**
 * Synchronous Gemini call via ccw cli subprocess.
 * Uses spawnSync with args array — no shell, no quoting issues on Windows.
 * NOTE: intentionally synchronous. Do not convert to async.
 */
function callGeminiCli(prompt, timeoutMs) {
  const result = spawnSync(
    "ccw",
    ["cli", "-p", prompt, "--tool", "gemini", "--mode", "analysis"],
    { encoding: "utf8", timeout: timeoutMs, windowsHide: true }
  );
  if (result.status !== 0) {
    const errMsg = result.stderr || result.error?.message || `exit code ${result.status}`;
    throw new Error(`ccw cli failed: ${errMsg}`);
  }
  return extractJson(result.stdout || "");
}

async function callOpenRouter(prompt, model, apiKey, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/agentic-bugbounty",
        "X-Title": "Agentic BugBounty"
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.2,
        response_format: { type: "json_object" }
      }),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const data = await res.json();
    const content = data.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty response from OpenRouter");
    return extractJson(content);
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Extract the first complete JSON object or array from arbitrary text.
 * Brace-matches rather than regex-stripping — handles multi-block responses.
 */
function extractJson(text) {
  const openBrace = text.indexOf("{");
  const openBracket = text.indexOf("[");
  let start = -1;
  if (openBrace === -1 && openBracket === -1) {
    throw new Error("No JSON found in LLM response");
  } else if (openBrace === -1) {
    start = openBracket;
  } else if (openBracket === -1) {
    start = openBrace;
  } else {
    start = Math.min(openBrace, openBracket);
  }
  const opener = text[start];
  const closer = opener === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (escape) { escape = false; continue; }
    if (ch === "\\") { escape = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (ch === opener) depth++;
    else if (ch === closer) {
      depth--;
      if (depth === 0) return JSON.parse(text.slice(start, i + 1));
    }
  }
  throw new Error("Unterminated JSON in LLM response");
}

module.exports = { callLLMJson };
```

- [ ] **Step 2: Smoke-test (requires ccw cli or OPENROUTER_API_KEY)**

```bash
node -e "require('./scripts/lib/llm').callLLMJson('Return JSON: {\"ok\": true}').then(r => console.log(r))"
```
Expected: `{ ok: true }` printed. If Gemini CLI unavailable and no API key, error message is printed — that is correct behavior.

- [ ] **Step 3: Commit**

```bash
git add scripts/lib/llm.js
git commit -m "feat(llm): free-model fallback chain — spawnSync Gemini + OpenRouter REST"
```

---

## Task 5: Skill extraction script (`scripts/extract-skills.js`)

**Files:**
- Create: `scripts/extract-skills.js`

**Design:** Batch of 30 reports per LLM call. Skips reports with `hacktivity_summary` < 80 chars. Skill ID is a hash of `source_report_key + vuln_class + title` — deterministic, deduplication-safe.

- [ ] **Step 1: Create `scripts/extract-skills.js`**

```javascript
#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const { openDatabase, resolveGlobalDatabasePath, replaceSkills, querySkills } = require("./lib/db");
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

Respond with a JSON object containing one key "skills" with an array of skill objects (empty array if nothing is extractable):
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

  // Collect already-processed source report keys (for incremental processing)
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

  process.stdout.write(`Unprocessed reports: ${reports.length}\n`);
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
```

- [ ] **Step 2: Test dry-run**

```bash
node scripts/extract-skills.js --dry-run
```
Expected: prints report count and "Nothing to process" (if bootstrap hasn't run) or batch progress without DB writes.

- [ ] **Step 3: Commit**

```bash
git add scripts/extract-skills.js
git commit -m "feat: skill extraction — deterministic IDs, brace-match JSON, incremental"
```

---

## Task 6: `query-skills.js` CLI

**Files:**
- Create: `scripts/query-skills.js`

- [ ] **Step 1: Create `scripts/query-skills.js`**

```javascript
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
```

- [ ] **Step 2: Smoke-test**

```bash
node scripts/query-skills.js --asset chromeext --limit 5
```
Expected: "No skills found." message or skill list.

- [ ] **Step 3: Commit**

```bash
git add scripts/query-skills.js
git commit -m "feat: query-skills CLI tool"
```

---

## Task 7: NVD client (`scripts/lib/nvd.js`)

**Files:**
- Create: `scripts/lib/nvd.js`

- [ ] **Step 1: Create `scripts/lib/nvd.js`**

```javascript
"use strict";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RATE_DELAY_MS = 7000; // 5 req/30s limit without key → 1 req/7s

async function searchCves(keywords, { resultsPerPage = 20 } = {}) {
  const url = `${NVD_BASE}?keywordSearch=${encodeURIComponent(keywords)}&resultsPerPage=${resultsPerPage}`;
  const res = await fetch(url, {
    headers: { "Accept": "application/json", "User-Agent": "agentic-bugbounty/1.0" }
  });
  if (!res.ok) throw new Error(`NVD API error: HTTP ${res.status}`);
  const data = await res.json();
  return (data.vulnerabilities || []).map(normalizeCve);
}

function normalizeCve(item) {
  const cve = item.cve;
  const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || null;
  const cweId = cve.weaknesses?.[0]?.description?.[0]?.value || null;
  const desc = cve.descriptions?.find((d) => d.lang === "en")?.value || "";
  const versions = [];
  for (const config of (cve.configurations || [])) {
    for (const node of (config.nodes || [])) {
      for (const match of (node.cpeMatch || [])) {
        if (match.versionStartIncluding || match.versionEndExcluding) {
          versions.push({
            cpe: match.criteria,
            from: match.versionStartIncluding || null,
            to: match.versionEndExcluding || null
          });
        }
      }
    }
  }
  return {
    cve_id: cve.id,
    description: desc,
    cvss_score: metrics?.cvssData?.baseScore || null,
    cvss_vector: metrics?.cvssData?.vectorString || null,
    cwe_id: cweId,
    affected_versions: versions,
    published_date: cve.published || null
  };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { searchCves, RATE_DELAY_MS, delay };
```

- [ ] **Step 2: Commit**

```bash
git add scripts/lib/nvd.js
git commit -m "feat(nvd): NVD REST API v2 client with rate-limit delay"
```

---

## Task 8: Exploit-DB client (`scripts/lib/exploit-db.js`)

**Files:**
- Create: `scripts/lib/exploit-db.js`

- [ ] **Step 1: Create `scripts/lib/exploit-db.js`**

```javascript
"use strict";

/**
 * Search Exploit-DB for exploits matching a CVE ID.
 * Uses the AJAX JSON endpoint — returns [] on any error (non-fatal).
 */
async function searchExploitDb(cveId) {
  const url = `https://www.exploit-db.com/search?cve=${encodeURIComponent(cveId)}&draw=1&start=0&length=10`;
  try {
    const res = await fetch(url, {
      headers: {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "agentic-bugbounty/1.0"
      }
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.data || []).map((r) => ({
      exploitdb_id: String(r.id),
      title: r.description || "",
      url: `https://www.exploit-db.com/exploits/${r.id}`,
      type: r.type || null,
      date: r.date_published || null
    }));
  } catch {
    return [];
  }
}

module.exports = { searchExploitDb };
```

- [ ] **Step 2: Commit**

```bash
git add scripts/lib/exploit-db.js
git commit -m "feat(exploitdb): Exploit-DB CVE search client"
```

---

## Task 9: CVE sync script (`scripts/sync-cve-intel.js`)

**Files:**
- Create: `scripts/sync-cve-intel.js`

- [ ] **Step 1: Create `scripts/sync-cve-intel.js`**

```javascript
#!/usr/bin/env node
"use strict";

const path = require("node:path");
const fs = require("node:fs");
const { openDatabase, resolveGlobalDatabasePath, replaceCveIntel, queryCveIntel } = require("./lib/db");
const { searchCves, RATE_DELAY_MS, delay } = require("./lib/nvd");
const { searchExploitDb } = require("./lib/exploit-db");
const { callLLMJson } = require("./lib/llm");
const { readJson, resolveTargetConfigPath } = require("./lib/contracts");

const PATCH_ANALYSIS_PROMPT = (cve) => `You are a security researcher doing variant hunting on a patched CVE.

CVE: ${cve.cve_id}
CVSS: ${cve.cvss_score || "?"} (${cve.cvss_vector || "?"})
CWE: ${cve.cwe_id || "?"}
Description: ${cve.description}

Tasks:
1. Identify the root cause from the description.
2. Analyze what the patch likely changed (even without seeing the diff).
3. Suggest specific patterns/functions to search in a similar codebase for variants.
4. Rate bypass likelihood: High/Medium/Low with brief reasoning.

Respond with JSON:
{
  "patch_analysis": "2-3 sentences on what the patch fixed and what it may have missed",
  "variant_hints": "specific functions/patterns to grep for in the target codebase",
  "bypass_likelihood": "High|Medium|Low",
  "bypass_reasoning": "one sentence"
}`;

function extractKeywords(targetDir, config) {
  const keywords = [config.target_name].filter(Boolean);
  const srcPath = config.source_path ? path.resolve(targetDir, config.source_path) : null;
  if (!srcPath) return keywords;

  // Chrome extension manifest name
  const manifestPath = path.join(srcPath, "manifest.json");
  if (fs.existsSync(manifestPath)) {
    try {
      const m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      if (m.name && !m.name.startsWith("__")) keywords.push(m.name);
    } catch { /**/ }
  }

  // Node.js package name
  const pkgPath = path.join(srcPath, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      if (pkg.name) keywords.push(pkg.name);
    } catch { /**/ }
  }

  // APK filename → strip version suffix
  if (/\.(apk|apkx)$/i.test(srcPath)) {
    const appName = path.basename(srcPath).replace(/[_\-][\d.]+\.(?:apk|apkx)$/i, "").trim();
    if (appName) keywords.push(appName);
  }

  return [...new Set(keywords)];
}

async function main() {
  const args = process.argv.slice(2);

  // Safe --target parsing (guard against args.indexOf returning -1)
  const targetIdx = args.indexOf("--target");
  const targetArg = targetIdx >= 0 ? args[targetIdx + 1] : null;
  const noAnalysis = args.includes("--no-analysis");
  const maxAgeDays = parseInt(args[args.indexOf("--max-age-days") + 1] || "1", 10);

  if (!targetArg) {
    process.stderr.write("Usage: node scripts/sync-cve-intel.js --target <name> [--no-analysis] [--max-age-days N]\n");
    process.exit(1);
  }

  const configPath = resolveTargetConfigPath(targetArg);
  const config = readJson(configPath);
  const targetDir = path.dirname(configPath);
  const keywords = extractKeywords(targetDir, config);

  // Staleness check: skip if already synced within maxAgeDays
  const db = openDatabase(resolveGlobalDatabasePath());
  const existing = queryCveIntel(db, targetArg, { limit: 1 });
  if (existing.length > 0) {
    const lastSync = new Date(existing[0].synced_at);
    const ageMs = Date.now() - lastSync.getTime();
    if (ageMs < maxAgeDays * 24 * 60 * 60 * 1000) {
      process.stdout.write(`CVE intel for "${targetArg}" is fresh (synced ${lastSync.toISOString()}). Skipping.\n`);
      db.close();
      return;
    }
  }

  process.stdout.write(`Target: ${targetArg} | Keywords: ${keywords.join(", ")}\n`);
  const allCves = [];

  for (let ki = 0; ki < keywords.length; ki++) {
    const kw = keywords[ki];
    process.stdout.write(`Searching NVD for "${kw}"... `);
    try {
      const cves = await searchCves(kw);
      process.stdout.write(`${cves.length} CVEs.\n`);
      allCves.push(...cves);
    } catch (e) {
      process.stdout.write(`FAILED: ${e.message}\n`);
    }
    if (ki < keywords.length - 1) await delay(RATE_DELAY_MS);
  }

  // Deduplicate
  const seen = new Set();
  const unique = allCves.filter((c) => { if (seen.has(c.cve_id)) return false; seen.add(c.cve_id); return true; });
  process.stdout.write(`Unique CVEs: ${unique.length}\n`);

  // Exploit-DB enrichment
  for (const cve of unique) {
    const exploits = await searchExploitDb(cve.cve_id);
    if (exploits.length > 0) {
      cve.exploitdb_id = exploits[0].exploitdb_id;
      cve.poc_urls = exploits.map((e) => e.url);
      process.stdout.write(`  ${cve.cve_id}: ${exploits.length} PoC(s)\n`);
    }
    await delay(500);
  }

  // LLM patch analysis
  if (!noAnalysis && unique.length > 0) {
    process.stdout.write(`\nLLM patch analysis on ${unique.length} CVEs...\n`);
    for (const cve of unique) {
      process.stdout.write(`  ${cve.cve_id}... `);
      try {
        const r = await callLLMJson(PATCH_ANALYSIS_PROMPT(cve));
        cve.patch_analysis = r.patch_analysis || null;
        const bypassLine = r.bypass_reasoning
          ? `Bypass likelihood: ${r.bypass_likelihood} — ${r.bypass_reasoning}`
          : null;
        cve.variant_hints = [r.variant_hints, bypassLine].filter(Boolean).join("\n");
        process.stdout.write("done.\n");
      } catch (e) {
        process.stdout.write(`FAILED: ${e.message}\n`);
      }
    }
  }

  replaceCveIntel(db, targetArg, unique);
  db.close();
  process.stdout.write(`\nSaved ${unique.length} CVEs for "${targetArg}".\n`);
}

main().catch((e) => { process.stderr.write(`${e.stack}\n`); process.exit(1); });
```

- [ ] **Step 2: Test with no-analysis flag**

```bash
node scripts/sync-cve-intel.js --target okta --no-analysis
```
Expected: prints CVE count per keyword, saves to DB. On re-run within 24h, prints "fresh — skipping".

- [ ] **Step 3: Commit**

```bash
git add scripts/sync-cve-intel.js
git commit -m "feat: CVE sync — NVD + Exploit-DB + LLM analysis + staleness cache"
```

---

## Task 10: `query-cve-intel.js` CLI

**Files:**
- Create: `scripts/query-cve-intel.js`

- [ ] **Step 1: Create `scripts/query-cve-intel.js`**

```javascript
#!/usr/bin/env node
"use strict";

const { openDatabase, resolveGlobalDatabasePath, queryCveIntel } = require("./lib/db");

function parseArgs() {
  const args = process.argv.slice(2);
  const out = { target: null, limit: 20, json: false, minCvss: 0 };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--target") out.target = args[++i];
    else if (args[i] === "--limit") out.limit = parseInt(args[++i], 10);
    else if (args[i] === "--min-cvss") out.minCvss = parseFloat(args[++i]);
    else if (args[i] === "--json") out.json = true;
  }
  return out;
}

function formatCves(cves) {
  if (cves.length === 0) return "No CVEs found. Run: npm run cve:sync -- --target <name>\n";
  return cves.map((c, i) => {
    const score = c.cvss_score ? `CVSS ${c.cvss_score}` : "CVSS ?";
    const poc = c.poc_urls.length > 0 ? `\n  PoC: ${c.poc_urls[0]}` : "";
    const analysis = c.patch_analysis ? `\n  Patch: ${c.patch_analysis}` : "";
    const hints = c.variant_hints ? `\n  Variants: ${c.variant_hints}` : "";
    return `[${i + 1}] ${c.cve_id} (${score}) — ${(c.description || "").slice(0, 120)}${poc}${analysis}${hints}`;
  }).join("\n\n") + "\n";
}

function main() {
  const args = parseArgs();
  if (!args.target) {
    process.stderr.write("Usage: node scripts/query-cve-intel.js --target <name> [--min-cvss 7.0] [--json]\n");
    process.exit(1);
  }
  const db = openDatabase(resolveGlobalDatabasePath());
  let cves = queryCveIntel(db, args.target, { limit: args.limit });
  db.close();
  if (args.minCvss > 0) cves = cves.filter((c) => (c.cvss_score || 0) >= args.minCvss);
  if (args.json) {
    process.stdout.write(JSON.stringify({ cves }, null, 2) + "\n");
  } else {
    process.stdout.write(formatCves(cves));
  }
}

main();
```

- [ ] **Step 2: Smoke-test**

```bash
node scripts/query-cve-intel.js --target okta --min-cvss 7.0
```
Expected: CVE list or "No CVEs found." message.

- [ ] **Step 3: Commit**

```bash
git add scripts/query-cve-intel.js
git commit -m "feat: query-cve-intel CLI tool"
```

---

## Task 11: npm scripts + `.env.example`

**Files:**
- Modify: `package.json`
- Create or modify: `.env.example`

- [ ] **Step 1: Add npm scripts to `package.json`**

```json
"calibration:extract-skills": "node scripts/extract-skills.js",
"cve:sync": "node scripts/sync-cve-intel.js",
"cve:query": "node scripts/query-cve-intel.js",
"skills:query": "node scripts/query-skills.js"
```

- [ ] **Step 2: Add `OPENROUTER_API_KEY` to `.env.example`**

If `.env.example` doesn't exist, create it. Add:

```bash
# OpenRouter API key — used for LLM fallback chain in skill extraction and CVE analysis
# Free tier supports Llama 4 Scout, Qwen3, Gemini 2.5 Flash (all free models)
# Get key at: https://openrouter.ai/keys
OPENROUTER_API_KEY=your_key_here
```

- [ ] **Step 3: Run tests + verify new scripts exist**

```bash
node --test --test-isolation=none tests/contracts.test.js
node scripts/query-skills.js 2>&1 | head -3
node scripts/query-cve-intel.js 2>&1 | head -3
```

- [ ] **Step 4: Commit**

```bash
git add package.json .env.example
git commit -m "chore: npm scripts for skill library + CVE intel + env var docs"
```

---

## Task 12: `compose-agent-prompt.js` — intelligence brief injection

**Files:**
- Modify: `scripts/compose-agent-prompt.js`

**Design:** Uses functions already imported via `require("./lib/contracts")` at module top — no inline requires. Opens global DB with `openDatabase` inside a `try/finally` to guarantee `db.close()`. The function stays fully synchronous (no async introduced).

- [ ] **Step 1: Add `querySkills`, `queryCveIntel`, `openDatabase`, `resolveGlobalDatabasePath` to the top-level destructured require in `compose-agent-prompt.js`**

Find:
```javascript
const {
  buildResearchBrief,
  deriveProgramHandle,
  loadDisclosedDataset,
  loadProgramIntel,
  readJson,
  resolveTargetConfigPath
} = require("./lib/contracts");
```

Replace with (adding 4 new imports):
```javascript
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
```

- [ ] **Step 2: Add `buildIntelligenceBrief(asset, targetName)` helper function**

Add before `composeResearcherPrompt`:

```javascript
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
    return null; // DB unavailable — silently skip
  } finally {
    if (db) db.close();
  }
}
```

- [ ] **Step 3: Inject the brief in the EXECUTION CONTEXT section**

Find the `sections.push` block containing `# EXECUTION CONTEXT` and add the brief after the existing fields:

```javascript
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

// Intelligence brief (from skill_library + cve_intel — may be empty if offline data not synced)
const targetName = targetCtx?.config?.target_name || null;
const brief = buildIntelligenceBrief(args.asset, targetName);
if (brief) {
  sections.push(`\n# INTELLIGENCE BRIEF\n\n${brief}\n`);
}
```

- [ ] **Step 4: Run tests**

```bash
node --test --test-isolation=none tests/contracts.test.js
```
Expected: 18 pass.

- [ ] **Step 5: Verify compose works standalone**

```bash
node scripts/compose-agent-prompt.js researcher --asset chromeext --mode whitebox 2>&1 | tail -20
```
Expected: outputs EXECUTION CONTEXT section + optionally INTELLIGENCE BRIEF section.

- [ ] **Step 6: Commit**

```bash
git add scripts/compose-agent-prompt.js
git commit -m "feat(prompt): inject intelligence brief (skills + CVE) into researcher EXECUTION CONTEXT"
```

---

## Task 13: Researcher Phase 0 documentation update

**Files:**
- Modify: `.claude/commands/shared/researcher_wb.md`
- Modify: `.claude/commands/shared/core.md`

- [ ] **Step 1: Add Phase 0 steps 0.5–0.8 to `researcher_wb.md`**

After the existing step 0.4 block, add:

```markdown
0.5 Query the skill library for this asset type + target:
    ```bash
    node scripts/query-skills.js --asset [asset_type] --program [program_handle] --limit 10
    node scripts/query-skills.js --asset [asset_type] --limit 15
    ```
    Read each skill. Prioritize ones with:
      - `bypass_of` set (patch bypass — apply immediately to version check)
      - `chain_steps` with 3+ steps (complex chains automated scanners miss)
      - `insight` field (the non-obvious part — use this as your first hypothesis)

0.6 Query CVE intel for the target:
    ```bash
    node scripts/query-cve-intel.js --target [target_name] --min-cvss 6.0
    ```
    For each CVE:
      - Check if the target version falls in `affected_versions`
      - Read `variant_hints` — these are grep targets for your source analysis
      - High `bypass_likelihood` → add the bypass check to your explicit checklist

0.7 Build your pre-analysis checklist (in analysis notes, not in the bundle):
    ```
    PRE-ANALYSIS INTELLIGENCE
    Skills loaded: [N] skills | Top: [list titles]
    CVEs found: [N total, N high/critical]
    Variant hunting targets: [specific functions/patterns from variant_hints]
    Bypass candidates: [CVE IDs with High bypass_likelihood]
    Chain opportunities: [skill titles with 3+ chain_steps]
    ```

0.8 If you discover a new technique not in the skill library, add it to your finding:
    In the finding JSON, add an `extracted_skill` field alongside the finding fields:
    ```json
    "extracted_skill": {
      "title": "short title",
      "technique": "how it works (specific enough to replicate)",
      "chain_steps": ["step 1", "step 2"],
      "insight": "the non-obvious part",
      "vuln_class": "...",
      "asset_type": "...",
      "severity_achieved": "Critical|High|Medium|Low",
      "bypass_of": null
    }
    ```
    The pipeline will automatically persist this to the skill library after your session.
```

- [ ] **Step 2: Add Skill Library + CVE Intel to the CALIBRATION DATASET section in `core.md`**

Find the CALIBRATION DATASET section and append:

```markdown
### Skill Library
Query: `node scripts/query-skills.js --asset [type] --program [handle] --limit 15`
Contains: distilled hacker techniques from H1 disclosed reports. Fields: `title`, `technique`, `chain_steps`, `insight`, `bypass_of` (CVE being bypassed), `severity_achieved`.
Sync: `npm run calibration:extract-skills` (run after h1:bootstrap, processes all disclosed reports).

### CVE Intel
Query: `node scripts/query-cve-intel.js --target [name] --min-cvss 6.0`
Contains: NVD CVEs + Exploit-DB PoC links + LLM variant-hunting analysis. Fields: `cve_id`, `cvss_score`, `description`, `poc_urls`, `patch_analysis`, `variant_hints`.
Sync: `npm run cve:sync -- --target [name]` (run once per engagement, cached 24h).
```

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/shared/researcher_wb.md .claude/commands/shared/core.md
git commit -m "docs: researcher Phase 0 — skill library + CVE intel steps 0.5-0.8"
```

---

## Task 14: Auto CVE sync + skill persist in pipeline (`run-pipeline.js`)

**Files:**
- Modify: `scripts/run-pipeline.js`

- [ ] **Step 1: Add `syncCveIntelIfPossible(context, logPath)` helper**

Following the exact pattern of `syncBbscopeIfPossible` (non-fatal, logged):

```javascript
function syncCveIntelIfPossible(context, logPath) {
  if (!context.config || !context.targetRef) return;
  logEvent(logPath, "Syncing CVE intel (NVD + Exploit-DB + LLM analysis)");
  try {
    // sync-cve-intel.js has its own staleness check (default 24h) — won't repeat on resume
    runCommand("node", ["scripts/sync-cve-intel.js", "--target", context.targetRef]);
    logEvent(logPath, "CVE intel sync complete");
  } catch (error) {
    logEvent(logPath, `CVE intel sync failed (non-fatal): ${error.message}`);
  }
}
```

- [ ] **Step 2: Call it once per pipeline run (not per asset)**

Find where `syncBbscopeIfPossible` and `syncHackerOneIfPossible` are called. Add immediately after:

```javascript
syncCveIntelIfPossible(context, runLog);
```

- [ ] **Step 3: Add skill persistence after each researcher pass**

After the researcher phase completes and validation passes, add:

```javascript
// Persist any researcher-extracted skills back to skill_library
try {
  const { openDatabase, resolveGlobalDatabasePath, persistExtractedSkills } = require("./lib/contracts");
  const bundlePath = path.join(assetContext.findingsDir, "confirmed", "report_bundle.json");
  if (fs.existsSync(bundlePath)) {
    const bundle = readJson(bundlePath);
    const skillDb = openDatabase(resolveGlobalDatabasePath());
    try {
      const saved = persistExtractedSkills(skillDb, bundle, context.targetRef || "unknown");
      if (saved > 0) logEvent(runLog, `Persisted ${saved} researcher-extracted skills to skill_library`);
    } finally {
      skillDb.close();
    }
  }
} catch (e) {
  logEvent(runLog, `Skill persistence failed (non-fatal): ${e.message}`);
}
```

**Note:** `require("./lib/contracts")` is already at the top of run-pipeline.js. Move the destructuring there instead of inside the try block.

- [ ] **Step 4: Run tests**

```bash
node --test --test-isolation=none tests/contracts.test.js
```
Expected: 18 pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/run-pipeline.js
git commit -m "feat(pipeline): auto CVE sync + researcher skill persistence"
```

---

## Task 15: Dual Researcher — second model pass

**Files:**
- Modify: `scripts/lib/llm.js` — add `callResearcherModel(model, prompt)` for GPT-4.5 via OpenRouter
- Modify: `scripts/run-pipeline.js` — second researcher pass + finding merge

**Design:** The second researcher uses GPT-4.5 (`openai/gpt-4.5-preview` via OpenRouter). It receives the same target + the first researcher's findings as context ("what has already been found"). Findings are merged by `affected_component`: duplicate components are flagged for triager review, new components are added. This runs only if `OPENROUTER_API_KEY` is set.

- [ ] **Step 1: Add `callResearcherModel(prompt, model, apiKey)` to `scripts/lib/llm.js`**

```javascript
/**
 * Call a specific OpenRouter model for researcher use (not the free fallback chain).
 * Returns the raw text response — researcher outputs are markdown/JSON, not structured.
 */
async function callResearcherModel(prompt, { model = "openai/gpt-4.5-preview", timeoutMs = 300000 } = {}) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) throw new Error("OPENROUTER_API_KEY not set — cannot call secondary researcher model");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/agentic-bugbounty",
        "X-Title": "Agentic BugBounty Dual Researcher"
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.4
      }),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const data = await res.json();
    return data.choices?.[0]?.message?.content || "";
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

module.exports = { callLLMJson, callResearcherModel };
```

- [ ] **Step 2: Add `mergeResearcherFindings(primaryBundle, secondaryFindings)` in `run-pipeline.js`**

```javascript
function mergeResearcherFindings(primaryBundle, secondaryFindings) {
  const primaryComponents = new Set(
    (primaryBundle.findings || []).map((f) => f.affected_component)
  );
  const newFindings = secondaryFindings.filter(
    (f) => !primaryComponents.has(f.affected_component)
  );
  const duplicates = secondaryFindings.filter(
    (f) => primaryComponents.has(f.affected_component)
  );
  if (duplicates.length > 0) {
    logEvent(null, `Dual researcher: ${duplicates.length} overlapping components (good signal), ${newFindings.length} new components added`);
  }
  return {
    ...primaryBundle,
    findings: [...(primaryBundle.findings || []), ...newFindings],
    analysis_summary: {
      ...(primaryBundle.analysis_summary || {}),
      dual_researcher_new_findings: newFindings.length,
      dual_researcher_overlaps: duplicates.length
    }
  };
}
```

- [ ] **Step 3: Trigger second researcher pass in pipeline (after primary, before triage)**

After the primary researcher pass completes and the bundle is saved, add:

```javascript
// Dual researcher pass (only if OPENROUTER_API_KEY is set)
if (process.env.OPENROUTER_API_KEY) {
  logEvent(runLog, "Starting dual researcher pass (GPT-4.5 via OpenRouter)");
  printFlavour("researcher_start");
  try {
    // Build a context-aware prompt for the second model
    const existingBundle = readJson(path.join(assetContext.findingsDir, "confirmed", "report_bundle.json"));
    const foundComponents = (existingBundle.findings || []).map((f) => f.affected_component).join(", ");
    const dualPrompt = `/researcher --asset ${assetContext.asset} --mode ${assetContext.mode} ${assetContext.target}\n\n` +
      `DUAL RESEARCHER CONTEXT: A primary researcher (Claude Sonnet) has already analyzed this target and found issues in: ${foundComponents || "(none yet)"}.\n` +
      `Your role: explore with a DIFFERENT approach. Prioritize components NOT already found. ` +
      `Apply your own creative attack angles. All standard output format rules apply.\n\n` +
      (assetContext.source_name ? `SOURCE ASSET: ${assetContext.source_name}\n` : "") +
      pathHint;

    // The second researcher is a model invoked via OpenRouter — it writes to the same bundle
    // We save the current bundle first, invoke, then merge
    const preMergeBundle = readJson(path.join(assetContext.findingsDir, "confirmed", "report_bundle.json"));
    await invokeAgent("openrouter-researcher", "researcher", assetContext, args, dualPrompt, runLog);
    const postMergeBundle = readJson(path.join(assetContext.findingsDir, "confirmed", "report_bundle.json"));
    const merged = mergeResearcherFindings(preMergeBundle, postMergeBundle.findings || []);
    writeJson(path.join(assetContext.findingsDir, "confirmed", "report_bundle.json"), merged);
    logEvent(runLog, `Dual researcher complete. Merged bundle: ${merged.findings.length} findings`);
  } catch (e) {
    logEvent(runLog, `Dual researcher failed (non-fatal): ${e.message}`);
  }
}
```

**Note:** Invoking GPT-4.5 as a researcher requires the second agent to be wired into `invokeAgent`. The simplest implementation: add an `"openrouter-researcher"` CLI branch that sends the prompt to `callResearcherModel` and expects the model to output a JSON bundle (same format). The model is instructed to output the bundle directly. This is **complex to wire fully in one step** — defer to a follow-up task if time-constrained, and document this as `status: planned` in the overview doc.

- [ ] **Step 4: Run tests**

```bash
node --test --test-isolation=none tests/contracts.test.js
```
Expected: 18 pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/llm.js scripts/run-pipeline.js
git commit -m "feat: dual researcher — GPT-4.5 second pass + finding merge"
```

---

## Final Verification Checklist

- [ ] `node --test --test-isolation=none tests/contracts.test.js` → 18 pass
- [ ] `node scripts/query-skills.js --asset chromeext` → runs without error
- [ ] `node scripts/query-cve-intel.js --target okta` → runs without error
- [ ] `node scripts/extract-skills.js --dry-run` → runs without error
- [ ] `node scripts/sync-cve-intel.js --target okta --no-analysis` → fetches NVD CVEs
- [ ] `node scripts/compose-agent-prompt.js researcher --asset chromeext --mode whitebox` → shows EXECUTION CONTEXT + optional INTELLIGENCE BRIEF

---

## Delegation Strategy

| Work | Model |
|---|---|
| Batch skill extraction (30 reports/call) | Gemini 2.5 Flash (free, ccw cli) → OpenRouter fallback |
| CVE patch analysis (per CVE) | Same free chain |
| Researcher Phase 0 synthesis | Claude Sonnet 4.6 (online) |
| Variant hunting + creative analysis | Claude Sonnet 4.6 |
| Dual researcher second pass | GPT-4.5 via OpenRouter |
| All structured JSON processing | Free models |
