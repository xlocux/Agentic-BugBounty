"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  buildResearchBrief,
  deriveProgramHandle,
  initDatabase,
  loadDisclosedDataset,
  loadProgramIntel,
  openDatabase,
  readJson,
  readDisclosedDatasetFromDb,
  persistDisclosedDataset,
  persistProgramIntel,
  renderH1ReportMarkdown,
  resolveDatabasePath,
  resolveGlobalDatabasePath,
  triageBundle,
  validateBundle,
  validateTargetConfig,
  validateTriageResult,
  writeJson,
  writeProgramIntel
} = require("../scripts/lib/contracts");

function fixture(name) {
  return path.join(__dirname, "fixtures", name);
}

// ---------------------------------------------------------------------------
// Existing tests
// ---------------------------------------------------------------------------

test("validateBundle accepts the canonical valid fixture", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  assert.deepEqual(validateBundle(bundle), []);
});

test("validateBundle rejects malformed bundle data", () => {
  const bundle = readJson(fixture("report_bundle.invalid.json"));
  const errors = validateBundle(bundle);
  assert.ok(errors.length > 5);
  assert.match(errors.join("\n"), /meta\.generated_at/);
  assert.match(errors.join("\n"), /findings\[0\]\.report_id/);
});

test("validateTargetConfig accepts a valid machine-readable target", () => {
  const config = readJson(fixture("target.valid.json"));
  assert.deepEqual(validateTargetConfig(config), []);
});

test("validateTargetConfig rejects invalid target metadata", () => {
  const config = readJson(fixture("target.invalid.json"));
  const errors = validateTargetConfig(config);
  assert.ok(errors.length >= 4);
  assert.match(errors.join("\n"), /asset_type/);
  assert.match(errors.join("\n"), /allowed_modes/);
});

test("triageBundle transforms bundle findings into a valid TRIAGE_RESULT", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const triageResult = triageBundle(bundle);

  assert.equal(triageResult.meta.total_findings_received, 1);
  assert.equal(triageResult.results[0].triage_verdict, "TRIAGED");
  assert.deepEqual(validateTriageResult(triageResult, bundle), []);
});

test("renderH1ReportMarkdown produces a report-ready markdown body", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const triageResult = triageBundle(bundle);
  const finding = bundle.findings[0];
  const markdown = renderH1ReportMarkdown(finding, triageResult.results[0]);

  assert.match(markdown, /^# SQL Injection/);
  assert.match(markdown, /## Steps To Reproduce/);
  assert.match(markdown, /## Triage Summary/);
});

test("writeJson persists stable artifacts for regression fixtures", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bugbounty-"));
  const outPath = path.join(tmpDir, "triage_result.json");
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const triageResult = triageBundle(bundle);

  writeJson(outPath, triageResult);

  const reloaded = readJson(outPath);
  assert.equal(reloaded.results[0].report_id, "WEB-001");
});

// ---------------------------------------------------------------------------
// H1 universal rules
// ---------------------------------------------------------------------------

test("triageBundle marks self-XSS findings as NOT_APPLICABLE", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const selfXssBundle = {
    ...bundle,
    findings: [
      {
        ...bundle.findings[0],
        report_id: "WEB-001",
        finding_title: "Self-XSS via profile bio field",
        vulnerability_class: "self-xss",
        severity_claimed: "Low",
        cvss_score_claimed: 2.0
      }
    ],
    analysis_summary: { ...bundle.analysis_summary, confirmed_findings: 1 }
  };

  const triageResult = triageBundle(selfXssBundle);
  assert.equal(triageResult.results[0].triage_verdict, "NOT_APPLICABLE");
  assert.equal(triageResult.results[0].ready_to_submit, false);
  assert.ok(triageResult.results[0].key_discrepancies[0].includes("Self-XSS"));
  assert.deepEqual(validateTriageResult(triageResult, selfXssBundle), []);
});

test("triageBundle marks DoS findings as NOT_APPLICABLE", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const dosBundle = {
    ...bundle,
    findings: [
      {
        ...bundle.findings[0],
        report_id: "WEB-001",
        finding_title: "DoS via oversized JSON payload",
        vulnerability_class: "denial of service",
        severity_claimed: "Medium",
        cvss_score_claimed: 5.0
      }
    ],
    analysis_summary: { ...bundle.analysis_summary, confirmed_findings: 1 }
  };

  const triageResult = triageBundle(dosBundle);
  assert.equal(triageResult.results[0].triage_verdict, "NOT_APPLICABLE");
  assert.equal(triageResult.results[0].ready_to_submit, false);
  assert.ok(triageResult.results[0].key_discrepancies[0].includes("Denial-of-service"));
  assert.deepEqual(validateTriageResult(triageResult, dosBundle), []);
});

test("validateTriageResult rejects report_id with path traversal characters", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const triageResult = triageBundle(bundle);
  // Inject a malformed report_id that would cause path traversal if used as a filename
  triageResult.results[0].report_id = "../../etc/evil";
  const errors = validateTriageResult(triageResult, null);
  assert.ok(errors.some((e) => e.includes("report_id")));
});

test("triageBundle marks theoretical findings as INFORMATIVE and produces valid output", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const theoreticalBundle = {
    ...bundle,
    findings: [
      {
        ...bundle.findings[0],
        summary: "This could potentially lead to XSS in some theoretical scenario.",
        observed_result: "Potential issue identified, no confirmed runtime impact."
      }
    ]
  };

  const triageResult = triageBundle(theoreticalBundle);
  assert.equal(triageResult.results[0].triage_verdict, "INFORMATIVE");
  assert.equal(triageResult.results[0].ready_to_submit, false);
  assert.deepEqual(validateTriageResult(triageResult, theoreticalBundle), []);
});

test("triageBundle uses structured scope intelligence to mark out-of-scope findings", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const triageResult = triageBundle(bundle, {
    intelligence: {
      scopeSnapshot: {
        scopes: [
          {
            id: "scope-1",
            asset_identifier: "src/controllers/UserController.php:142",
            instruction: "Out of scope for this program",
            eligible_for_submission: false
          }
        ]
      },
      historySnapshot: { history: [] }
    }
  });

  assert.equal(triageResult.results[0].triage_verdict, "NOT_APPLICABLE");
  assert.match(triageResult.results[0].key_discrepancies.join("\n"), /Structured scope/);
  assert.deepEqual(validateTriageResult(triageResult, bundle), []);
});

test("triageBundle uses HackerOne history to flag likely duplicates", () => {
  const bundle = readJson(fixture("report_bundle.valid.json"));
  const triageResult = triageBundle(bundle, {
    intelligence: {
      scopeSnapshot: { scopes: [] },
      historySnapshot: {
        history: [
          {
            id: "hist-1",
            title:
              "SQL Injection in /api/users endpoint allows full database dump via id parameter",
            weakness: "SQLi",
            cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
          }
        ]
      }
    }
  });

  assert.equal(triageResult.results[0].triage_verdict, "DUPLICATE");
  assert.match(triageResult.results[0].duplicate_reference || "", /historical duplicate/i);
  assert.deepEqual(validateTriageResult(triageResult, bundle), []);
});

test("deriveProgramHandle prefers explicit hackerone handle and falls back to program_url", () => {
  assert.equal(
    deriveProgramHandle({
      program_url: "https://hackerone.com/example",
      hackerone: { program_handle: "duckduckgo" }
    }),
    "duckduckgo"
  );
  assert.equal(
    deriveProgramHandle({
      program_url: "https://hackerone.com/example"
    }),
    "example"
  );
});

test("writeProgramIntel persists snapshots that loadProgramIntel can read back", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bugbounty-intel-"));
  const intel = {
    meta: {
      program_handle: "duckduckgo",
      synced_at: "2026-03-18T10:00:00Z",
      sources: { scopes: 1, hacktivity: 1, reports: 0 }
    },
    scopes: [
      {
        id: "scope-1",
        program_handle: "duckduckgo",
        asset_identifier: "https://duckduckgo.com",
        eligible_for_submission: true
      }
    ],
    history: [
      {
        id: "hist-1",
        source: "hacktivity",
        program_handle: "duckduckgo",
        title: "OAuth misconfiguration",
        weakness: "OAuth"
      }
    ],
    skill_suggestions: [
      {
        key: "oauth",
        skill: "oauth",
        evidence_count: 1,
        sample_titles: ["OAuth misconfiguration"],
        reason: "Historical HackerOne data shows repeated oauth patterns for this target."
      }
    ]
  };

  writeProgramIntel(tmpDir, intel);
  const loaded = loadProgramIntel(tmpDir);

  assert.equal(loaded.scopeSnapshot.scopes[0].asset_identifier, "https://duckduckgo.com");
  assert.equal(loaded.historySnapshot.history[0].title, "OAuth misconfiguration");
  assert.equal(loaded.skillSnapshot.skill_suggestions[0].skill, "oauth");
});

test("persistProgramIntel writes the same intelligence into sqlite and loadProgramIntel can read it back", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bugbounty-db-"));
  const targetConfig = {
    target_name: "DuckDuckGo Privacy Essentials",
    asset_type: "browserext",
    program_url: "https://hackerone.com/duckduckgo"
  };
  const intel = {
    meta: {
      program_handle: "duckduckgo",
      synced_at: "2026-03-18T10:00:00Z",
      sources: { scopes: 1, hacktivity: 0, reports: 1 }
    },
    scopes: [
      {
        id: "scope-1",
        program_handle: "duckduckgo",
        asset_identifier: "https://duckduckgo.com",
        eligible_for_submission: true
      }
    ],
    history: [
      {
        id: "rep-1",
        source: "report",
        program_handle: "duckduckgo",
        title: "OAuth redirect_uri issue",
        weakness: "OAuth",
        created_at: "2026-03-18T09:00:00Z"
      }
    ],
    skill_suggestions: [
      {
        key: "oauth",
        skill: "oauth",
        evidence_count: 1,
        sample_titles: ["OAuth redirect_uri issue"],
        reason: "Historical HackerOne data shows repeated oauth patterns for this target."
      }
    ]
  };

  persistProgramIntel(targetConfig, tmpDir, intel);
  const dbPath = resolveDatabasePath(tmpDir);
  const db = openDatabase(dbPath);
  initDatabase(db);
  db.close();

  const loaded = loadProgramIntel(tmpDir, "duckduckgo");
  assert.equal(loaded.historySnapshot.history[0].title, "OAuth redirect_uri issue");
  assert.equal(loaded.skillSnapshot.skill_suggestions[0].skill, "oauth");
});

test("persistDisclosedDataset writes global disclosed reports that can be read back", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bugbounty-global-"));
  const payload = {
    meta: {
      synced_at: "2026-03-19T00:00:00Z",
      counts: {
        disclosed_reports: 2
      }
    },
    disclosed_reports: [
      {
        id: "100",
        source: "disclosed",
        program_handle: "curl",
        program_name: "curl",
        title: "HSTS accepted from HTTP origin behind HTTPS proxy",
        severity_rating: "Medium",
        weakness: "Acceptance of Extraneous Untrusted Data With Trusted Data",
        cwe: "CWE-349",
        disclosed_at: "2026-03-18T10:00:00Z",
        url: "https://hackerone.com/reports/100"
      },
      {
        id: "101",
        source: "disclosed",
        program_handle: "security",
        program_name: "HackerOne",
        title: "Reward redemption abuse",
        severity_rating: "Low",
        weakness: "Improper Access Control",
        cwe: "CWE-284",
        disclosed_at: "2026-03-18T11:00:00Z",
        url: "https://hackerone.com/reports/101"
      }
    ]
  };

  persistDisclosedDataset(tmpDir, payload);

  const db = openDatabase(resolveGlobalDatabasePath(tmpDir));
  initDatabase(db);
  const fromDb = readDisclosedDatasetFromDb(db);
  db.close();
  const loaded = loadDisclosedDataset(tmpDir);

  assert.equal(fromDb.disclosed_reports.length, 2);
  assert.equal(fromDb.summaries.top_programs.length, 2);
  assert.equal(loaded.meta.counts.disclosed_reports, 2);
});

test("buildResearchBrief prioritizes uncovered assets and merges local plus disclosed signal", () => {
  const config = {
    target_name: "DuckDuckGo Privacy Essentials",
    asset_type: "browserext",
    hackerone: { program_handle: "duckduckgo" }
  };

  const intelligence = {
    scopeSnapshot: {
      meta: { program_handle: "duckduckgo" },
      scopes: [
        {
          id: "scope-1",
          asset_type: "SOURCE_CODE",
          asset_identifier: "https://github.com/duckduckgo/duckduckgo-privacy-extension",
          eligible_for_submission: true,
          max_severity: "critical"
        },
        {
          id: "scope-2",
          asset_type: "WILDCARD",
          asset_identifier: "*.internal.duckduckgo.com",
          eligible_for_submission: true,
          max_severity: "critical"
        }
      ]
    },
    historySnapshot: {
      history: [
        {
          id: "hist-1",
          title: "XSS on duckduckgo.com settings page",
          weakness: "XSS",
          url: "https://duckduckgo.com/settings"
        }
      ]
    },
    skillSnapshot: {
      skill_suggestions: [
        {
          key: "xss",
          skill: "xss_filter_evasion",
          evidence_count: 1,
          reason: "Historical HackerOne data shows repeated xss patterns for this target.",
          sample_titles: ["XSS on duckduckgo.com settings page"]
        }
      ]
    }
  };

  const disclosed = {
    meta: { counts: { disclosed_reports: 1 } },
    disclosed_reports: [
      {
        id: "rep-1",
        program_handle: "duckduckgo",
        title: "Content script origin confusion in browser extension",
        weakness: "Origin Validation Error",
        cwe: "CWE-346",
        url: "https://github.com/duckduckgo/duckduckgo-privacy-extension"
      }
    ]
  };

  const brief = buildResearchBrief(config, intelligence, disclosed);

  assert.equal(brief.overview.uncovered_assets, 2);
  assert.equal(brief.prioritized_assets[0].asset_identifier, "https://github.com/duckduckgo/duckduckgo-privacy-extension");
  assert.equal(brief.prioritized_assets[0].coverage_status, "uncovered");
  assert.equal(brief.prioritized_assets[0].same_program_disclosed_matches, 1);
  assert.equal(brief.same_program_disclosed_top_weaknesses[0].label, "Origin Validation Error");
  assert.equal(brief.priority_bug_families[0].module_hint, "xss_filter_evasion");
});

// ── DB schema v2 ─────────────────────────────────────────────────────────────

test("project_components table is created with correct schema", () => {
  const dir  = fs.mkdtempSync(path.join(os.tmpdir(), "bb-test-"));
  const db   = openDatabase(path.join(dir, "test.db"));
  const cols = db.prepare("PRAGMA table_info(project_components)").all().map(c => c.name);
  assert.ok(cols.includes("target_id"));
  assert.ok(cols.includes("name"));
  assert.ok(cols.includes("version"));
  assert.ok(cols.includes("ecosystem"));
  assert.ok(cols.includes("source_file"));
  assert.ok(cols.includes("direct_dep"));
  db.close();
  fs.rmSync(dir, { recursive: true });
});

test("endpoints table is created with correct schema", () => {
  const dir  = fs.mkdtempSync(path.join(os.tmpdir(), "bb-test-"));
  const db   = openDatabase(path.join(dir, "test.db"));
  const cols = db.prepare("PRAGMA table_info(endpoints)").all().map(c => c.name);
  assert.ok(cols.includes("target_id"));
  assert.ok(cols.includes("method"));
  assert.ok(cols.includes("path"));
  assert.ok(cols.includes("params"));
  assert.ok(cols.includes("auth_required"));
  assert.ok(cols.includes("auth_type"));
  assert.ok(cols.includes("source"));
  db.close();
  fs.rmSync(dir, { recursive: true });
});

test("findings_history table is created with correct schema", () => {
  const dir  = fs.mkdtempSync(path.join(os.tmpdir(), "bb-test-"));
  const db   = openDatabase(path.join(dir, "test.db"));
  const cols = db.prepare("PRAGMA table_info(findings_history)").all().map(c => c.name);
  assert.ok(cols.includes("target_id"));
  assert.ok(cols.includes("report_id"));
  assert.ok(cols.includes("vuln_class"));
  assert.ok(cols.includes("severity"));
  assert.ok(cols.includes("status"));
  assert.ok(cols.includes("h1_submitted"));
  assert.ok(cols.includes("chain_id"));
  db.close();
  fs.rmSync(dir, { recursive: true });
});

test("zeroday_alerts table is created in global DB", () => {
  const dir    = fs.mkdtempSync(path.join(os.tmpdir(), "bb-test-"));
  const dbPath = resolveGlobalDatabasePath(dir);
  const db     = openDatabase(dbPath);
  const cols   = db.prepare("PRAGMA table_info(zeroday_alerts)").all().map(c => c.name);
  assert.ok(cols.includes("cve_id"));
  assert.ok(cols.includes("component"));
  assert.ok(cols.includes("affected_targets"));
  assert.ok(cols.includes("notified"));
  db.close();
  fs.rmSync(dir, { recursive: true });
});

test("upsertComponent inserts and deduplicates by target+name+ecosystem", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-test-"));
  const db  = openDatabase(path.join(dir, "test.db"));

  // Insert a fake target first
  db.prepare(
    "INSERT INTO targets_registry (handle, platform) VALUES (?, ?)"
  ).run("acme", "hackerone");
  const targetId = db.prepare("SELECT id FROM targets_registry WHERE handle = ?").get("acme").id;

  const { upsertComponent } = require("../scripts/lib/db");
  upsertComponent(db, { targetId, name: "lodash", version: "4.17.20", ecosystem: "npm", sourceFile: "package.json", directDep: 1 });
  upsertComponent(db, { targetId, name: "lodash", version: "4.17.21", ecosystem: "npm", sourceFile: "package-lock.json", directDep: 1 });

  const row = db.prepare("SELECT * FROM project_components WHERE name = 'lodash'").get();
  assert.equal(row.version, "4.17.21", "upsert should update version to latest");
  const count = db.prepare("SELECT COUNT(*) as n FROM project_components WHERE name = 'lodash'").get();
  assert.equal(count.n, 1, "should not duplicate");

  db.close();
  fs.rmSync(dir, { recursive: true });
});

test("upsertEndpoint inserts and deduplicates by target+method+path", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-test-"));
  const db  = openDatabase(path.join(dir, "test.db"));

  db.prepare("INSERT INTO targets_registry (handle) VALUES (?)").run("acme");
  const targetId = db.prepare("SELECT id FROM targets_registry WHERE handle = ?").get("acme").id;

  const { upsertEndpoint } = require("../scripts/lib/db");
  upsertEndpoint(db, { targetId, method: "GET", path: "/api/users", params: ["page", "limit"], authRequired: 1, authType: "jwt", source: "surface_map" });
  upsertEndpoint(db, { targetId, method: "GET", path: "/api/users", params: ["page", "limit", "filter"], authRequired: 1, authType: "jwt", source: "crawl" });

  const count = db.prepare("SELECT COUNT(*) as n FROM endpoints WHERE path = '/api/users'").get();
  assert.equal(count.n, 1, "should not duplicate");

  db.close();
  fs.rmSync(dir, { recursive: true });
});
