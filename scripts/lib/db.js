"use strict";

const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { ensureDir } = require("./io");

function resolveDatabasePath(intelligenceDir) {
  return path.join(intelligenceDir, "agentic-bugbounty.db");
}

function resolveGlobalDatabasePath(baseDir = path.resolve("data", "global-intelligence")) {
  return path.join(baseDir, "agentic-bugbounty-global.db");
}

function openDatabase(databasePath) {
  ensureDir(path.dirname(databasePath));
  const db = new DatabaseSync(databasePath);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  initDatabase(db);
  migrateDatabase(db);
  return db;
}

function migrateDatabase(db) {
  // ── disclosed_reports columns ──────────────────────────────────────────────
  const drColumns = db
    .prepare("PRAGMA table_info(disclosed_reports)")
    .all()
    .map((c) => c.name);

  if (!drColumns.includes("asset_type")) {
    db.exec("ALTER TABLE disclosed_reports ADD COLUMN asset_type TEXT");
  }
  if (!drColumns.includes("vuln_class")) {
    db.exec("ALTER TABLE disclosed_reports ADD COLUMN vuln_class TEXT");
  }
  if (!drColumns.includes("hacktivity_summary")) {
    db.exec("ALTER TABLE disclosed_reports ADD COLUMN hacktivity_summary TEXT");
  }

  // ── domains layer tables (added in v2) ────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS targets_registry (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      handle      TEXT    NOT NULL UNIQUE,
      platform    TEXT,
      program_url TEXT,
      created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      last_scanned TEXT
    );

    CREATE TABLE IF NOT EXISTS scope_rules (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id   INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      type        TEXT    NOT NULL CHECK(type IN ('in','out')),
      entity_type TEXT    NOT NULL CHECK(entity_type IN ('domain','vuln','asset','ip')),
      pattern     TEXT    NOT NULL,
      source      TEXT,
      updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    CREATE TABLE IF NOT EXISTS subdomains (
      id                  INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id           INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      subdomain           TEXT    NOT NULL,
      ip                  TEXT,
      cname               TEXT,
      status              TEXT    NOT NULL DEFAULT 'unknown'
                            CHECK(status IN ('live','dead','redirects','unknown')),
      http_status         INTEGER,
      title               TEXT,
      interesting         INTEGER NOT NULL DEFAULT 0,
      takeover_candidate  INTEGER NOT NULL DEFAULT 0,
      first_seen          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      last_seen           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      last_checked        TEXT,
      UNIQUE(target_id, subdomain)
    );

    CREATE TABLE IF NOT EXISTS host_technologies (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
      target_id    INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      tech_name    TEXT    NOT NULL,
      tech_category TEXT,
      version      TEXT,
      confidence   TEXT    NOT NULL DEFAULT 'medium'
                     CHECK(confidence IN ('high','medium','low')),
      source       TEXT,
      first_seen   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      last_seen    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(subdomain_id, tech_name)
    );

    CREATE TABLE IF NOT EXISTS services (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
      ip           TEXT    NOT NULL,
      port         INTEGER NOT NULL,
      protocol     TEXT    NOT NULL DEFAULT 'tcp',
      service      TEXT,
      version      TEXT,
      banner       TEXT,
      first_seen   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      last_seen    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(subdomain_id, port, protocol)
    );

    CREATE TABLE IF NOT EXISTS email_security (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id        INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      domain           TEXT    NOT NULL,
      spf              TEXT,
      dmarc            TEXT,
      dkim_selectors   TEXT,
      spoofable        INTEGER NOT NULL DEFAULT 0,
      checked_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(target_id, domain)
    );

    CREATE TABLE IF NOT EXISTS domain_changes (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id   INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      entity_type TEXT    NOT NULL,
      entity_id   INTEGER,
      change_type TEXT    NOT NULL,
      old_value   TEXT,
      new_value   TEXT,
      detected_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    CREATE TABLE IF NOT EXISTS scan_runs (
      id                  INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id           INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      run_type            TEXT    NOT NULL
                            CHECK(run_type IN ('domains','whitebox','blackbox','cve_hunt')),
      started_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      finished_at         TEXT,
      subdomains_found    INTEGER NOT NULL DEFAULT 0,
      hosts_live          INTEGER NOT NULL DEFAULT 0,
      hosts_interesting   INTEGER NOT NULL DEFAULT 0,
      findings_count      INTEGER NOT NULL DEFAULT 0,
      status              TEXT    NOT NULL DEFAULT 'running'
                            CHECK(status IN ('running','completed','failed','interrupted'))
    );

    CREATE TABLE IF NOT EXISTS schedules (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id  INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      run_type   TEXT    NOT NULL,
      cron_expr  TEXT    NOT NULL,
      last_run   TEXT,
      next_run   TEXT,
      enabled    INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS cve_tech_matches (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id    INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
      tech_name    TEXT    NOT NULL,
      tech_version TEXT,
      cve_id       TEXT    NOT NULL,
      cvss_score   REAL,
      notified     INTEGER NOT NULL DEFAULT 0,
      detected_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(subdomain_id, cve_id)
    );

    CREATE INDEX IF NOT EXISTS idx_subdomains_target     ON subdomains(target_id);
    CREATE INDEX IF NOT EXISTS idx_subdomains_status     ON subdomains(status);
    CREATE INDEX IF NOT EXISTS idx_subdomains_interesting ON subdomains(interesting);
    CREATE INDEX IF NOT EXISTS idx_subdomains_takeover   ON subdomains(takeover_candidate);
    CREATE INDEX IF NOT EXISTS idx_host_tech_name        ON host_technologies(tech_name);
    CREATE INDEX IF NOT EXISTS idx_host_tech_version     ON host_technologies(tech_name, version);
    CREATE INDEX IF NOT EXISTS idx_host_tech_target      ON host_technologies(target_id);
    CREATE INDEX IF NOT EXISTS idx_changes_target        ON domain_changes(target_id);
    CREATE INDEX IF NOT EXISTS idx_changes_detected      ON domain_changes(detected_at);
    CREATE INDEX IF NOT EXISTS idx_cve_matches_target    ON cve_tech_matches(target_id);
    CREATE INDEX IF NOT EXISTS idx_cve_matches_notified  ON cve_tech_matches(notified);
    CREATE INDEX IF NOT EXISTS idx_scan_runs_target      ON scan_runs(target_id);

    -- ── Operative identities ──────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS operative_identities (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id     INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      role          TEXT    NOT NULL CHECK(role IN ('victim','attacker','admin','reviewer')),
      email         TEXT    NOT NULL,
      username      TEXT    NOT NULL,
      first_name    TEXT    NOT NULL,
      last_name     TEXT    NOT NULL,
      password_enc  TEXT    NOT NULL,
      birth_date    TEXT,
      phone         TEXT,
      extra_json    TEXT    NOT NULL DEFAULT '{}',
      created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(target_id, role)
    );

    -- ── interactsh callbacks ──────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS interactsh_callbacks (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      full_id       TEXT    NOT NULL,
      report_id     TEXT,
      target_handle TEXT,
      protocol      TEXT,
      source_ip     TEXT,
      raw_request   TEXT,
      raw_response  TEXT,
      timestamp     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      notified      INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_callbacks_report    ON interactsh_callbacks(report_id);
    CREATE INDEX IF NOT EXISTS idx_callbacks_target    ON interactsh_callbacks(target_handle);
    CREATE INDEX IF NOT EXISTS idx_callbacks_notified  ON interactsh_callbacks(notified);
    CREATE INDEX IF NOT EXISTS idx_identities_target   ON operative_identities(target_id);

    -- ── project_components — dependency inventory from whitebox analysis ──────
    CREATE TABLE IF NOT EXISTS project_components (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id     INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      name          TEXT    NOT NULL,
      version       TEXT,
      version_range TEXT,
      ecosystem     TEXT    NOT NULL,
      source_file   TEXT    NOT NULL,
      direct_dep    INTEGER NOT NULL DEFAULT 1,
      in_scope      INTEGER NOT NULL DEFAULT 1,
      first_seen    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      last_seen     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(target_id, name, ecosystem)
    );

    CREATE INDEX IF NOT EXISTS idx_components_name      ON project_components(name);
    CREATE INDEX IF NOT EXISTS idx_components_ecosystem ON project_components(target_id, name, ecosystem);
    CREATE INDEX IF NOT EXISTS idx_components_target    ON project_components(target_id);

    -- ── endpoints — discovered API surface ───────────────────────────────────
    CREATE TABLE IF NOT EXISTS endpoints (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id     INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      subdomain_id  INTEGER REFERENCES subdomains(id) ON DELETE SET NULL,
      method        TEXT    NOT NULL DEFAULT 'GET',
      path          TEXT    NOT NULL,
      params        TEXT    NOT NULL DEFAULT '[]',
      auth_required INTEGER NOT NULL DEFAULT 0,
      auth_type     TEXT,
      content_type  TEXT,
      source        TEXT    NOT NULL DEFAULT 'surface_map',
      notes         TEXT,
      first_seen    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      last_seen     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(target_id, method, path)
    );

    CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target_id);
    CREATE INDEX IF NOT EXISTS idx_endpoints_path   ON endpoints(path);
    CREATE INDEX IF NOT EXISTS idx_endpoints_auth   ON endpoints(auth_required);

    -- ── findings_history — confirmed/unconfirmed findings per target ──────────
    CREATE TABLE IF NOT EXISTS findings_history (
      id                 INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id          INTEGER NOT NULL REFERENCES targets_registry(id) ON DELETE CASCADE,
      report_id          TEXT    NOT NULL,
      vuln_class         TEXT    NOT NULL,
      severity           TEXT    NOT NULL,
      cvss_score         REAL,
      title              TEXT    NOT NULL,
      affected_component TEXT,
      status             TEXT    NOT NULL DEFAULT 'confirmed'
                           CHECK(status IN ('confirmed','unconfirmed','invalid','duplicate')),
      h1_submitted       INTEGER NOT NULL DEFAULT 0,
      h1_report_url      TEXT,
      h1_bounty          REAL,
      poc_type           TEXT,
      chain_id           TEXT,
      run_id             INTEGER REFERENCES scan_runs(id),
      discovered_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(target_id, report_id)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings_history(target_id);
    CREATE INDEX IF NOT EXISTS idx_findings_vuln     ON findings_history(vuln_class);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings_history(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_h1       ON findings_history(h1_submitted);
  `);
}

function initDatabase(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sync_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      program_handle TEXT NOT NULL,
      synced_at TEXT NOT NULL,
      scope_count INTEGER NOT NULL DEFAULT 0,
      hacktivity_count INTEGER NOT NULL DEFAULT 0,
      report_count INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS programs (
      program_handle TEXT PRIMARY KEY,
      target_name TEXT,
      asset_type TEXT,
      program_url TEXT,
      last_synced_at TEXT
    );

    CREATE TABLE IF NOT EXISTS structured_scopes (
      id TEXT PRIMARY KEY,
      program_handle TEXT NOT NULL,
      asset_type TEXT,
      asset_identifier TEXT,
      instruction TEXT,
      eligible_for_submission INTEGER,
      max_severity TEXT,
      created_at TEXT,
      updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS vulnerability_history (
      history_key TEXT PRIMARY KEY,
      remote_id TEXT,
      source TEXT NOT NULL,
      program_handle TEXT NOT NULL,
      title TEXT,
      state TEXT,
      severity_rating TEXT,
      cwe TEXT,
      weakness TEXT,
      disclosed_at TEXT,
      created_at TEXT,
      updated_at TEXT,
      url TEXT
    );

    CREATE TABLE IF NOT EXISTS skill_suggestions (
      program_handle TEXT NOT NULL,
      skill_key TEXT NOT NULL,
      skill_name TEXT NOT NULL,
      evidence_count INTEGER NOT NULL DEFAULT 0,
      reason TEXT,
      sample_titles_json TEXT NOT NULL,
      PRIMARY KEY (program_handle, skill_key)
    );

    CREATE TABLE IF NOT EXISTS disclosed_sync_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      synced_at TEXT NOT NULL,
      disclosed_count INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS disclosed_reports (
      disclosed_key TEXT PRIMARY KEY,
      remote_id TEXT,
      program_handle TEXT,
      program_name TEXT,
      program_url TEXT,
      title TEXT,
      severity_rating TEXT,
      weakness TEXT,
      cwe TEXT,
      disclosed_at TEXT,
      created_at TEXT,
      url TEXT,
      asset_type TEXT,
      vuln_class TEXT
    );

    CREATE TABLE IF NOT EXISTS calibration_sync_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      synced_at TEXT NOT NULL,
      total_reports INTEGER NOT NULL DEFAULT 0,
      classified_reports INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS calibration_patterns (
      pattern_key TEXT PRIMARY KEY,
      asset_type TEXT NOT NULL,
      vuln_class TEXT NOT NULL,
      severity_rating TEXT,
      total_count INTEGER NOT NULL DEFAULT 0,
      critical_count INTEGER NOT NULL DEFAULT 0,
      high_count INTEGER NOT NULL DEFAULT 0,
      medium_count INTEGER NOT NULL DEFAULT 0,
      low_count INTEGER NOT NULL DEFAULT 0,
      informative_count INTEGER NOT NULL DEFAULT 0,
      sample_titles_json TEXT NOT NULL DEFAULT '[]',
      sample_urls_json TEXT NOT NULL DEFAULT '[]',
      top_programs_json TEXT NOT NULL DEFAULT '[]',
      typical_cwe TEXT,
      typical_weakness TEXT,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS report_behaviors (
      behavior_key TEXT PRIMARY KEY,
      asset_type TEXT NOT NULL,
      vuln_class TEXT NOT NULL,
      report_id TEXT,
      program_handle TEXT,
      title TEXT,
      severity_rating TEXT,
      hacktivity_summary TEXT,
      url TEXT,
      disclosed_at TEXT,
      updated_at TEXT NOT NULL
    );

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

    -- ── zeroday_alerts — cross-project 0-day matches ─────────────────────────
    CREATE TABLE IF NOT EXISTS zeroday_alerts (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id           TEXT    NOT NULL,
      cvss_score       REAL,
      component        TEXT    NOT NULL,
      version          TEXT,
      affected_targets TEXT    NOT NULL DEFAULT '[]',
      notified         INTEGER NOT NULL DEFAULT 0,
      created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      UNIQUE(cve_id, component)
    );

    CREATE INDEX IF NOT EXISTS idx_zeroday_notified  ON zeroday_alerts(notified);
    CREATE INDEX IF NOT EXISTS idx_zeroday_component ON zeroday_alerts(component);
  `);
}

function replaceProgramIntel(db, targetConfig, intel) {
  const insertSyncRun = db.prepare(`
    INSERT INTO sync_runs (
      program_handle, synced_at, scope_count, hacktivity_count, report_count
    ) VALUES (?, ?, ?, ?, ?)
  `);

  const upsertProgram = db.prepare(`
    INSERT INTO programs (
      program_handle, target_name, asset_type, program_url, last_synced_at
    ) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(program_handle) DO UPDATE SET
      target_name = excluded.target_name,
      asset_type = excluded.asset_type,
      program_url = excluded.program_url,
      last_synced_at = excluded.last_synced_at
  `);

  const clearScopes = db.prepare("DELETE FROM structured_scopes WHERE program_handle = ?");
  const clearHistory = db.prepare("DELETE FROM vulnerability_history WHERE program_handle = ?");
  const clearSkills = db.prepare("DELETE FROM skill_suggestions WHERE program_handle = ?");

  const insertScope = db.prepare(`
    INSERT OR REPLACE INTO structured_scopes (
      id, program_handle, asset_type, asset_identifier, instruction,
      eligible_for_submission, max_severity, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertHistory = db.prepare(`
    INSERT OR REPLACE INTO vulnerability_history (
      history_key, remote_id, source, program_handle, title, state, severity_rating,
      cwe, weakness, disclosed_at, created_at, updated_at, url
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertSkill = db.prepare(`
    INSERT OR REPLACE INTO skill_suggestions (
      program_handle, skill_key, skill_name, evidence_count, reason, sample_titles_json
    ) VALUES (?, ?, ?, ?, ?, ?)
  `);

  db.exec("BEGIN");
  try {
    upsertProgram.run(
      intel.meta.program_handle,
      targetConfig.target_name,
      targetConfig.asset_type,
      targetConfig.program_url,
      intel.meta.synced_at
    );

    insertSyncRun.run(
      intel.meta.program_handle,
      intel.meta.synced_at,
      intel.meta.sources.scopes,
      intel.meta.sources.hacktivity,
      intel.meta.sources.reports
    );

    clearScopes.run(intel.meta.program_handle);
    clearHistory.run(intel.meta.program_handle);
    clearSkills.run(intel.meta.program_handle);

    for (const scope of intel.scopes) {
      insertScope.run(
        sqlValue(
          scope.id || `${intel.meta.program_handle}:${scope.asset_identifier || cryptoRandomKey()}`
        ),
        intel.meta.program_handle,
        sqlValue(scope.asset_type),
        sqlValue(scope.asset_identifier),
        sqlValue(scope.instruction),
        scope.eligible_for_submission === true ? 1 : scope.eligible_for_submission === false ? 0 : null,
        sqlValue(scope.max_severity),
        sqlValue(scope.created_at),
        sqlValue(scope.updated_at)
      );
    }

    for (const historyItem of intel.history) {
      insertHistory.run(
        buildHistoryKey(historyItem),
        sqlValue(historyItem.id),
        sqlValue(historyItem.source),
        intel.meta.program_handle,
        sqlValue(historyItem.title),
        sqlValue(historyItem.state),
        sqlValue(historyItem.severity_rating),
        sqlValue(historyItem.cwe),
        sqlValue(historyItem.weakness),
        sqlValue(historyItem.disclosed_at),
        sqlValue(historyItem.created_at),
        sqlValue(historyItem.updated_at),
        sqlValue(historyItem.url)
      );
    }

    for (const suggestion of intel.skill_suggestions) {
        insertSkill.run(
          intel.meta.program_handle,
          sqlValue(suggestion.key),
          sqlValue(suggestion.skill),
          suggestion.evidence_count,
          sqlValue(suggestion.reason),
          JSON.stringify(suggestion.sample_titles || [])
        );
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function buildHistoryKey(historyItem) {
  return [
    historyItem.program_handle || "",
    historyItem.source || "",
    historyItem.id || "",
    historyItem.title || "",
    historyItem.created_at || ""
  ].join("::");
}

function cryptoRandomKey() {
  return Math.random().toString(36).slice(2, 10);
}

function sqlValue(value) {
  return value === undefined ? null : value;
}

function readProgramIntelFromDb(db, programHandle) {
  const scopes = db
    .prepare(`
      SELECT id, program_handle, asset_type, asset_identifier, instruction,
             eligible_for_submission, max_severity, created_at, updated_at
      FROM structured_scopes
      WHERE program_handle = ?
      ORDER BY asset_identifier
    `)
    .all(programHandle)
    .map((row) => ({
      ...row,
      eligible_for_submission:
        row.eligible_for_submission === null
          ? null
          : Boolean(row.eligible_for_submission)
    }));

  const history = db
    .prepare(`
      SELECT remote_id AS id, source, program_handle, title, state, severity_rating,
             cwe, weakness, disclosed_at, created_at, updated_at, url
      FROM vulnerability_history
      WHERE program_handle = ?
      ORDER BY created_at DESC
    `)
    .all(programHandle);

  const skillSuggestions = db
    .prepare(`
      SELECT skill_key AS key, skill_name AS skill, evidence_count, reason, sample_titles_json
      FROM skill_suggestions
      WHERE program_handle = ?
      ORDER BY evidence_count DESC, skill_name ASC
    `)
    .all(programHandle)
    .map((row) => ({
      key: row.key,
      skill: row.skill,
      evidence_count: row.evidence_count,
      reason: row.reason,
      sample_titles: JSON.parse(row.sample_titles_json)
    }));

  const latestSync = db
    .prepare(`
      SELECT synced_at, scope_count, hacktivity_count, report_count
      FROM sync_runs
      WHERE program_handle = ?
      ORDER BY synced_at DESC
      LIMIT 1
    `)
    .get(programHandle);

  if (!latestSync) {
    return null;
  }

  return {
    meta: {
      program_handle: programHandle,
      synced_at: latestSync.synced_at,
      sources: {
        scopes: latestSync.scope_count,
        hacktivity: latestSync.hacktivity_count,
        reports: latestSync.report_count
      }
    },
    scopes,
    history,
    skill_suggestions: skillSuggestions
  };
}

function replaceDisclosedReports(db, payload) {
  const clearReports = db.prepare("DELETE FROM disclosed_reports");
  const insertSyncRun = db.prepare(`
    INSERT INTO disclosed_sync_runs (synced_at, disclosed_count) VALUES (?, ?)
  `);
  const insertDisclosed = db.prepare(`
    INSERT OR REPLACE INTO disclosed_reports (
      disclosed_key, remote_id, program_handle, program_name, program_url, title,
      severity_rating, weakness, cwe, disclosed_at, created_at, url, hacktivity_summary
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  db.exec("BEGIN");
  try {
    clearReports.run();
    insertSyncRun.run(payload.meta.synced_at, payload.meta.counts.disclosed_reports);

    for (const report of payload.disclosed_reports) {
      insertDisclosed.run(
        [
          sqlValue(report.program_handle || "unknown"),
          sqlValue(report.id || ""),
          sqlValue(report.disclosed_at || report.created_at || "")
        ].join("::"),
        sqlValue(report.id),
        sqlValue(report.program_handle),
        sqlValue(report.program_name),
        sqlValue(report.program_url),
        sqlValue(report.title),
        sqlValue(report.severity_rating),
        sqlValue(report.weakness),
        sqlValue(report.cwe),
        sqlValue(report.disclosed_at),
        sqlValue(report.created_at),
        sqlValue(report.url),
        sqlValue(report.hacktivity_summary)
      );
    }

    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function readDisclosedDatasetFromDb(db) {
  const latestSync = db
    .prepare(`
      SELECT synced_at, disclosed_count
      FROM disclosed_sync_runs
      ORDER BY synced_at DESC
      LIMIT 1
    `)
    .get();

  if (!latestSync) {
    return null;
  }

  const disclosedReports = db
    .prepare(`
      SELECT remote_id AS id, program_handle, program_name, program_url, title,
             severity_rating, weakness, cwe, disclosed_at, created_at, url
      FROM disclosed_reports
      ORDER BY disclosed_at DESC, created_at DESC
    `)
    .all();

  const topPrograms = db
    .prepare(`
      SELECT program_handle, program_name, COUNT(*) AS disclosed_count
      FROM disclosed_reports
      GROUP BY program_handle, program_name
      ORDER BY disclosed_count DESC, program_handle ASC
      LIMIT 25
    `)
    .all();

  const topWeaknesses = db
    .prepare(`
      SELECT weakness, COUNT(*) AS count
      FROM disclosed_reports
      WHERE weakness IS NOT NULL AND weakness != ''
      GROUP BY weakness
      ORDER BY count DESC, weakness ASC
      LIMIT 25
    `)
    .all();

  return {
    meta: {
      synced_at: latestSync.synced_at,
      counts: {
        disclosed_reports: latestSync.disclosed_count
      }
    },
    disclosed_reports: disclosedReports,
    summaries: {
      top_programs: topPrograms,
      top_weaknesses: topWeaknesses
    }
  };
}

function replaceCalibrationPatterns(db, payload) {
  const insertSyncRun = db.prepare(`
    INSERT INTO calibration_sync_runs (synced_at, total_reports, classified_reports)
    VALUES (?, ?, ?)
  `);
  const upsertPattern = db.prepare(`
    INSERT OR REPLACE INTO calibration_patterns (
      pattern_key, asset_type, vuln_class,
      total_count, critical_count, high_count, medium_count, low_count, informative_count,
      sample_titles_json, sample_urls_json, top_programs_json,
      typical_cwe, typical_weakness, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const upsertAssetType = db.prepare(`
    UPDATE disclosed_reports SET asset_type = ?, vuln_class = ?
    WHERE disclosed_key = ?
  `);

  db.exec("BEGIN");
  try {
    insertSyncRun.run(
      payload.meta.synced_at,
      payload.meta.total_reports,
      payload.meta.classified_reports
    );

    for (const [key, pattern] of Object.entries(payload.patterns)) {
      upsertPattern.run(
        key,
        pattern.asset_type,
        pattern.vuln_class,
        pattern.total_count,
        pattern.critical_count,
        pattern.high_count,
        pattern.medium_count,
        pattern.low_count,
        pattern.informative_count,
        JSON.stringify(pattern.sample_titles || []),
        JSON.stringify(pattern.sample_urls || []),
        JSON.stringify(pattern.top_programs || []),
        sqlValue(pattern.typical_cwe),
        sqlValue(pattern.typical_weakness),
        payload.meta.synced_at
      );
    }

    for (const report of payload.classified_reports) {
      upsertAssetType.run(
        sqlValue(report.asset_type),
        sqlValue(report.vuln_class),
        report.disclosed_key
      );
    }

    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function queryCalibrationDataset(db, { assetType, vulnClass } = {}) {
  let where = "1=1";
  const params = [];
  if (assetType) {
    where += " AND asset_type = ?";
    params.push(assetType);
  }
  if (vulnClass) {
    where += " AND vuln_class = ?";
    params.push(vulnClass);
  }

  const patterns = db
    .prepare(`
      SELECT asset_type, vuln_class,
             total_count, critical_count, high_count, medium_count, low_count, informative_count,
             sample_titles_json, sample_urls_json, top_programs_json,
             typical_cwe, typical_weakness, updated_at
      FROM calibration_patterns
      WHERE ${where}
      ORDER BY total_count DESC, asset_type, vuln_class
    `)
    .all(...params)
    .map((row) => ({
      asset_type: row.asset_type,
      vuln_class: row.vuln_class,
      counts: {
        total: row.total_count,
        critical: row.critical_count,
        high: row.high_count,
        medium: row.medium_count,
        low: row.low_count,
        informative: row.informative_count
      },
      typical_severity: deriveTypicalSeverity(row),
      typical_cwe: row.typical_cwe,
      typical_weakness: row.typical_weakness,
      sample_titles: JSON.parse(row.sample_titles_json),
      sample_urls: JSON.parse(row.sample_urls_json),
      top_programs: JSON.parse(row.top_programs_json),
      updated_at: row.updated_at
    }));

  const latestSync = db
    .prepare(`
      SELECT synced_at, total_reports, classified_reports
      FROM calibration_sync_runs
      ORDER BY synced_at DESC
      LIMIT 1
    `)
    .get();

  return {
    meta: latestSync || { synced_at: null, total_reports: 0, classified_reports: 0 },
    patterns
  };
}

function replaceReportBehaviors(db, payload) {
  const deleteExisting = db.prepare(
    "DELETE FROM report_behaviors WHERE asset_type = ? AND vuln_class = ?"
  );
  const insert = db.prepare(`
    INSERT OR REPLACE INTO report_behaviors (
      behavior_key, asset_type, vuln_class, report_id, program_handle,
      title, severity_rating, hacktivity_summary, url, disclosed_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  db.exec("BEGIN");
  try {
    for (const [key, records] of Object.entries(payload.by_class)) {
      const [asset_type, vuln_class] = key.split("::");
      deleteExisting.run(asset_type, vuln_class);
      for (const r of records) {
        insert.run(
          r.behavior_key,
          asset_type,
          vuln_class,
          sqlValue(r.report_id),
          sqlValue(r.program_handle),
          sqlValue(r.title),
          sqlValue(r.severity_rating),
          sqlValue(r.hacktivity_summary),
          sqlValue(r.url),
          sqlValue(r.disclosed_at),
          payload.meta.synced_at
        );
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function queryReportBehaviors(db, { assetType, vulnClass, limit = 10 } = {}) {
  let where = "1=1";
  const params = [];
  if (assetType) {
    where += " AND asset_type = ?";
    params.push(assetType);
  }
  if (vulnClass) {
    where += " AND vuln_class = ?";
    params.push(vulnClass);
  }

  const rows = db
    .prepare(`
      SELECT asset_type, vuln_class, report_id, program_handle,
             title, severity_rating, hacktivity_summary, url, disclosed_at
      FROM report_behaviors
      WHERE ${where} AND hacktivity_summary IS NOT NULL
      ORDER BY disclosed_at DESC
      LIMIT ?
    `)
    .all(...params, limit);

  return rows;
}

function deriveTypicalSeverity(row) {
  const ranked = [
    { label: "critical", count: row.critical_count },
    { label: "high", count: row.high_count },
    { label: "medium", count: row.medium_count },
    { label: "low", count: row.low_count },
    { label: "informative", count: row.informative_count }
  ].filter((s) => s.count > 0);
  if (ranked.length === 0) return null;
  ranked.sort((a, b) => b.count - a.count);
  return ranked[0].label;
}

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

function queryCveIntel(db, targetRef, { limit = 50 } = {}) {
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

// ── Domains layer ─────────────────────────────────────────────────────────────

function upsertTarget(db, { handle, platform, program_url }) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO targets_registry (handle, platform, program_url, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(handle) DO UPDATE SET
      platform    = excluded.platform,
      program_url = excluded.program_url
  `).run(handle, sqlValue(platform), sqlValue(program_url), now);
  return db.prepare("SELECT * FROM targets_registry WHERE handle = ?").get(handle);
}

function getTarget(db, handle) {
  return db.prepare("SELECT * FROM targets_registry WHERE handle = ?").get(handle) || null;
}

function listTargets(db) {
  return db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM subdomains s WHERE s.target_id = t.id AND s.status = 'live') AS live_count,
      (SELECT COUNT(*) FROM subdomains s WHERE s.target_id = t.id AND s.interesting = 1) AS interesting_count,
      (SELECT COUNT(*) FROM subdomains s WHERE s.target_id = t.id AND s.takeover_candidate = 1) AS takeover_count
    FROM targets_registry t
    ORDER BY t.last_scanned DESC NULLS LAST, t.created_at DESC
  `).all();
}

function touchTargetScanned(db, targetId) {
  db.prepare("UPDATE targets_registry SET last_scanned = ? WHERE id = ?")
    .run(new Date().toISOString(), targetId);
}

function replaceScopeRules(db, targetId, rules) {
  db.prepare("DELETE FROM scope_rules WHERE target_id = ?").run(targetId);
  const insert = db.prepare(`
    INSERT INTO scope_rules (target_id, type, entity_type, pattern, source, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const now = new Date().toISOString();
  db.exec("BEGIN");
  try {
    for (const r of rules) {
      insert.run(targetId, r.type, r.entity_type, r.pattern, sqlValue(r.source), now);
    }
    db.exec("COMMIT");
  } catch (e) { db.exec("ROLLBACK"); throw e; }
}

function getScopeRules(db, targetId, { type, entity_type } = {}) {
  const conds = ["target_id = ?"];
  const params = [targetId];
  if (type) { conds.push("type = ?"); params.push(type); }
  if (entity_type) { conds.push("entity_type = ?"); params.push(entity_type); }
  return db.prepare(`SELECT * FROM scope_rules WHERE ${conds.join(" AND ")}`).all(...params);
}

function upsertSubdomain(db, targetId, data) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO subdomains
      (target_id, subdomain, ip, cname, status, http_status, title,
       interesting, takeover_candidate, first_seen, last_seen, last_checked)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(target_id, subdomain) DO UPDATE SET
      ip                 = excluded.ip,
      cname              = excluded.cname,
      status             = excluded.status,
      http_status        = excluded.http_status,
      title              = excluded.title,
      interesting        = excluded.interesting,
      takeover_candidate = excluded.takeover_candidate,
      last_seen          = excluded.last_seen,
      last_checked       = excluded.last_checked
  `).run(
    targetId,
    data.subdomain,
    sqlValue(data.ip),
    sqlValue(data.cname),
    data.status || "unknown",
    sqlValue(data.http_status),
    sqlValue(data.title),
    data.interesting ? 1 : 0,
    data.takeover_candidate ? 1 : 0,
    data.first_seen || now,
    now,
    now
  );
  return db.prepare(
    "SELECT * FROM subdomains WHERE target_id = ? AND subdomain = ?"
  ).get(targetId, data.subdomain);
}

function getSubdomains(db, targetId, { status, interesting, takeover, limit = 1000 } = {}) {
  const conds = ["s.target_id = ?"];
  const params = [targetId];
  if (status)      { conds.push("s.status = ?");             params.push(status); }
  if (interesting) { conds.push("s.interesting = 1"); }
  if (takeover)    { conds.push("s.takeover_candidate = 1"); }
  return db.prepare(`
    SELECT s.*,
      (SELECT json_group_array(json_object(
         'tech_name', ht.tech_name, 'version', ht.version,
         'category', ht.tech_category, 'confidence', ht.confidence))
       FROM host_technologies ht WHERE ht.subdomain_id = s.id) AS technologies_json
    FROM subdomains s
    WHERE ${conds.join(" AND ")}
    ORDER BY s.interesting DESC, s.status ASC, s.subdomain ASC
    LIMIT ?
  `).all(...params, limit).map((r) => ({
    ...r,
    technologies: JSON.parse(r.technologies_json || "[]")
  }));
}

function upsertTechnology(db, subdomainId, targetId, data) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO host_technologies
      (subdomain_id, target_id, tech_name, tech_category, version,
       confidence, source, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(subdomain_id, tech_name) DO UPDATE SET
      tech_category = excluded.tech_category,
      version       = COALESCE(excluded.version, version),
      confidence    = excluded.confidence,
      source        = excluded.source,
      last_seen     = excluded.last_seen
  `).run(
    subdomainId, targetId,
    data.tech_name.toLowerCase().trim(),
    sqlValue(data.tech_category),
    sqlValue(data.version),
    data.confidence || "medium",
    sqlValue(data.source),
    data.first_seen || now, now
  );
}

function getTechByName(db, techName, { liveOnly = true } = {}) {
  const statusFilter = liveOnly ? "AND s.status = 'live'" : "";
  return db.prepare(`
    SELECT ht.tech_name, ht.version, ht.confidence, ht.source,
           s.subdomain, s.ip, s.http_status,
           t.handle AS target_handle, t.program_url
    FROM host_technologies ht
    JOIN subdomains s ON s.id = ht.subdomain_id
    JOIN targets_registry t ON t.id = ht.target_id
    WHERE ht.tech_name = ? ${statusFilter}
    ORDER BY ht.confidence DESC, t.handle ASC
  `).all(techName.toLowerCase().trim());
}

function getTechSummary(db, targetId) {
  return db.prepare(`
    SELECT ht.tech_name, ht.tech_category,
           COUNT(DISTINCT ht.subdomain_id) AS host_count,
           GROUP_CONCAT(DISTINCT ht.version) AS versions,
           MAX(ht.last_seen) AS last_seen
    FROM host_technologies ht
    JOIN subdomains s ON s.id = ht.subdomain_id
    WHERE ht.target_id = ? AND s.status = 'live'
    GROUP BY ht.tech_name, ht.tech_category
    ORDER BY host_count DESC, ht.tech_name ASC
  `).all(targetId);
}

function upsertService(db, subdomainId, data) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO services
      (subdomain_id, ip, port, protocol, service, version, banner, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(subdomain_id, port, protocol) DO UPDATE SET
      service   = excluded.service,
      version   = excluded.version,
      banner    = excluded.banner,
      last_seen = excluded.last_seen
  `).run(
    subdomainId, data.ip, data.port, data.protocol || "tcp",
    sqlValue(data.service), sqlValue(data.version), sqlValue(data.banner),
    data.first_seen || now, now
  );
}

function upsertEmailSecurity(db, targetId, data) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO email_security
      (target_id, domain, spf, dmarc, dkim_selectors, spoofable, checked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(target_id, domain) DO UPDATE SET
      spf            = excluded.spf,
      dmarc          = excluded.dmarc,
      dkim_selectors = excluded.dkim_selectors,
      spoofable      = excluded.spoofable,
      checked_at     = excluded.checked_at
  `).run(
    targetId, data.domain,
    sqlValue(data.spf), sqlValue(data.dmarc), sqlValue(data.dkim_selectors),
    data.spoofable ? 1 : 0, now
  );
}

function recordChange(db, targetId, { entity_type, entity_id, change_type, old_value, new_value }) {
  db.prepare(`
    INSERT INTO domain_changes
      (target_id, entity_type, entity_id, change_type, old_value, new_value, detected_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    targetId, entity_type, sqlValue(entity_id),
    change_type, sqlValue(old_value), sqlValue(new_value),
    new Date().toISOString()
  );
}

function getChanges(db, targetId, { since, limit = 100 } = {}) {
  const conds = ["target_id = ?"];
  const params = [targetId];
  if (since) { conds.push("detected_at >= ?"); params.push(since); }
  return db.prepare(`
    SELECT * FROM domain_changes
    WHERE ${conds.join(" AND ")}
    ORDER BY detected_at DESC
    LIMIT ?
  `).all(...params, limit);
}

function startScanRun(db, targetId, runType) {
  const result = db.prepare(`
    INSERT INTO scan_runs (target_id, run_type, started_at, status)
    VALUES (?, ?, ?, 'running')
  `).run(targetId, runType, new Date().toISOString());
  return result.lastInsertRowid;
}

function finishScanRun(db, runId, { status = "completed", subdomains_found = 0,
  hosts_live = 0, hosts_interesting = 0, findings_count = 0 } = {}) {
  db.prepare(`
    UPDATE scan_runs SET
      finished_at       = ?,
      status            = ?,
      subdomains_found  = ?,
      hosts_live        = ?,
      hosts_interesting = ?,
      findings_count    = ?
    WHERE id = ?
  `).run(new Date().toISOString(), status,
    subdomains_found, hosts_live, hosts_interesting, findings_count, runId);
}

function getScanRuns(db, targetId, { limit = 20 } = {}) {
  return db.prepare(`
    SELECT * FROM scan_runs WHERE target_id = ?
    ORDER BY started_at DESC LIMIT ?
  `).all(targetId, limit);
}

function upsertCveTechMatch(db, targetId, subdomainId, data) {
  db.prepare(`
    INSERT INTO cve_tech_matches
      (target_id, subdomain_id, tech_name, tech_version, cve_id, cvss_score, notified, detected_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    ON CONFLICT(subdomain_id, cve_id) DO UPDATE SET
      cvss_score = excluded.cvss_score
  `).run(
    targetId, subdomainId,
    data.tech_name, sqlValue(data.tech_version),
    data.cve_id, sqlValue(data.cvss_score),
    new Date().toISOString()
  );
}

function getUnnotifiedCveMatches(db) {
  return db.prepare(`
    SELECT cm.*, s.subdomain, t.handle AS target_handle, t.program_url
    FROM cve_tech_matches cm
    JOIN subdomains s ON s.id = cm.subdomain_id
    JOIN targets_registry t ON t.id = cm.target_id
    WHERE cm.notified = 0
    ORDER BY cm.cvss_score DESC NULLS LAST, cm.detected_at DESC
  `).all();
}

// ── Operative identities ──────────────────────────────────────────────────────

function upsertIdentity(db, targetId, data) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO operative_identities
      (target_id, role, email, username, first_name, last_name,
       password_enc, birth_date, phone, extra_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(target_id, role) DO UPDATE SET
      email        = excluded.email,
      username     = excluded.username,
      first_name   = excluded.first_name,
      last_name    = excluded.last_name,
      password_enc = excluded.password_enc,
      birth_date   = excluded.birth_date,
      phone        = excluded.phone,
      extra_json   = excluded.extra_json
  `).run(
    targetId,
    data.role,
    data.email,
    data.username,
    data.first_name,
    data.last_name,
    data.password_enc,
    sqlValue(data.birth_date),
    sqlValue(data.phone),
    JSON.stringify(data.extra || {}),
    now
  );
  return db.prepare(
    "SELECT * FROM operative_identities WHERE target_id = ? AND role = ?"
  ).get(targetId, data.role);
}

function getIdentities(db, targetId) {
  return db.prepare(
    "SELECT * FROM operative_identities WHERE target_id = ? ORDER BY role"
  ).all(targetId).map((r) => ({ ...r, extra: JSON.parse(r.extra_json || "{}") }));
}

function getIdentity(db, targetId, role) {
  const r = db.prepare(
    "SELECT * FROM operative_identities WHERE target_id = ? AND role = ?"
  ).get(targetId, role);
  return r ? { ...r, extra: JSON.parse(r.extra_json || "{}") } : null;
}

// ── interactsh callbacks ──────────────────────────────────────────────────────

function recordCallback(db, data) {
  db.prepare(`
    INSERT INTO interactsh_callbacks
      (full_id, report_id, target_handle, protocol, source_ip,
       raw_request, raw_response, timestamp, notified)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
  `).run(
    data.full_id,
    sqlValue(data.report_id),
    sqlValue(data.target_handle),
    sqlValue(data.protocol),
    sqlValue(data.source_ip),
    sqlValue(data.raw_request),
    sqlValue(data.raw_response),
    data.timestamp || new Date().toISOString()
  );
}

function getCallbacks(db, { report_id, target_handle, since, limit = 100 } = {}) {
  const conds  = [];
  const params = [];
  if (report_id)     { conds.push("report_id = ?");     params.push(report_id); }
  if (target_handle) { conds.push("target_handle = ?"); params.push(target_handle); }
  if (since)         { conds.push("timestamp >= ?");    params.push(since); }
  const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
  return db.prepare(`
    SELECT * FROM interactsh_callbacks
    ${where}
    ORDER BY timestamp DESC LIMIT ?
  `).all(...params, limit);
}

function getUnnotifiedCallbacks(db) {
  return db.prepare(`
    SELECT * FROM interactsh_callbacks
    WHERE notified = 0
    ORDER BY timestamp DESC
  `).all();
}

function markCallbacksNotified(db, ids) {
  if (!ids.length) return;
  const ph = ids.map(() => "?").join(",");
  db.prepare(`UPDATE interactsh_callbacks SET notified = 1 WHERE id IN (${ph})`)
    .run(...ids);
}

function markCveMatchesNotified(db, ids) {
  if (!ids.length) return;
  const placeholders = ids.map(() => "?").join(",");
  db.prepare(`UPDATE cve_tech_matches SET notified = 1 WHERE id IN (${placeholders})`)
    .run(...ids);
}

// version and versionRange use COALESCE: if the new value is non-null it replaces the
// existing one; if null, the existing value is preserved. This means once a version is
// set it cannot be cleared by passing null — callers must use a DELETE+INSERT for that.
function upsertComponent(db, { targetId, name, version, versionRange, ecosystem, sourceFile, directDep }) {
  db.prepare(`
    INSERT INTO project_components
      (target_id, name, version, version_range, ecosystem, source_file, direct_dep, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    ON CONFLICT(target_id, name, ecosystem) DO UPDATE SET
      version       = COALESCE(excluded.version, version),
      version_range = COALESCE(excluded.version_range, version_range),
      source_file   = excluded.source_file,
      direct_dep    = excluded.direct_dep,
      last_seen     = excluded.last_seen
  `).run(targetId, name, version ?? null, versionRange ?? null, ecosystem, sourceFile, directDep ? 1 : 0);
}

function upsertEndpoint(db, { targetId, subdomainId, method, path, params, authRequired, authType, contentType, source, notes }) {
  db.prepare(`
    INSERT INTO endpoints
      (target_id, subdomain_id, method, path, params, auth_required, auth_type, content_type, source, notes, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    ON CONFLICT(target_id, method, path) DO UPDATE SET
      params       = excluded.params,
      auth_required = excluded.auth_required,
      auth_type    = excluded.auth_type,
      source       = excluded.source,
      notes        = COALESCE(excluded.notes, notes),
      last_seen    = excluded.last_seen
  `).run(
    targetId,
    subdomainId ?? null,
    (method || "GET").toUpperCase(),
    path,
    JSON.stringify(params || []),
    authRequired ? 1 : 0,
    authType ?? null,
    contentType ?? null,
    source || "surface_map",
    notes ?? null
  );
}

module.exports = {
  initDatabase,
  openDatabase,
  queryCveIntel,
  queryCalibrationDataset,
  queryReportBehaviors,
  querySkills,
  readDisclosedDatasetFromDb,
  readProgramIntelFromDb,
  replaceCveIntel,
  replaceCalibrationPatterns,
  replaceDisclosedReports,
  replaceReportBehaviors,
  replaceSkills,
  replaceProgramIntel,
  resolveDatabasePath,
  resolveGlobalDatabasePath,
  // operative identities
  upsertIdentity,
  getIdentities,
  getIdentity,
  // interactsh callbacks
  recordCallback,
  getCallbacks,
  getUnnotifiedCallbacks,
  markCallbacksNotified,
  // domains layer
  upsertTarget,
  getTarget,
  listTargets,
  touchTargetScanned,
  replaceScopeRules,
  getScopeRules,
  upsertSubdomain,
  getSubdomains,
  upsertTechnology,
  getTechByName,
  getTechSummary,
  upsertService,
  upsertEmailSecurity,
  recordChange,
  getChanges,
  startScanRun,
  finishScanRun,
  getScanRuns,
  upsertCveTechMatch,
  getUnnotifiedCveMatches,
  markCveMatchesNotified,
  // whitebox analysis layer
  upsertComponent,
  upsertEndpoint
};
