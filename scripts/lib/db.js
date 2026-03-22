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
  // Add asset_type and vuln_class columns to disclosed_reports if they don't exist
  const columns = db
    .prepare("PRAGMA table_info(disclosed_reports)")
    .all()
    .map((c) => c.name);

  if (!columns.includes("asset_type")) {
    db.exec("ALTER TABLE disclosed_reports ADD COLUMN asset_type TEXT");
  }
  if (!columns.includes("vuln_class")) {
    db.exec("ALTER TABLE disclosed_reports ADD COLUMN vuln_class TEXT");
  }
  if (!columns.includes("hacktivity_summary")) {
    db.exec("ALTER TABLE disclosed_reports ADD COLUMN hacktivity_summary TEXT");
  }
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
  resolveGlobalDatabasePath
};
