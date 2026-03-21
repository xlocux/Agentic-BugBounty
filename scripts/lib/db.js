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
  return db;
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
      url TEXT
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
      severity_rating, weakness, cwe, disclosed_at, created_at, url
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        sqlValue(report.url)
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

module.exports = {
  initDatabase,
  openDatabase,
  readDisclosedDatasetFromDb,
  readProgramIntelFromDb,
  replaceDisclosedReports,
  replaceProgramIntel,
  resolveDatabasePath,
  resolveGlobalDatabasePath
};
