"use strict";

/**
 * bbscope.js
 *
 * Client for the bbscope public API (https://bbscope.com/api/v1).
 * No authentication required.
 *
 * Fetches scope data for a specific program or the full program list,
 * normalizes the output to match the existing structured_scopes schema,
 * and persists everything into the same agentic-bugbounty.db used by H1.
 */

const https = require("node:https");
const path = require("node:path");
const {
  initDatabase,
  openDatabase,
  resolveDatabasePath
} = require("./db");
const { ensureDir, writeJson } = require("./io");

const API_BASE_URL = "https://bbscope.com/api/v1";

// bbscope platform codes → human label
const PLATFORM_LABELS = {
  h1: "HackerOne",
  bc: "Bugcrowd",
  it: "Intigriti",
  ywh: "YesWeHack"
};

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

function requestJson(pathname, searchParams = {}) {
  const url = new URL(pathname, API_BASE_URL);
  url.searchParams.set("format", "json");
  for (const [key, value] of Object.entries(searchParams)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }

  return new Promise((resolve, reject) => {
    const req = https.request(
      url,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          "User-Agent": "Agentic-BugBounty/0.1"
        }
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => { body += chunk; });
        res.on("end", () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`bbscope API request failed (${res.statusCode}): ${body.slice(0, 500)}`));
            return;
          }
          try {
            resolve(JSON.parse(body));
          } catch (err) {
            reject(new Error(`Failed to parse bbscope response: ${err.message}`));
          }
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}

// ─── Normalization ────────────────────────────────────────────────────────────

/**
 * Normalize a bbscope scope target into the structured_scopes schema.
 * bbscope returns targets with fields: target, type, platform, program, in_scope, max_severity
 */
function normalizeScopeTarget(item, programHandle, platform) {
  // bbscope target types map roughly to H1 asset_type names
  const typeMap = {
    url:      "URL",
    wildcard: "WILDCARD",
    domain:   "WILDCARD",
    ip:       "IP_ADDRESS",
    cidr:     "CIDR",
    android:  "GOOGLE_PLAY_APP_ID",
    ios:      "APPLE_STORE_APP_ID",
    other:    "OTHER"
  };

  const rawType = (item.type || "other").toLowerCase();
  const assetType = typeMap[rawType] || item.type || "OTHER";
  const identifier = item.target || item.asset_identifier || null;

  return {
    id: `bbscope:${platform}:${programHandle}:${identifier || Math.random().toString(36).slice(2)}`,
    program_handle: programHandle,
    asset_type: assetType,
    asset_identifier: identifier,
    instruction: item.instruction || null,
    eligible_for_submission: item.in_scope !== false,
    max_severity: item.max_severity || null,
    created_at: null,
    updated_at: null,
    source: `bbscope_${platform}`
  };
}

// ─── API calls ────────────────────────────────────────────────────────────────

/**
 * Fetch all programs from bbscope (optionally filtered by platform).
 * Returns array of program objects: { handle, name, platform, url, type }
 */
async function fetchAllPrograms(options = {}) {
  const params = {};
  if (options.platform) params.platform = options.platform;
  if (options.type) params.type = options.type;

  const data = await requestJson("/programs", params);
  // bbscope returns array of program objects
  const programs = Array.isArray(data) ? data : (data.programs || data.data || []);
  return programs;
}

/**
 * Fetch in-scope targets for a specific program.
 * platform: h1 | bc | it | ywh
 * handle: program handle/slug
 */
async function fetchProgramScope(platform, handle, options = {}) {
  const scopeParam = options.scope || "in";
  const data = await requestJson(`/programs/${platform}/${handle}`, { scope: scopeParam });

  // Response may be { targets: [...] } or a flat array
  const targets = Array.isArray(data) ? data : (data.targets || data.in_scope || data.data || []);
  return targets.map((item) => normalizeScopeTarget(item, handle, platform));
}

/**
 * Fetch scope updates with optional time range.
 * Returns paginated list of scope changes.
 */
async function fetchScopeUpdates(options = {}) {
  const params = {};
  if (options.since) params.since = options.since;
  if (options.until) params.until = options.until;
  if (options.page) params.page = options.page;
  if (options.perPage) params.per_page = options.perPage;
  if (options.platform) params.platform = options.platform;

  const data = await requestJson("/updates", params);
  return Array.isArray(data) ? data : (data.updates || data.data || []);
}

// ─── Sync ─────────────────────────────────────────────────────────────────────

/**
 * Sync scope for a specific program from bbscope.
 * Returns intel object compatible with persistProgramIntel structure.
 */
async function syncBbscopeProgramIntel(platform, handle, options = {}) {
  const scopes = await fetchProgramScope(platform, handle, options);

  return {
    meta: {
      program_handle: handle,
      platform,
      platform_label: PLATFORM_LABELS[platform] || platform,
      synced_at: new Date().toISOString(),
      source: "bbscope",
      sources: {
        scopes: scopes.length,
        hacktivity: 0,
        reports: 0
      }
    },
    scopes,
    history: [],
    skill_suggestions: []
  };
}

// ─── Persistence ──────────────────────────────────────────────────────────────

/**
 * Write bbscope scope snapshot JSON and persist scopes into the shared DB.
 * Scopes are written with source = 'bbscope_<platform>' so they coexist with H1 scopes.
 */
function persistBbscopeIntel(targetConfig, intelligenceDir, intel) {
  ensureDir(intelligenceDir);

  // JSON snapshot
  writeJson(path.join(intelligenceDir, "bbscope_scope_snapshot.json"), {
    meta: intel.meta,
    scopes: intel.scopes
  });

  // Persist into shared SQLite DB
  const dbPath = resolveDatabasePath(intelligenceDir);
  const db = openDatabase(dbPath);
  initDatabase(db);
  upsertBbscopeScopes(db, targetConfig, intel);
  db.close();

  return dbPath;
}

function upsertBbscopeScopes(db, targetConfig, intel) {
  // Ensure source column exists (migration for existing DBs)
  try {
    db.exec("ALTER TABLE structured_scopes ADD COLUMN source TEXT");
  } catch {
    // Column already exists — ignore
  }

  const upsertProgram = db.prepare(`
    INSERT INTO programs (program_handle, target_name, asset_type, program_url, last_synced_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(program_handle) DO UPDATE SET
      target_name = excluded.target_name,
      asset_type = excluded.asset_type,
      program_url = excluded.program_url,
      last_synced_at = excluded.last_synced_at
  `);

  const clearScopes = db.prepare(
    "DELETE FROM structured_scopes WHERE program_handle = ? AND (source LIKE 'bbscope%' OR source IS NULL)"
  );

  const insertScope = db.prepare(`
    INSERT OR REPLACE INTO structured_scopes (
      id, program_handle, asset_type, asset_identifier, instruction,
      eligible_for_submission, max_severity, created_at, updated_at, source
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertSyncRun = db.prepare(`
    INSERT INTO sync_runs (program_handle, synced_at, scope_count, hacktivity_count, report_count)
    VALUES (?, ?, ?, ?, ?)
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

    clearScopes.run(intel.meta.program_handle);

    for (const scope of intel.scopes) {
      insertScope.run(
        scope.id,
        intel.meta.program_handle,
        scope.asset_type || null,
        scope.asset_identifier || null,
        scope.instruction || null,
        scope.eligible_for_submission === false ? 0 : 1,
        scope.max_severity || null,
        scope.created_at || null,
        scope.updated_at || null,
        scope.source || `bbscope_${intel.meta.platform}`
      );
    }

    insertSyncRun.run(
      intel.meta.program_handle,
      intel.meta.synced_at,
      intel.scopes.length,
      0,
      0
    );

    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

module.exports = {
  fetchAllPrograms,
  fetchProgramScope,
  fetchScopeUpdates,
  persistBbscopeIntel,
  syncBbscopeProgramIntel,
  PLATFORM_LABELS
};
