"use strict";

/**
 * pipeline-sync.js
 * Reads per-target JSON output files and syncs them into the global SQLite DB.
 * Call syncTarget(name) after a pipeline run, or syncAll() on server startup.
 */

const path = require("node:path");
const fs   = require("node:fs");

const {
  openDatabase,
  resolveGlobalDatabasePath,
  upsertTarget,
  upsertFinding,
} = require("./db");

function readJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { return null; }
}

/**
 * Sync one target's JSON output files → global DB.
 * Returns { targetId, confirmed, candidates, errors[] }
 */
function syncTarget(targetName) {
  const dbPath    = resolveGlobalDatabasePath();
  const db        = openDatabase(dbPath);
  const targetDir = path.resolve("targets", targetName);
  const errors    = [];
  let confirmed   = 0;
  let candidates  = 0;

  try {
    // 1. Upsert target into registry
    const targetJson = readJson(path.join(targetDir, "target.json")) || {};
    const tRec = upsertTarget(db, {
      handle:      targetName,
      platform:    "hackerone",
      program_url: targetJson.program_url || null,
    });
    const targetId = tRec.id;

    // 2. Confirmed findings from report_bundle.json
    const bundle = readJson(path.join(targetDir, "findings", "confirmed", "report_bundle.json"));
    if (bundle?.findings) {
      for (const f of bundle.findings) {
        try {
          upsertFinding(db, {
            targetId,
            reportId:         f.id,
            vulnClass:        f.vuln_class || f.type || "unknown",
            severity:         (f.severity || "info").toLowerCase(),
            title:            f.title || "",
            affectedComponent: f.affected_component || f.endpoint || null,
            status:           "confirmed",
            discoveredAt:     f.created_at || bundle.meta?.generated_at || null,
          });
          confirmed++;
        } catch (e) { errors.push(`finding ${f.id}: ${e.message}`); }
      }
    }

    // 3. Candidates (unconfirmed) from all pool files
    for (const agent of ["auth", "inject", "client", "access", "media", "infra"]) {
      const pool = readJson(path.join(targetDir, "findings", `candidates_pool_${agent}.json`));
      if (!pool?.candidates) continue;
      for (const c of pool.candidates) {
        try {
          upsertFinding(db, {
            targetId,
            reportId:         c.id,
            vulnClass:        c.vuln_class || "unknown",
            severity:         (c.severity || "info").toLowerCase(),
            title:            c.title || "",
            affectedComponent: c.sink?.file || c.source?.file || null,
            status:           "unconfirmed",
            discoveredAt:     pool.generated_at || null,
          });
          candidates++;
        } catch (e) { errors.push(`candidate ${c.id}: ${e.message}`); }
      }
    }

    return { targetId, confirmed, candidates, errors };
  } finally {
    db.close();
  }
}

/**
 * Sync all targets found in targets/ directory.
 * Returns array of per-target results.
 */
function syncAll() {
  const targetsDir = path.resolve("targets");
  let entries = [];
  try {
    entries = fs.readdirSync(targetsDir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch { return []; }

  return entries.map((name) => {
    try {
      return { name, ...syncTarget(name), ok: true };
    } catch (err) {
      return { name, ok: false, error: err.message };
    }
  });
}

module.exports = { syncTarget, syncAll };
