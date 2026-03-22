"use strict";

// Backward-compatible re-export barrel.
// New code should import directly from the focused sub-modules:
//   - constants.js  — shared enums and regex
//   - io.js         — readJson, writeJson, ensureDir, resolveTargetConfigPath
//   - validators.js — validateBundle, validateTargetConfig, validateTriageResult
//   - triage.js     — triageBundle (includes H1 universal rules)
//   - render.js     — renderH1ReportMarkdown
const {
  deriveProgramHandle,
  readJson,
  writeJson,
  ensureDir,
  resolveTargetConfigPath
} = require("./io");
const {
  initDatabase,
  openDatabase,
  queryCveIntel,
  querySkills,
  readDisclosedDatasetFromDb,
  readProgramIntelFromDb,
  replaceCveIntel,
  replaceDisclosedReports,
  replaceProgramIntel,
  replaceSkills,
  resolveDatabasePath,
  resolveGlobalDatabasePath
} = require("./db");
const { validateBundle, validateTargetConfig, validateTriageResult } = require("./validators");
const {
  loadDisclosedDataset,
  loadProgramIntel,
  persistDisclosedDataset,
  persistProgramIntel,
  syncGlobalDisclosedReports,
  syncProgramIntel,
  writeProgramIntel
} = require("./hackerone");
const { buildResearchBrief } = require("./research");
const { triageBundle } = require("./triage");
const { renderH1ReportMarkdown } = require("./render");
const {
  fetchAllPrograms,
  fetchProgramScope,
  persistBbscopeIntel,
  syncBbscopeProgramIntel,
  PLATFORM_LABELS
} = require("./bbscope");

/**
 * Persist any researcher-extracted skills from a report bundle into skill_library.
 * Receives an already-open db handle — caller manages open/close.
 * Returns the number of skills saved.
 */
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

module.exports = {
  buildResearchBrief,
  deriveProgramHandle,
  fetchAllPrograms,
  fetchProgramScope,
  persistBbscopeIntel,
  syncBbscopeProgramIntel,
  PLATFORM_LABELS,
  ensureDir,
  initDatabase,
  loadDisclosedDataset,
  loadProgramIntel,
  openDatabase,
  persistDisclosedDataset,
  persistProgramIntel,
  readJson,
  readDisclosedDatasetFromDb,
  readProgramIntelFromDb,
  renderH1ReportMarkdown,
  replaceDisclosedReports,
  replaceProgramIntel,
  resolveTargetConfigPath,
  resolveDatabasePath,
  resolveGlobalDatabasePath,
  syncGlobalDisclosedReports,
  syncProgramIntel,
  triageBundle,
  validateBundle,
  validateTargetConfig,
  validateTriageResult,
  queryCveIntel,
  querySkills,
  replaceCveIntel,
  replaceSkills,
  persistExtractedSkills,
  writeJson,
  writeProgramIntel
};
