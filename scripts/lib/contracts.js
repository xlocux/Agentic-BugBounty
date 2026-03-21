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
  readDisclosedDatasetFromDb,
  readProgramIntelFromDb,
  replaceDisclosedReports,
  replaceProgramIntel,
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
  writeJson,
  writeProgramIntel
};
