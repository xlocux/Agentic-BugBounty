"use strict";

const fs   = require("node:fs");
const path = require("node:path");

/**
 * Resolves a logical role name to a concrete model ID.
 *
 * Roles used in all prompts and orchestration:
 *   "researcher"  — deep reasoning agent (Opus class)
 *   "coordinator" — chain analysis coordinator (Opus class)
 *   "triage"      — mechanical triage / surface mapping (cheap model)
 *
 * Never hardcode model IDs in prompts. Always go through this adapter
 * so provider/model swaps require only a config change.
 */

function loadConfig() {
  const configPath = process.env.APIS_CONFIG_PATH
    || path.resolve(__dirname, "../../config/apis.json");
  return JSON.parse(fs.readFileSync(configPath, "utf8"));
}

function resolveModel(role) {
  const config      = loadConfig();
  const assignments = config.model_assignments || {};
  if (!Object.prototype.hasOwnProperty.call(assignments, role)) {
    throw new Error(`model-adapter: unknown role "${role}". Known roles: ${Object.keys(assignments).join(", ")}`);
  }
  return assignments[role];
}

function listRoles() {
  const config = loadConfig();
  return Object.keys(config.model_assignments || {});
}

module.exports = { resolveModel, listRoles };
