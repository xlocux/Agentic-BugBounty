"use strict";

const fs   = require("node:fs");
const path = require("node:path");

const AGENTS = ["auth", "inject", "client", "access", "media", "infra", "git_intel"];

/**
 * Returns the path for an agent's shard file.
 * @param {string} findingsDir  e.g. "findings/"
 * @param {string} agent        one of AGENTS
 */
function shardPath(findingsDir, agent) {
  if (!AGENTS.includes(agent)) throw new Error(`Unknown agent: ${agent}`);
  return path.join(findingsDir, `candidates_pool_${agent}.json`);
}

/**
 * Reads an agent's shard, returning an empty pool if not found.
 * @param {string} findingsDir
 * @param {string} agent
 * @returns {object} parsed candidates pool
 */
function readShard(findingsDir, agent) {
  const p = shardPath(findingsDir, agent);
  if (!fs.existsSync(p)) {
    return { schema_version: 2, generated_at: new Date().toISOString(), target: "", candidates: [] };
  }
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

/**
 * Writes (replaces) an agent's shard atomically via temp file + rename.
 * @param {string} findingsDir
 * @param {string} agent
 * @param {object} pool
 */
function writeShard(findingsDir, agent, pool) {
  const p   = shardPath(findingsDir, agent);
  const tmp = p + ".tmp";
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(pool, null, 2), "utf8");
  fs.renameSync(tmp, p);
}

/**
 * Merges all agent shards into a single candidates pool.
 * Deduplicates by candidate ID. Last write wins on conflict.
 * @param {string} findingsDir
 * @returns {object} merged candidates pool
 */
function mergeShards(findingsDir) {
  const seen = new Map();
  let target = "";
  for (const agent of AGENTS) {
    const shard = readShard(findingsDir, agent);
    if (shard.target) target = shard.target;
    for (const candidate of shard.candidates) {
      seen.set(candidate.id, candidate);
    }
  }
  return {
    schema_version: 2,
    generated_at:   new Date().toISOString(),
    target,
    candidates:     [...seen.values()]
  };
}

/**
 * Lists all shard files that currently exist.
 * @param {string} findingsDir
 * @returns {string[]} agent names with existing shards
 */
function listShards(findingsDir) {
  return AGENTS.filter(agent => fs.existsSync(shardPath(findingsDir, agent)));
}

module.exports = { shardPath, readShard, writeShard, mergeShards, listShards, AGENTS };
