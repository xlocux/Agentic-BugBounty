"use strict";

const fs   = require("node:fs");
const path = require("node:path");

/**
 * Persists all rejected candidates from candidates.json into the global
 * false_positive_registry table. Called once at the end of each researcher session.
 *
 * @param {object} globalDb     opened global DB (writeFpEntry lives here)
 * @param {string} findingsDir  path to the target's findings directory
 * @param {string} target       target name (for tagging FP entries)
 * @param {string} runId        unique run identifier (ISO timestamp or UUID)
 * @returns {number}            number of FP entries written
 */
function persistRejectedCandidates(globalDb, findingsDir, target, runId) {
  const { writeFpEntry } = require("./db");

  const candidatesPath = path.join(findingsDir, "unconfirmed", "candidates.json");
  if (!fs.existsSync(candidatesPath)) return 0;

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(candidatesPath, "utf8"));
  } catch {
    return 0;
  }

  const candidates = Array.isArray(parsed.candidates) ? parsed.candidates : [];
  const rejected   = candidates.filter(c => c.state === "rejected");
  let written = 0;

  for (const c of rejected) {
    try {
      writeFpEntry(globalDb, {
        vuln_class:       c.vuln_class  || "unknown",
        rejection_reason: c.false_positive_reason || extractGateReason(c) || "unspecified",
        detail:           buildDetail(c),
        target,
        run_id:           runId,
        file:             c.source?.file  ?? null,
        line:             c.source?.line  ?? null,
        agent:            c.agent         ?? null
      });
      written++;
    } catch { /* non-fatal — continue */ }
  }

  return written;
}

/**
 * Builds a detail string from gate/advocate data if rejection_reason is missing.
 * @param {object} c  candidate
 * @returns {string}
 */
function buildDetail(c) {
  const parts = [];

  // Skepticism gate — which check failed?
  if (c.skepticism_gate) {
    for (const [check, result] of Object.entries(c.skepticism_gate)) {
      if (result === "fail") parts.push(`gate_fail:${check}`);
    }
  }

  // Devil's advocate verdict
  if (c.devil_advocate?.verdict === "needs_evidence") {
    parts.push("devil_advocate_not_rebutted");
  }

  // Source info
  if (c.source?.file) parts.push(`file:${c.source.file}:${c.source.line || "?"}`);

  return parts.join("; ") || null;
}

/**
 * Extracts a rejection reason from the skepticism gate data.
 * @param {object} c  candidate
 * @returns {string|null}
 */
function extractGateReason(c) {
  if (!c.skepticism_gate) return null;
  for (const [check, result] of Object.entries(c.skepticism_gate)) {
    if (result === "fail") return check;
  }
  return null;
}

/**
 * Loads known FP patterns for a given vuln class.
 * Returns a formatted context string for injection into researcher prompt.
 *
 * @param {object} globalDb
 * @param {string} vulnClass
 * @returns {string}   empty string if no patterns found
 */
function buildFpContext(globalDb, vulnClass) {
  const { readFpPatterns } = require("./db");
  let patterns;
  try {
    patterns = readFpPatterns(globalDb, vulnClass, 10);
  } catch {
    return "";
  }

  if (!patterns || patterns.length === 0) return "";

  const lines = patterns.map(p =>
    `  - [x${p.count}] ${p.rejection_reason}${p.detail ? `: ${p.detail}` : ""}`
  ).join("\n");

  return `\nKNOWN FALSE POSITIVE PATTERNS for ${vulnClass}:\n${lines}\n`;
}

module.exports = { persistRejectedCandidates, buildFpContext };
