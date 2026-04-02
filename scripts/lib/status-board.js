"use strict";

/**
 * status-board.js — Live Pipeline Status Board
 *
 * Prints ANSI-rendered progress boards at key pipeline milestones.
 * Designed for sequential stage/domain execution (not parallel).
 *
 * Exports:
 *   printPipelineBoard(stages)         — stage progress (✓/⏱/○)
 *   printDomainBoard(domains, opts)    — domain research progress
 *   printStageTransition(label)        — separator between major stages
 *   writeDomainStatus(logsDir, agent, status) — write per-agent status JSON
 *   readDomainStatuses(logsDir)        — read all per-agent status JSONs
 */

const fs   = require("node:fs");
const path = require("node:path");

// ── ANSI ──────────────────────────────────────────────────────────────────────

const C = {
  reset:    "\x1b[0m",
  bold:     "\x1b[1m",
  dim:      "\x1b[2m",
  cyan:     "\x1b[36m",
  bcyan:    "\x1b[96m",
  magenta:  "\x1b[35m",
  bmagenta: "\x1b[95m",
  yellow:   "\x1b[33m",
  byellow:  "\x1b[93m",
  green:    "\x1b[32m",
  bgreen:   "\x1b[92m",
  red:      "\x1b[31m",
  bred:     "\x1b[91m",
  gray:     "\x1b[90m",
  white:    "\x1b[97m"
};

// Domain colors as per design spec
const DOMAIN_COLOR = {
  AUTH:   C.bcyan,
  INJECT: C.bred,
  CLIENT: C.bmagenta,
  ACCESS: C.byellow,
  MEDIA:  C.bgreen,
  INFRA:  C.cyan,
  CHAIN:  C.bold + C.bmagenta
};

const ALL_DOMAINS = ["AUTH", "INJECT", "CLIENT", "ACCESS", "MEDIA", "INFRA"];

// Stage icons
const ICON = {
  done:    C.bgreen  + "✓" + C.reset,
  running: C.yellow  + "⏱" + C.reset,
  pending: C.gray    + "○" + C.reset,
  skip:    C.gray    + "↷" + C.reset,
  fail:    C.bred    + "✗" + C.reset
};

function out(line = "") { process.stdout.write(line + "\n"); }

// ── Pipeline board ────────────────────────────────────────────────────────────

/**
 * Print the pipeline stage progress board.
 *
 * @param {Array<{label: string, status: "done"|"running"|"pending"|"skip"|"fail", detail?: string}>} stages
 */
function printPipelineBoard(stages) {
  const width = 70;
  const bar   = C.magenta + "─".repeat(width) + C.reset;

  out();
  out(bar);
  out(`${C.bold}${C.bmagenta}RESEARCHER v2 — PIPELINE STATUS${C.reset}`);
  out(bar);

  for (const s of stages) {
    const icon   = ICON[s.status] || ICON.pending;
    const label  = (s.label || "").padEnd(22);
    const detail = s.detail ? `${C.dim}  ${s.detail}${C.reset}` : "";
    out(`  ${icon}  ${C.bold}${label}${C.reset}${detail}`);
  }

  out(bar);
  out();
}

// ── Domain board ──────────────────────────────────────────────────────────────

/**
 * Print the domain research progress board.
 *
 * @param {object} opts
 * @param {string[]}  opts.done       — completed domain names
 * @param {string}    opts.running    — currently running domain (or null)
 * @param {string}    opts.target     — target name
 * @param {number}    opts.candidates — total candidates found so far
 * @param {number}    opts.confirmed  — total confirmed so far
 * @param {string}    opts.elapsed    — elapsed time string (e.g. "4m32s")
 * @param {object}    opts.statuses   — { DOMAIN: { tool_calls, message } }
 */
function printDomainBoard(opts = {}) {
  const {
    done       = [],
    running    = null,
    target     = "unknown",
    candidates = 0,
    confirmed  = 0,
    elapsed    = "?",
    statuses   = {}
  } = opts;

  const width = 70;
  const bar   = C.magenta + "═".repeat(width) + C.reset;
  const divider = C.magenta + "─".repeat(width) + C.reset;

  out();
  out(bar);
  out(`${C.bold}${C.bmagenta}RESEARCHER v2${C.reset} — target: ${C.bold}${target}${C.reset}  |  phase: ${C.cyan}deep research${C.reset}  |  elapsed: ${C.yellow}${elapsed}${C.reset}`);
  out(bar);

  for (const domain of ALL_DOMAINS) {
    const dc      = DOMAIN_COLOR[domain] || C.white;
    const isDone  = done.includes(domain);
    const isRunning = domain === running;
    const status  = statuses[domain] || {};
    const icon    = isDone ? ICON.done : isRunning ? ICON.running : ICON.pending;
    const calls   = status.tool_calls != null ? `${status.tool_calls} tool calls` : "";
    const msg     = status.message ? `${C.dim}${status.message.slice(0, 38)}${C.reset}` : "";
    const callStr = calls ? `${C.dim}${calls}${C.reset}  ` : "";
    out(`  ${icon}  ${dc}[${domain}]${C.reset}  ${callStr}${msg}`);
  }

  out(divider);
  out(`  Candidates so far: ${C.bold}${candidates}${C.reset}  |  Confirmed: ${C.bgreen}${confirmed}${C.reset}  |  Agents done: ${C.cyan}${done.length}/${ALL_DOMAINS.length}${C.reset}`);
  out(bar);
  out();
}

// ── Domain completion banner ──────────────────────────────────────────────────

/**
 * Print a completion banner for a single domain.
 *
 * @param {string}   domain        — domain name e.g. "CLIENT"
 * @param {object}   opts
 * @param {number}   opts.elapsed  — elapsed ms
 * @param {number}   opts.tool_calls
 * @param {number}   opts.candidates
 * @param {string[]} opts.vuln_classes — vuln class labels found
 */
function printDomainDone(domain, opts = {}) {
  const dc         = DOMAIN_COLOR[domain] || C.white;
  const elapsed    = opts.elapsed    != null ? formatMs(opts.elapsed) : "?";
  const toolCalls  = opts.tool_calls != null ? opts.tool_calls : "?";
  const candidates = opts.candidates != null ? opts.candidates : 0;
  const classes    = Array.isArray(opts.vuln_classes) ? opts.vuln_classes.join(", ") : "";

  out();
  out(`${C.bold}${C.bmagenta}╔${"═".repeat(54)}╗${C.reset}`);
  out(`${C.bold}${C.bmagenta}║${C.reset}  ${dc}[${domain}]${C.reset} ${ICON.done} ${C.bold}DONE${C.reset}  —  ${C.dim}${elapsed}  |  ${toolCalls} tool calls${C.reset}${" ".repeat(Math.max(0,16-elapsed.length))}${C.bmagenta}║${C.reset}`);
  if (candidates > 0 || classes) {
    const summary = `Candidates: ${candidates}${classes ? `  (${classes.slice(0,30)})` : ""}`;
    out(`${C.bold}${C.bmagenta}║${C.reset}  ${summary}${" ".repeat(Math.max(0, 52 - summary.length))}${C.bmagenta}║${C.reset}`);
  }
  out(`${C.bold}${C.bmagenta}╚${"═".repeat(54)}╝${C.reset}`);
  out();
}

// ── Stage transition ──────────────────────────────────────────────────────────

/**
 * Print a stage transition separator with label.
 *
 * @param {string} stage  — e.g. "STAGE 0 — File Triage"
 * @param {string} detail — optional detail line
 */
function printStageTransition(stage, detail = "") {
  const bar = C.cyan + "─".repeat(70) + C.reset;
  out();
  out(bar);
  out(`  ${C.bold}${C.cyan}${stage}${C.reset}${detail ? `  ${C.dim}${detail}${C.reset}` : ""}`);
  out(bar);
  out();
}

// ── Per-agent status files ────────────────────────────────────────────────────

/**
 * Write agent status JSON for live board consumption.
 *
 * @param {string} logsDir   — path to logs directory
 * @param {string} agent     — domain name e.g. "AUTH"
 * @param {object} status    — { tool_calls, message, candidates, started_at }
 */
function writeDomainStatus(logsDir, agent, status) {
  try {
    const agentsDir = path.join(logsDir, "agents");
    if (!fs.existsSync(agentsDir)) fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(
      path.join(agentsDir, `${agent.toLowerCase()}-status.json`),
      JSON.stringify({ agent, ...status, updated_at: new Date().toISOString() }),
      "utf8"
    );
  } catch { /* non-fatal */ }
}

/**
 * Read all per-agent status files from logsDir/agents/.
 *
 * @param {string} logsDir
 * @returns {object}  { DOMAIN: status }
 */
function readDomainStatuses(logsDir) {
  const result = {};
  try {
    const agentsDir = path.join(logsDir, "agents");
    if (!fs.existsSync(agentsDir)) return result;
    for (const f of fs.readdirSync(agentsDir)) {
      if (!f.endsWith("-status.json")) continue;
      try {
        const data = JSON.parse(fs.readFileSync(path.join(agentsDir, f), "utf8"));
        result[data.agent] = data;
      } catch { /* skip malformed */ }
    }
  } catch { /* non-fatal */ }
  return result;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatMs(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m${s % 60}s` : `${s}s`;
}

module.exports = {
  printPipelineBoard,
  printDomainBoard,
  printDomainDone,
  printStageTransition,
  writeDomainStatus,
  readDomainStatuses,
  DOMAIN_COLOR,
  ALL_DOMAINS
};
