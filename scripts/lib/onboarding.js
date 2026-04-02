"use strict";

/**
 * onboarding.js — Phase 0 Smart Onboarding
 *
 * Displays all available intel (scope, H1 history, CVE intel, skills),
 * then asks the minimal set of adaptive questions needed to configure
 * the research session. Returns a sessionConfig object.
 *
 * Called by run-pipeline.js when --interactive is set on a fresh run.
 */

const fs       = require("node:fs");
const path     = require("node:path");
const readline = require("node:readline");

// ── ANSI helpers ──────────────────────────────────────────────────────────────

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

const BAR_DOUBLE  = C.bmagenta + "══════════════════════════════════════════════════════════════════════" + C.reset;
const BAR_SINGLE  = C.magenta  + "──────────────────────────────────────────────────────────────────────" + C.reset;

function out(line = "") { process.stdout.write(line + "\n"); }
function header(title) {
  out(BAR_DOUBLE);
  out(`${C.bold}${C.bmagenta}${title}${C.reset}`);
  out(BAR_DOUBLE);
}

// ── Readline helper ───────────────────────────────────────────────────────────

function ask(rl, question, defaultVal = "") {
  return new Promise(resolve => {
    const suffix = defaultVal ? ` ${C.dim}[${defaultVal}]${C.reset}` : "";
    rl.question(`${C.byellow}?${C.reset} ${question}${suffix} › `, (ans) => {
      resolve(ans.trim() || defaultVal);
    });
  });
}

function askChoice(rl, question, choices, defaultKey) {
  const choiceStr = choices.map(c =>
    c.key === defaultKey
      ? `${C.bgreen}[${c.key}]${C.reset} ${c.label}`
      : `${C.dim}[${c.key}]${C.reset} ${c.label}`
  ).join("  ");
  return new Promise(resolve => {
    rl.question(`${C.byellow}?${C.reset} ${question}\n    ${choiceStr}\n  › `, (ans) => {
      const key = ans.trim().toUpperCase() || defaultKey;
      const match = choices.find(c => c.key === key);
      resolve(match ? match.key : defaultKey);
    });
  });
}

// ── Intel loading ─────────────────────────────────────────────────────────────

function loadIntel(context) {
  let scope       = null;
  let h1History   = null;
  let cveIntel    = null;
  let skillCount  = 0;
  let programHandle = null;

  try {
    const {
      openDatabase, resolveGlobalDatabasePath,
      readProgramIntelFromDb, queryCveIntel, querySkills
    } = require("./db");

    const globalDb = openDatabase(resolveGlobalDatabasePath());

    // Derive program handle from target config
    const targetConfig = context.config;
    programHandle = targetConfig?.hackerone?.handle || targetConfig?.program_handle || null;

    if (programHandle) {
      try {
        const intel = readProgramIntelFromDb(globalDb, programHandle);
        if (intel) {
          scope     = intel.scopes    || [];
          h1History = intel.history   || [];
        }
      } catch { /* non-fatal */ }
    }

    try {
      cveIntel = queryCveIntel(globalDb, context.targetRef || context.target, { limit: 10 });
    } catch { /* non-fatal */ }

    try {
      const skills = querySkills(globalDb, { asset_type: context.asset, limit: 50 });
      skillCount = skills.length;
    } catch { /* non-fatal */ }

    globalDb.close();
  } catch { /* non-fatal — no DB available */ }

  return { scope, h1History, cveIntel, skillCount, programHandle };
}

// ── Intel display ─────────────────────────────────────────────────────────────

function displayIntelBrief(context, intel) {
  const target  = context.targetRef || context.target || "unknown";
  const version = context.config?.version || null;

  out();
  header(`NETRUNNER INTERFACE — ${C.white}${target}${C.bmagenta}${version ? ` v${version}` : ""}`);
  out(`${C.dim}Loading street intel...${C.reset}`);
  out(BAR_SINGLE);
  out();

  // ── SCOPE ──────────────────────────────────────────────────────────────────
  out(`${C.bold}${C.cyan}SCOPE${C.reset}`);
  if (intel.scope && intel.scope.length > 0) {
    const inScope  = intel.scope.filter(s => s.type !== "excluded" && s.instruction !== "Excluded");
    const outScope = intel.scope.filter(s => s.type === "excluded" || s.instruction === "Excluded");
    if (inScope.length > 0) {
      out(`  ${C.bgreen}In scope:${C.reset}`);
      for (const s of inScope.slice(0, 8)) {
        out(`    ${C.green}✓${C.reset} ${s.asset_identifier || s.pattern || s.entity_type}`);
      }
      if (inScope.length > 8) out(`    ${C.dim}…and ${inScope.length - 8} more${C.reset}`);
    }
    if (outScope.length > 0) {
      out(`  ${C.bred}Out of scope:${C.reset}`);
      for (const s of outScope.slice(0, 4)) {
        out(`    ${C.red}✗${C.reset} ${s.asset_identifier || s.pattern || s.entity_type}`);
      }
    }
  } else {
    out(`  ${C.dim}NOT AVAILABLE — run: node scripts/sync-program-scope.js${C.reset}`);
  }
  out();

  // ── H1 HISTORY ─────────────────────────────────────────────────────────────
  out(`${C.bold}${C.cyan}DISCLOSED REPORTS (HackerOne)${C.reset}`);
  if (intel.h1History && intel.h1History.length > 0) {
    const hist = intel.h1History;
    const bySeverity = {};
    for (const h of hist) {
      const sev = (h.severity_rating || "unknown").toLowerCase();
      bySeverity[sev] = (bySeverity[sev] || 0) + 1;
    }
    out(`  Total: ${C.bold}${hist.length}${C.reset}  |  ` +
      Object.entries(bySeverity)
        .sort((a,b) => ["critical","high","medium","low","informative"].indexOf(a[0]) - ["critical","high","medium","low","informative"].indexOf(b[0]))
        .map(([sev, cnt]) => `${_sevColor(sev)}${sev}: ${cnt}${C.reset}`)
        .join("  "));
    // Top vuln classes
    const byClass = {};
    for (const h of hist) {
      const cls = (h.weakness || h.cwe || "unknown").toLowerCase().split(":")[0].trim();
      byClass[cls] = (byClass[cls] || 0) + 1;
    }
    const topClasses = Object.entries(byClass)
      .sort((a,b) => b[1] - a[1])
      .slice(0, 5)
      .map(([cls, cnt]) => `${cls} (${cnt})`)
      .join(", ");
    if (topClasses) out(`  Top classes: ${C.yellow}${topClasses}${C.reset}`);
    // Most recent
    const recent = [...hist].sort((a,b) => (b.disclosed_at||"").localeCompare(a.disclosed_at||"")).slice(0, 2);
    for (const r of recent) {
      out(`  Recent: ${C.dim}${r.title?.slice(0, 60) || "?"} — ${r.disclosed_at?.slice(0,10) || "?"} — ${r.severity_rating || "?"}${C.reset}`);
    }
  } else {
    out(`  ${C.dim}NOT AVAILABLE — run: node scripts/sync-hackerone-disclosed.js${C.reset}`);
  }
  out();

  // ── CVE INTEL ──────────────────────────────────────────────────────────────
  out(`${C.bold}${C.cyan}CVE INTEL${C.reset}`);
  if (intel.cveIntel && intel.cveIntel.length > 0) {
    for (const cve of intel.cveIntel.slice(0, 4)) {
      const cvss = cve.cvss_score ? ` (CVSS ${cve.cvss_score})` : "";
      out(`  ${C.bred}${cve.cve_id}${cvss}${C.reset} — ${(cve.description || "").slice(0, 80)}`);
    }
    if (intel.cveIntel.length > 4) out(`  ${C.dim}…and ${intel.cveIntel.length - 4} more${C.reset}`);
  } else {
    out(`  ${C.dim}NONE FOUND${C.reset}`);
  }
  out();

  // ── SKILL LIBRARY ──────────────────────────────────────────────────────────
  out(`${C.bold}${C.cyan}SKILL LIBRARY${C.reset}`);
  if (intel.skillCount > 0) {
    out(`  ${C.bgreen}${intel.skillCount} technique(s)${C.reset} available for ${context.asset}`);
  } else {
    out(`  ${C.dim}No skills loaded yet${C.reset}`);
  }
  out();
  out(BAR_DOUBLE);
  out();
}

function _sevColor(sev) {
  const m = { critical: C.bred, high: C.red, medium: C.yellow, low: C.cyan, informative: C.dim };
  return m[sev] || C.gray;
}

// ── Interactive Q&A ────────────────────────────────────────────────────────────

async function runInteractiveQuestions(rl, context, intel) {
  const session = {
    scope_confirmed: false,
    scope_manual:    null,
    version:         context.config?.version || null,
    environment:     "static",   // "live" | "auto" | "static"
    base_url:        null,
    admin_url:       null,
    credentials:     null,
    focus:           "full",     // "full" | custom string
    extra_context:   null,
    cve_priority:    false
  };

  out(`${C.bold}${C.bmagenta}PHASE 0 — ADAPTIVE QUESTIONS${C.reset}`);
  out(`${C.dim}Only asking what's missing or needs confirmation.${C.reset}`);
  out();

  // ── Q-SCOPE ────────────────────────────────────────────────────────────────
  if (intel.scope && intel.scope.length > 0) {
    const inScope = intel.scope.filter(s => s.type !== "excluded").map(s => s.asset_identifier).slice(0,4).join(", ");
    const ans = await askChoice(rl,
      `Got your scope from bbscope (${inScope}…). Correct?`,
      [{ key: "Y", label: "Yes, confirmed" }, { key: "N", label: "No, describe manually" }],
      "Y"
    );
    session.scope_confirmed = (ans === "Y");
    if (!session.scope_confirmed) {
      session.scope_manual = await ask(rl, "Describe your scope (comma-separated domains/IPs):", "");
    }
  } else {
    out(`  ${C.dim}No scope synced.${C.reset}`);
    session.scope_manual = await ask(rl, "Paste a scope URL or describe it manually:", "");
    session.scope_confirmed = false;
  }
  out();

  // ── Q-VERSION ──────────────────────────────────────────────────────────────
  if (context.config?.version) {
    const ans = await askChoice(rl,
      `Intel says we're looking at v${context.config.version}. Confirm?`,
      [{ key: "Y", label: "Yes" }, { key: "N", label: "Different version" }],
      "Y"
    );
    if (ans !== "Y") {
      session.version = await ask(rl, "Enter the correct version:", "");
    }
  } else {
    session.version = await ask(rl, "What version is this target? (optional, press Enter to skip):", "");
  }
  out();

  // ── Q-FOCUS ────────────────────────────────────────────────────────────────
  if (intel.h1History && intel.h1History.length > 0) {
    const byClass = {};
    for (const h of intel.h1History) {
      const cls = (h.weakness || h.cwe || "?").toLowerCase().split(":")[0].trim().slice(0, 20);
      byClass[cls] = (byClass[cls] || 0) + 1;
    }
    const top = Object.entries(byClass).sort((a,b) => b[1]-a[1]).slice(0,3).map(([c]) => c).join(", ");
    out(`  ${C.dim}H1 history shows ${top} hit most often. I'll cover every class regardless.${C.reset}`);
    const ans = await ask(rl, "Any specific areas to dig into first? (Enter to use H1 signal ordering):", "");
    session.focus = ans || "h1_signal";
  } else {
    const ans = await ask(rl, "Any specific vuln classes or areas to prioritize? (Enter for full coverage):", "");
    session.focus = ans || "full";
  }
  out();

  // ── Q-CVE ─────────────────────────────────────────────────────────────────
  if (intel.cveIntel && intel.cveIntel.length > 0) {
    const ans = await askChoice(rl,
      `Found ${intel.cveIntel.length} CVE(s) for this target. Include as priority candidates?`,
      [{ key: "Y", label: "Yes" }, { key: "N", label: "No" }],
      "Y"
    );
    session.cve_priority = (ans === "Y");
    out();
  }

  // ── Q-ENVIRONMENT ─────────────────────────────────────────────────────────
  const envAns = await askChoice(rl,
    "Got a live test environment?",
    [
      { key: "A", label: "Yes — I'll provide the URL and creds now" },
      { key: "B", label: "No — static analysis only (all findings → unconfirmed)" },
      { key: "C", label: "No — auto-setup (read official docs)" }
    ],
    "B"
  );
  out();

  if (envAns === "A") {
    session.environment = "live";
    session.base_url    = await ask(rl, "Base URL (e.g. http://localhost:8080):", "");
    session.admin_url   = await ask(rl, "Admin URL (or press Enter to skip):", "");
    const hasCreds = context.config?.credentials;
    if (hasCreds) {
      out(`  ${C.dim}Credentials loaded from target.json.${C.reset}`);
      session.credentials = hasCreds;
    } else {
      const creds = await ask(rl, "Test credentials (admin user:pass, user user:pass, or Enter to skip):", "");
      session.credentials = creds || null;
    }
    out();
  } else if (envAns === "C") {
    session.environment = "auto";
  } else {
    session.environment = "static";
    out(`  ${C.dim}Static-only mode. All live-dependent findings will stay unconfirmed.${C.reset}`);
  }

  // ── Q-EXTRA ───────────────────────────────────────────────────────────────
  const extra = await ask(rl, "Anything the intel doesn't know? Suspicious areas, recent fixes, quirks? (Enter to skip):", "");
  session.extra_context = extra || null;
  out();

  return session;
}

// ── Session summary ───────────────────────────────────────────────────────────

async function displaySessionSummary(rl, context, session) {
  const target  = context.targetRef || context.target || "unknown";
  const version = session.version ? ` v${session.version}` : "";
  const envLabel = { live: "live test env (user-provided)", auto: "auto-setup", static: "static analysis only" };

  out(BAR_SINGLE);
  out(`${C.bold}${C.bmagenta}╔${"═".repeat(56)}╗${C.reset}`);
  out(`${C.bold}${C.bmagenta}║${C.reset}  ${C.white}${C.bold}RESEARCH SESSION — ${target}${version}${" ".repeat(Math.max(0, 33 - (target + version).length))}${C.reset}${C.bmagenta}║${C.reset}`);
  out(`${C.bold}${C.bmagenta}║${C.reset}                                                          ${C.bmagenta}║${C.reset}`);
  _summaryLine("Environment",
    session.environment === "live"   ? `${C.bgreen}${envLabel.live}${C.reset}` :
    session.environment === "auto"   ? `${C.yellow}${envLabel.auto}${C.reset}` :
                                        `${C.gray}${envLabel.static}${C.reset}`);
  _summaryLine("Base URL",  session.base_url  || `${C.dim}(none)${C.reset}`);
  _summaryLine("Scope",     session.scope_confirmed ? `${C.bgreen}confirmed from bbscope${C.reset}` :
                             session.scope_manual   ? `${C.yellow}manual: ${session.scope_manual.slice(0,30)}${C.reset}` :
                                                       `${C.dim}not set${C.reset}`);
  _summaryLine("Focus",     session.focus === "full"      ? `${C.bgreen}full coverage — all classes${C.reset}` :
                             session.focus === "h1_signal" ? `${C.cyan}full coverage — H1 history ordering${C.reset}` :
                                                              `${C.yellow}${session.focus}${C.reset}`);
  _summaryLine("CVE priority", session.cve_priority ? `${C.bgreen}yes${C.reset}` : `${C.dim}no${C.reset}`);
  _summaryLine("Credentials", session.credentials ? `${C.bgreen}loaded${C.reset}` : `${C.dim}none${C.reset}`);
  out(`${C.bold}${C.bmagenta}║${C.reset}                                                          ${C.bmagenta}║${C.reset}`);
  out(`${C.bold}${C.bmagenta}╚${"═".repeat(56)}╝${C.reset}`);
  out();

  const confirm = await askChoice(rl,
    "Confirm session configuration? After YES, the pipeline runs autonomously.",
    [{ key: "Y", label: "Yes — jack in" }, { key: "N", label: "No — abort" }],
    "Y"
  );
  return confirm === "Y";
}

function _summaryLine(label, value) {
  const padded = `${label}:`.padEnd(14);
  out(`${C.bold}${C.bmagenta}║${C.reset}  ${C.cyan}${padded}${C.reset} ${value}${" ".repeat(4)}${C.bmagenta}║${C.reset}`);
}

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Run Phase 0 Smart Onboarding.
 *
 * @param {object} context   pipeline context (target, asset, config, findingsDir, …)
 * @param {object} _args     parsed CLI args (unused here, kept for future flags)
 * @param {string} _runLog   path to pipeline log (unused here)
 * @returns {Promise<object>} sessionConfig — merged into pipeline args for later stages
 */
async function runPhase0(context, _args, _runLog) {
  const intel = loadIntel(context);
  displayIntelBrief(context, intel);

  const rl = readline.createInterface({
    input:  process.stdin,
    output: process.stdout,
    terminal: true
  });

  let session;
  try {
    session = await runInteractiveQuestions(rl, context, intel);
    const confirmed = await displaySessionSummary(rl, context, session);
    if (!confirmed) {
      out(`${C.bred}Aborted. No changes made.${C.reset}`);
      process.exit(0);
    }
    out(`${C.bgreen}Session confirmed. Jacking in...${C.reset}`);
    out();
  } finally {
    rl.close();
  }

  return session;
}

module.exports = { runPhase0, loadIntel, displayIntelBrief };
