"use strict";

/**
 * hitl.js — Human-in-the-Loop structured checkpoints for Agentic-BugBounty.
 *
 * Three checkpoints:
 *   1. Post-Explorer: review surface map, focus scope
 *   2. Post-Researcher: review candidates, guide chain hypothesis
 *   3. Pre-Triage: approval/rejection finding, notify
 *
 * Each checkpoint can be skipped by pressing Enter without input.
 * The pipeline never blocks in an unrecoverable way.
 */

const fs       = require("node:fs");
const path     = require("node:path");
const readline = require("node:readline");

// ─── ANSI colors (inline, no dependencies) ──────────────────────────────────

const C = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  cyan:    "\x1b[36m",
  yellow:  "\x1b[33m",
  green:   "\x1b[32m",
  red:     "\x1b[31m",
  magenta: "\x1b[35m",
  bgRed:   "\x1b[41m",
  bgGreen: "\x1b[42m",
};

const SEV_COLOR = {
  Critical: C.red + C.bold,
  High:     C.red,
  Medium:   C.yellow,
  Low:      C.cyan,
  Informative: C.dim,
};

// ─── UI helpers ──────────────────────────────────────────────────────────────

function bar(char = "─", len = 72) {
  return char.repeat(len);
}

function header(title) {
  process.stdout.write(`\n${C.magenta}${bar("═")}${C.reset}\n`);
  process.stdout.write(`${C.bold}${C.magenta}${title}${C.reset}\n`);
  process.stdout.write(`${C.magenta}${bar("═")}${C.reset}\n\n`);
}

function section(title) {
  process.stdout.write(`\n${C.cyan}${bar()}${C.reset}\n`);
  process.stdout.write(`${C.bold}${title}${C.reset}\n`);
  process.stdout.write(`${C.cyan}${bar()}${C.reset}\n`);
}

function createRl() {
  return readline.createInterface({ input: process.stdin, output: process.stdout });
}

async function ask(rl, question) {
  return new Promise((resolve) => rl.question(question, resolve));
}

async function askYN(rl, question, defaultYes = true) {
  const hint = defaultYes ? "[Y/n]" : "[y/N]";
  const answer = (await ask(rl, `${question} ${hint} `)).trim().toLowerCase();
  if (!answer) return defaultYes;
  return answer === "y" || answer === "yes";
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

// ─── CHECKPOINT 1 — Post-Explorer, Pre-Researcher ────────────────────────────

/**
 * Shows the Explorer surface map and allows the user to:
 *   - Exclude components/endpoints from scope
 *   - Add specific focus areas
 *   - Add notes to inject into the Researcher prompt
 *
 * @returns {string} additional text to inject into the Researcher prompt
 */
async function checkpoint1_postExplorer(explorerHint, assetContext) {
  header("HITL CHECKPOINT 1 — Surface Review (Pre-Researcher)");

  process.stdout.write(`${C.dim}Target: ${assetContext.target || "(unknown)"}${C.reset}\n`);
  process.stdout.write(`${C.dim}Asset:  ${assetContext.asset} / ${assetContext.mode}${C.reset}\n\n`);

  if (explorerHint) {
    process.stdout.write(`${C.bold}Explorer surface analysis:${C.reset}\n`);
    process.stdout.write(explorerHint + "\n");
  } else {
    process.stdout.write(`${C.dim}(Explorer produced no surface data — no OPENROUTER_API_KEY or target unreachable)${C.reset}\n\n`);
  }

  const rl = createRl();
  let extraHint = "";

  try {
    const proceed = await askYN(rl, "Proceed with Researcher pass using this surface data?", true);
    if (!proceed) {
      process.stdout.write(`${C.yellow}Pipeline stopped at HITL Checkpoint 1 by user.${C.reset}\n`);
      rl.close();
      process.exit(0);
    }

    process.stdout.write(`\n${C.bold}Focus areas${C.reset} (optional — comma-separated endpoints or vuln classes to prioritize):\n`);
    process.stdout.write(`${C.dim}Example: /api/admin, JWT auth, file upload, GraphQL${C.reset}\n`);
    const focusInput = (await ask(rl, "Focus on → ")).trim();

    if (focusInput) {
      extraHint += `\n\nHITL FOCUS DIRECTIVE (set by human operator):\n`;
      extraHint += `Prioritize these areas above all others: ${focusInput}\n`;
      extraHint += `Spend at least 40% of your analysis effort on the above before moving to other surfaces.\n`;
    }

    process.stdout.write(`\n${C.bold}Exclude from scope${C.reset} (optional — comma-separated patterns to skip):\n`);
    process.stdout.write(`${C.dim}Example: /admin/legacy, test endpoints, static assets${C.reset}\n`);
    const excludeInput = (await ask(rl, "Exclude → ")).trim();

    if (excludeInput) {
      extraHint += `\n\nHITL SCOPE EXCLUSION (set by human operator):\n`;
      extraHint += `Do NOT test or report on: ${excludeInput}\n`;
      extraHint += `Treat these as out-of-scope for this session.\n`;
    }

    process.stdout.write(`\n${C.bold}Additional notes for the Researcher${C.reset} (optional, press Enter to skip):\n`);
    const notes = (await ask(rl, "Notes → ")).trim();
    if (notes) {
      extraHint += `\n\nHITL OPERATOR NOTES:\n${notes}\n`;
    }

  } finally {
    rl.close();
  }

  if (extraHint) {
    process.stdout.write(`\n${C.green}HITL directives will be injected into Researcher prompt.${C.reset}\n`);
  } else {
    process.stdout.write(`\n${C.dim}No HITL directives added — Researcher will proceed with default scope.${C.reset}\n`);
  }

  return extraHint;
}

// ─── CHECKPOINT 2 — Post-Researcher, Pre-Chain ───────────────────────────────

/**
 * Shows found candidates and allows the user to:
 *   - Reject candidates before chain synthesis
 *   - Suggest specific chain hypotheses
 *   - Add context about how the target works
 *
 * @returns {{ filteredBundlePath: string, chainHints: string }}
 */
async function checkpoint2_postResearcher(bundlePath, unconfirmedPath) {
  header("HITL CHECKPOINT 2 — Candidate Review (Pre-Chain-Synthesis)");

  const bundle = readJson(bundlePath);
  const confirmed = (bundle && bundle.findings) || [];
  const unconfirmed = fs.existsSync(unconfirmedPath)
    ? ((readJson(unconfirmedPath) || {}).candidates || [])
    : [];

  if (confirmed.length === 0 && unconfirmed.length === 0) {
    process.stdout.write(`${C.dim}No candidates found — skipping checkpoint 2.${C.reset}\n`);
    return { chainHints: "" };
  }

  section(`Confirmed findings: ${confirmed.length}`);
  for (const f of confirmed) {
    const sevColor = SEV_COLOR[f.severity_claimed] || "";
    process.stdout.write(
      `  ${C.bold}[${f.report_id}]${C.reset} ${sevColor}${f.severity_claimed}${C.reset} — ${f.finding_title}\n`
    );
    process.stdout.write(`    Component: ${f.affected_component}\n`);
    process.stdout.write(`    ${C.dim}${f.summary}${C.reset}\n\n`);
  }

  if (unconfirmed.length > 0) {
    section(`Unconfirmed candidates: ${unconfirmed.length}`);
    for (const c of unconfirmed.slice(0, 10)) {
      process.stdout.write(
        `  ${C.dim}[${c.report_id || "?"}]${C.reset} ${c.vulnerability_class || "unknown"} — ${c.affected_component || "?"}\n`
      );
      if (c.reason_not_confirmed) {
        process.stdout.write(`    ${C.dim}Reason: ${c.reason_not_confirmed}${C.reset}\n`);
      }
    }
    if (unconfirmed.length > 10) {
      process.stdout.write(`  ${C.dim}... and ${unconfirmed.length - 10} more${C.reset}\n`);
    }
  }

  const rl = createRl();
  let chainHints = "";

  try {
    process.stdout.write("\n");
    const proceed = await askYN(rl, "Proceed to Chain Synthesis with these candidates?", true);
    if (!proceed) {
      process.stdout.write(`${C.yellow}Pipeline stopped at HITL Checkpoint 2 by user.${C.reset}\n`);
      rl.close();
      process.exit(0);
    }

    // Reject confirmed candidates
    if (confirmed.length > 0) {
      const rejectInput = (await ask(rl,
        `\nReject any confirmed findings before chain synthesis? (IDs comma-separated, Enter to skip): `
      )).trim();

      if (rejectInput) {
        const toReject = new Set(rejectInput.split(",").map((s) => s.trim().toUpperCase()));
        const kept = confirmed.filter((f) => !toReject.has(f.report_id.toUpperCase()));
        const rejected = confirmed.filter((f) => toReject.has(f.report_id.toUpperCase()));

        if (rejected.length > 0) {
          bundle.findings = kept;
          bundle.unconfirmed_candidates = [
            ...(bundle.unconfirmed_candidates || []),
            ...rejected.map((f) => ({ ...f, reason_not_confirmed: "rejected by human operator at HITL checkpoint 2" }))
          ];
          writeJson(bundlePath, bundle);
          process.stdout.write(`${C.yellow}Rejected: ${rejected.map((f) => f.report_id).join(", ")}${C.reset}\n`);
        }
      }
    }

    // Chain hypothesis hints
    process.stdout.write(`\n${C.bold}Chain hypothesis hints${C.reset} (optional):\n`);
    process.stdout.write(`${C.dim}Suggest specific combinations to test. Example:\n`);
    process.stdout.write(`  "WEB-002 open redirect might chain with WEB-005 CSRF on /api/email"\n`);
    process.stdout.write(`  "The JWT weakness (WEB-003) could bypass the IDOR check in WEB-001"\n${C.reset}`);
    const chainInput = (await ask(rl, "Chain hints → ")).trim();

    if (chainInput) {
      chainHints = `\n\nHITL CHAIN HYPOTHESIS (suggested by human operator):\n${chainInput}\n`;
      chainHints += `Test these chain hypotheses first before running the general primitive matrix.\n`;
    }

    // Additional application context
    process.stdout.write(`\n${C.bold}Application context${C.reset} (optional — helps chain reasoning):\n`);
    process.stdout.write(`${C.dim}Example: "Users can have admin role. Profile update is async. OAuth uses PKCE."${C.reset}\n`);
    const ctxInput = (await ask(rl, "Context → ")).trim();

    if (ctxInput) {
      chainHints += `\n\nHITL APPLICATION CONTEXT:\n${ctxInput}\n`;
      chainHints += `Use this context when evaluating chain feasibility and attack preconditions.\n`;
    }

  } finally {
    rl.close();
  }

  if (chainHints) {
    process.stdout.write(`\n${C.green}Chain hints will be injected into Chain Synthesis phase.${C.reset}\n`);
  }

  return { chainHints };
}

// ─── CHECKPOINT 3 — Post-Chain, Pre-Triage ───────────────────────────────────

/**
 * Final review before triage. Allows to:
 *   - Approve / reject / downgrade findings
 *   - View the PoC of each finding
 *   - Send notification via notify.js if configured
 *
 * Replaces the old reviewFindings() with a richer version.
 */
async function checkpoint3_preTriage(bundlePath, logPath) {
  header("HITL CHECKPOINT 3 — Final Review (Pre-Triage)");

  if (!fs.existsSync(bundlePath)) {
    process.stdout.write(`${C.dim}No bundle found — skipping checkpoint 3.${C.reset}\n`);
    return;
  }

  const bundle = readJson(bundlePath);
  const findings = (bundle && bundle.findings) || [];

  if (findings.length === 0) {
    process.stdout.write(`${C.dim}No confirmed findings to review.${C.reset}\n`);
    return;
  }

  process.stdout.write(`${C.bold}${findings.length} finding(s) ready for triage review:${C.reset}\n\n`);

  // Summary table
  for (const f of findings) {
    const sevColor = SEV_COLOR[f.severity_claimed] || "";
    const isChain = f.chain_meta && f.chain_meta.is_chain;
    const chainLabel = isChain ? ` ${C.magenta}[CHAIN]${C.reset}` : "";
    process.stdout.write(
      `  ${C.bold}[${f.report_id}]${C.reset}${chainLabel} ${sevColor}${f.severity_claimed}${C.reset} — ${f.finding_title}\n`
    );
    process.stdout.write(`    Component : ${f.affected_component}\n`);
    process.stdout.write(`    PoC type  : ${f.poc_type || "?"}\n`);
    process.stdout.write(`    ${C.dim}${f.summary}${C.reset}\n\n`);
  }

  const rl = createRl();
  const approved = [];
  const rejected = [];

  try {
    for (const f of findings) {
      const sevColor = SEV_COLOR[f.severity_claimed] || "";
      const isChain = f.chain_meta && f.chain_meta.is_chain;

      process.stdout.write(`\n${bar()}\n`);
      process.stdout.write(`${C.bold}[${f.report_id}]${C.reset} ${sevColor}${f.severity_claimed}${C.reset}`);
      if (isChain) process.stdout.write(` ${C.magenta}[CHAIN — ${(f.chain_meta.chain_steps || []).length} steps]${C.reset}`);
      process.stdout.write(`\n${f.finding_title}\n\n`);

      process.stdout.write(`Summary: ${f.summary}\n`);
      process.stdout.write(`Impact:  ${f.impact_claimed || "?"}\n`);

      if (isChain && f.chain_meta.chain_severity_rationale) {
        process.stdout.write(`\n${C.magenta}Chain rationale: ${f.chain_meta.chain_severity_rationale}${C.reset}\n`);
      }

      let choice = "";
      while (!["a", "r", "d", "v"].includes(choice)) {
        choice = (await ask(rl,
          `\n  [a] approve  [r] reject  [d] downgrade severity  [v] view PoC → `
        )).trim().toLowerCase();
      }

      if (choice === "v") {
        process.stdout.write(`\n${C.bold}PoC (${f.poc_type || "?"})${C.reset}:\n`);
        process.stdout.write(`${f.poc_code || "(none)"}\n\n`);
        if (f.steps_to_reproduce && f.steps_to_reproduce.length > 0) {
          process.stdout.write(`${C.bold}Steps to reproduce:${C.reset}\n`);
          f.steps_to_reproduce.forEach((s, i) => process.stdout.write(`  ${i + 1}. ${s}\n`));
        }
        if (isChain && f.chain_meta.chain_steps) {
          process.stdout.write(`\n${C.bold}Chain steps:${C.reset}\n`);
          for (const step of f.chain_meta.chain_steps) {
            process.stdout.write(`  ${step.step}. [${step.vuln_class}] ${step.component}\n`);
            process.stdout.write(`     Primitive: ${step.primitive_provided}\n`);
            process.stdout.write(`     Precondition: ${step.precondition}\n`);
          }
        }
        process.stdout.write("\n");
        while (!["a", "r", "d"].includes(choice)) {
          choice = (await ask(rl, "  [a] approve  [r] reject  [d] downgrade → ")).trim().toLowerCase();
        }
      }

      if (choice === "a") {
        approved.push(f);
        process.stdout.write(`  ${C.green}Approved${C.reset}\n`);
      } else if (choice === "r") {
        rejected.push(f);
        process.stdout.write(`  ${C.red}Rejected${C.reset}\n`);
      } else if (choice === "d") {
        const severities = ["Critical", "High", "Medium", "Low", "Informative"];
        const currentIdx = severities.indexOf(f.severity_claimed);
        process.stdout.write(`  Current severity: ${f.severity_claimed}\n`);
        process.stdout.write(`  Available: ${severities.slice(currentIdx + 1).join(", ")}\n`);
        const newSev = (await ask(rl, "  New severity → ")).trim();
        if (severities.includes(newSev)) {
          f.severity_claimed = newSev;
          process.stdout.write(`  ${C.yellow}Downgraded to ${newSev}${C.reset}\n`);
        } else {
          process.stdout.write(`  ${C.dim}Invalid severity — keeping original${C.reset}\n`);
        }
        approved.push(f);
      }
    }
  } finally {
    rl.close();
  }

  // Update the bundle with approvals
  if (rejected.length > 0 || findings.some((f) => f.severity_claimed !== (bundle.findings.find((b) => b.report_id === f.report_id) || {}).severity_claimed)) {
    bundle.findings = approved;
    bundle.unconfirmed_candidates = [
      ...(bundle.unconfirmed_candidates || []),
      ...rejected.map((f) => ({ ...f, reason_not_confirmed: "rejected by human operator at HITL checkpoint 3" }))
    ];
    writeJson(bundlePath, bundle);
  }

  process.stdout.write(`\n${bar()}\n`);
  process.stdout.write(`${C.green}HITL Checkpoint 3 complete:${C.reset} `);
  process.stdout.write(`${approved.length} approved, ${rejected.length} rejected\n`);

  if (logPath) {
    try {
      fs.appendFileSync(logPath,
        `[${new Date().toISOString()}] HITL checkpoint 3: ${approved.length} approved, ${rejected.length} rejected\n`
      );
    } catch { /* do not block */ }
  }
}

module.exports = {
  checkpoint1_postExplorer,
  checkpoint2_postResearcher,
  checkpoint3_preTriage,
};
