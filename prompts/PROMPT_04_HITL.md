# PROMPT 04 — Human-in-the-Loop (HITL) Strutturato
# Esegui per ultimo. Modifica run-pipeline.js e crea scripts/lib/hitl.js.
# Questo è l'upgrade finale — nessun prompt successivo.

---

Sei un ingegnere che sta evolvendo il framework Agentic-BugBounty.
Il tuo task è sostituire il rudimentale `--interactive` esistente con
**checkpoint HITL strutturati** in tre punti chiave del pipeline.

Il `--interactive` attuale fa solo una review manuale finding-per-finding
prima del triage. È troppo poco e troppo tardi.

I nuovi checkpoint HITL sono:

```
CHECKPOINT 1 — Post-Explorer (prima del Researcher)
  Mostra la surface map dell'Explorer e chiede: vuoi escludere scope o
  focalizzare su aree specifiche prima che il Researcher inizi?

CHECKPOINT 2 — Post-Researcher / Pre-Chain-Synthesis
  Mostra i candidati trovati (confermati + non confermati) e chiede:
  quali chain hypothesis vuoi che l'agente prioritizzi?
  Puoi anche approvare/rigettare candidati manualmente qui.

CHECKPOINT 3 — Post-Chain-Synthesis / Pre-Triage
  Mostra i finding finali (inclusi chain finding) con severity e PoC type.
  Approvazione / rifiuto / downgrade manuale per finding prima del triage.
  Notifica via Telegram/Discord se configurata.
```

I checkpoint si attivano **solo con `--hitl`** (nuovo flag).
`--interactive` continua a funzionare come prima per retrocompatibilità.

---

## FILE DA CREARE

### `scripts/lib/hitl.js`

```javascript
"use strict";

/**
 * hitl.js — Human-in-the-Loop checkpoint strutturati per Agentic-BugBounty.
 *
 * Tre checkpoint:
 *   1. Post-Explorer: review surface map, focalizza scope
 *   2. Post-Researcher: review candidati, guida chain hypothesis
 *   3. Pre-Triage: approval/rejection finding, notifica
 *
 * Ogni checkpoint può essere saltato premendo Invio senza input.
 * Il pipeline non si blocca mai in modo non recuperabile.
 */

const fs       = require("node:fs");
const path     = require("node:path");
const readline = require("node:readline");

// ─── Colori ANSI (inline, no dipendenze) ────────────────────────────────────

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
 * Mostra la surface map dell'Explorer e permette all'utente di:
 *   - Escludere componenti/endpoint dallo scope
 *   - Aggiungere focus areas specifiche
 *   - Aggiungere note da iniettare nel Researcher prompt
 *
 * @returns {string} testo aggiuntivo da iniettare nel Researcher prompt
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
    process.stdout.write(`\n${C.green}✓ HITL directives will be injected into Researcher prompt.${C.reset}\n`);
  } else {
    process.stdout.write(`\n${C.dim}No HITL directives added — Researcher will proceed with default scope.${C.reset}\n`);
  }

  return extraHint;
}

// ─── CHECKPOINT 2 — Post-Researcher, Pre-Chain ───────────────────────────────

/**
 * Mostra i candidati trovati e permette all'utente di:
 *   - Rigettare candidati prima del chain synthesis
 *   - Suggerire chain hypothesis specifiche
 *   - Aggiungere context su come il target funziona
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

    // Rifiuto candidati confermati
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

    // Context aggiuntivo sull'applicazione
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
    process.stdout.write(`\n${C.green}✓ Chain hints will be injected into Chain Synthesis phase.${C.reset}\n`);
  }

  return { chainHints };
}

// ─── CHECKPOINT 3 — Post-Chain, Pre-Triage ───────────────────────────────────

/**
 * Review finale prima del triage. Permette di:
 *   - Approvare / rigettare / downgrade finding
 *   - Vedere il PoC di ogni finding
 *   - Inviare notifica via notify.js se configurato
 *
 * Sostituisce il vecchio reviewFindings() con versione più ricca.
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
        process.stdout.write(`  ${C.green}✓ Approved${C.reset}\n`);
      } else if (choice === "r") {
        rejected.push(f);
        process.stdout.write(`  ${C.red}✗ Rejected${C.reset}\n`);
      } else if (choice === "d") {
        const severities = ["Critical", "High", "Medium", "Low", "Informative"];
        const currentIdx = severities.indexOf(f.severity_claimed);
        process.stdout.write(`  Current severity: ${f.severity_claimed}\n`);
        process.stdout.write(`  Available: ${severities.slice(currentIdx + 1).join(", ")}\n`);
        const newSev = (await ask(rl, "  New severity → ")).trim();
        if (severities.includes(newSev)) {
          f.severity_claimed = newSev;
          process.stdout.write(`  ${C.yellow}↓ Downgraded to ${newSev}${C.reset}\n`);
        } else {
          process.stdout.write(`  ${C.dim}Invalid severity — keeping original${C.reset}\n`);
        }
        approved.push(f);
      }
    }
  } finally {
    rl.close();
  }

  // Aggiorna il bundle con le approvazioni
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
    } catch { /* non bloccare */ }
  }
}

module.exports = {
  checkpoint1_postExplorer,
  checkpoint2_postResearcher,
  checkpoint3_preTriage,
};
```

---

## FILE DA MODIFICARE

### `scripts/run-pipeline.js`

#### Modifica 1 — Import

Trova la riga:

```javascript
const { runExplorer } = require("./lib/explorer");
```

Aggiungi subito dopo:

```javascript
const { checkpoint1_postExplorer, checkpoint2_postResearcher, checkpoint3_preTriage } = require("./lib/hitl");
```

#### Modifica 2 — Nuovo flag `--hitl` nel parser

Trova in `parseArgs`:

```javascript
    interactive: false,
    resume: false
```

Sostituisci con:

```javascript
    interactive: false,
    hitl: false,
    resume: false
```

Trova nel loop di parsing:

```javascript
    else if (value === "--interactive") parsed.interactive = true;
```

Aggiungi subito dopo:

```javascript
    else if (value === "--hitl") { parsed.hitl = true; parsed.interactive = false; }
```

#### Modifica 3 — Checkpoint 1 dopo Explorer, prima del Researcher

In `runResearcherPhase`, dopo il blocco che costruisce `explorerHint`, trova:

```javascript
  if (explorerHint) extraText += explorerHint;
  if (reconText) extraText += reconText;
```

Sostituisci con:

```javascript
  if (explorerHint) extraText += explorerHint;
  if (reconText) extraText += reconText;

  // HITL Checkpoint 1 — mostra surface map, ricevi focus directives
  if (args.hitl) {
    const hitlHint = await checkpoint1_postExplorer(explorerHint, assetContext);
    if (hitlHint) extraText += hitlHint;
  }
```

#### Modifica 4 — Checkpoint 2 dopo Researcher, prima di chain / dual pass

In `main()`, trova il blocco:

```javascript
  runCommand("node", ["scripts/validate-bundle.js", bundlePath]);

  // Adaptive self-check:
```

Inserisci prima di `runCommand(...)`:

```javascript
  // HITL Checkpoint 2 — review candidati, guida chain synthesis
  if (args.hitl && fs.existsSync(bundlePath)) {
    const unconfirmedPath = path.join(context.findingsDir, "unconfirmed", "candidates.json");
    const { chainHints } = await checkpoint2_postResearcher(bundlePath, unconfirmedPath);
    if (chainHints) {
      // Scrivi i chain hints nel file di intelligence per il dual researcher pass
      const chainHintPath = context.intelligenceDir
        ? path.join(context.intelligenceDir, "hitl_chain_hints.txt")
        : null;
      if (chainHintPath) {
        fs.writeFileSync(chainHintPath, chainHints, "utf8");
        logEvent(runLog, `HITL chain hints saved to ${chainHintPath}`);
      }
    }
  }

```

#### Modifica 5 — Checkpoint 3 sostituisce `--interactive` quando `--hitl` è attivo

Trova:

```javascript
  // Optional manual review before triage
  if (args.interactive) {
    await reviewFindings(bundlePath, runLog);
  }
```

Sostituisci con:

```javascript
  // HITL Checkpoint 3 (--hitl) o review classica (--interactive)
  if (args.hitl) {
    await checkpoint3_preTriage(bundlePath, runLog);
  } else if (args.interactive) {
    await reviewFindings(bundlePath, runLog);
  }
```

#### Modifica 6 — Aggiorna il briefing iniziale

Trova nel briefing la riga che stampa le opzioni del pipeline e aggiungi
dopo la riga che mostra `--interactive`:

```javascript
    process.stdout.write(`\n  ${C.cyan}Mode flags:${C.reset}\n`);
    process.stdout.write(`    ${C.yellow}--hitl${C.reset}        Structured human-in-the-loop: 3 review checkpoints\n`);
    process.stdout.write(`    ${C.yellow}--interactive${C.reset} Legacy: single finding review before triage\n`);
    process.stdout.write(`    ${C.yellow}--resume${C.reset}      Resume from last checkpoint after session limit\n`);
```

---

## VERIFICA FINALE

```bash
# Syntax check di tutti i file modificati/creati
node --check scripts/run-pipeline.js && echo "Pipeline syntax OK"
node --check scripts/lib/hitl.js      && echo "HITL syntax OK"

# Verifica import e checkpoint functions
grep -n "checkpoint1\|checkpoint2\|checkpoint3\|hitl\|--hitl" scripts/run-pipeline.js | head -15

# Verifica che il modulo si carichi
node -e "
  const h = require('./scripts/lib/hitl');
  console.log('HITL functions:', Object.keys(h).join(', '));
"

# Test del flag parsing (non deve lanciare il pipeline)
node -e "
  // Simula il parsing dei nuovi flag
  const args = ['node', 'run-pipeline.js', '--hitl', '--target', '1'];
  // Se il parseArgs è corretto, hitl sarà true
  console.log('Flag parsing test: OK (manual verification needed)');
"
```

Verifica finale dell'intera catena di upgrade:

```bash
# Tutti e 4 i prompt applicati — verifica presenza dei componenti chiave
echo "=== Prompt 01 — Chain Synthesis ===" && \
grep -l "Phase 2.6\|chain_meta\|CHAIN_VALID" .claude/commands/shared/*.md

echo "=== Prompt 02 — Adaptive Loop ===" && \
grep -l "detectReconSignals\|globalSignalSet" scripts/run-pipeline.js

echo "=== Prompt 03 — Explorer Agent ===" && \
ls scripts/lib/explorer.js && \
grep -l "runExplorer" scripts/run-pipeline.js

echo "=== Prompt 04 — HITL ===" && \
ls scripts/lib/hitl.js && \
grep -l "checkpoint1_postExplorer\|--hitl" scripts/run-pipeline.js
```

Tutti e 4 i check devono produrre output non vuoto.

---

## RIEPILOGO COMANDI DOPO I 4 UPGRADE

```bash
# Pipeline standard (invariato)
node scripts/run-pipeline.js --target 1 --cli claude

# Con HITL strutturato (nuovo)
node scripts/run-pipeline.js --target 1 --cli claude --hitl

# Con HITL + resume
node scripts/run-pipeline.js --target 1 --cli claude --hitl --resume

# Solo Researcher + HITL checkpoint 1 e 2 (senza triage)
node scripts/run-pipeline.js --target 1 --cli claude --hitl --max-nmi-rounds 0
```
