# PROMPT 03 — Explorer Agent (Multi-Agent)
# Esegui dopo PROMPT_02. Crea un nuovo file e modifica run-pipeline.js.
# Dopo: esegui PROMPT_04_HITL.md

---

Sei un ingegnere che sta evolvendo il framework Agentic-BugBounty.
Il tuo task è aggiungere un secondo agente specializzato: l'**Explorer**.

Architettura attuale:
```
Researcher (Claude Code) → Triager (Claude Code)
```

Architettura target:
```
Explorer (free LLM, parallelo) ──┐
                                  ├─→ Researcher (Claude Code) → Triager (Claude Code)
Hybrid Recon (già esistente) ───┘
```

L'Explorer è un agente leggero che gira in parallelo alla researcher pass,
usando un free LLM via OpenRouter. Il suo compito non è trovare vulnerabilità
— è **mappare la superficie d'attacco** in modo più profondo di quanto
faccia l'hybrid recon attuale: enumera endpoint nascosti, analizza JS bundles,
cerca pattern di autenticazione, identifica dependency con CVE note.
Il risultato viene iniettato nel prompt del Researcher come intelligence
aggiuntiva, non come finding.

---

## FILE DA CREARE

### `scripts/lib/explorer.js`

Crea questo file da zero:

```javascript
"use strict";

/**
 * explorer.js — Agente Explorer leggero (free LLM via OpenRouter).
 *
 * Responsabilità:
 *   - Enumerazione endpoint da JS bundles e path bruteforce leggero
 *   - Identificazione pattern di autenticazione (OAuth, JWT, API key, session)
 *   - Detection dipendenze con CVE note (package.json / requirements.txt / pom.xml)
 *   - Identificazione tecnologie e framework da header / error messages / file paths
 *   - Costruzione di una surface map strutturata da iniettare nel Researcher prompt
 *
 * Failure contract: qualsiasi errore viene loggato e il pipeline continua.
 * La funzione restituisce null su failure — il Researcher opera senza l'Explorer hint.
 *
 * Non produce findings. Non tocca il report_bundle. Solo surface intelligence.
 */

const fs   = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { callLLMJson } = require("./llm");

// ─── Helpers ──────────────────────────────────────────────────────────────────

function log(msg) {
  process.stdout.write(`  \x1b[2m[explorer] ${msg}\x1b[0m\n`);
}

function safeRead(filePath, maxBytes = 50000) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxBytes) {
      // Leggi solo i primi maxBytes per non saturare il context
      const buf = Buffer.alloc(maxBytes);
      const fd = fs.openSync(filePath, "r");
      fs.readSync(fd, buf, 0, maxBytes, 0);
      fs.closeSync(fd);
      return buf.toString("utf8");
    }
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function findFiles(dir, extensions, maxFiles = 20) {
  const results = [];
  if (!dir || !fs.existsSync(dir)) return results;
  try {
    const result = spawnSync("find", [dir, "-type", "f", ...extensions.flatMap((e) => ["-o", "-name", `*.${e}`]).slice(1)], {
      encoding: "utf8", timeout: 10000
    });
    return (result.stdout || "").split("\n").filter(Boolean).slice(0, maxFiles);
  } catch {
    return results;
  }
}

// ─── Analisi dipendenze ───────────────────────────────────────────────────────

async function analyzeDependencies(sourceDir) {
  const depFiles = [
    "package.json", "requirements.txt", "pom.xml", "build.gradle",
    "Gemfile", "composer.json", "go.mod", "Cargo.toml"
  ];

  const found = [];
  for (const depFile of depFiles) {
    const fullPath = path.join(sourceDir, depFile);
    const content = safeRead(fullPath, 20000);
    if (content) {
      found.push({ file: depFile, content: content.slice(0, 5000) });
    }
  }

  if (found.length === 0) return null;

  const prompt = `You are a security researcher analyzing dependency files for known vulnerable packages.

Dependency files found:
${found.map((f) => `\n--- ${f.file} ---\n${f.content}`).join("\n")}

Respond with a JSON object:
{
  "vulnerable_deps": [
    {
      "package": "package-name",
      "version_found": "x.y.z or range",
      "cve_ids": ["CVE-XXXX-XXXXX"],
      "severity": "Critical|High|Medium",
      "exploit_surface": "brief description of what attack surface this opens"
    }
  ],
  "interesting_deps": [
    {
      "package": "package-name",
      "reason": "why this is interesting for security testing"
    }
  ]
}

Only include packages you are confident have known CVEs or notable security implications.
Return { "vulnerable_deps": [], "interesting_deps": [] } if nothing notable found.`;

  try {
    return await callLLMJson(prompt, { timeoutMs: 60000 });
  } catch {
    return null;
  }
}

// ─── Analisi endpoint da JS ───────────────────────────────────────────────────

async function analyzeJsEndpoints(sourceDir) {
  const jsFiles = findFiles(sourceDir, ["js", "ts", "jsx", "tsx"], 15);
  if (jsFiles.length === 0) return null;

  const samples = [];
  for (const f of jsFiles) {
    // Cerca solo pattern rilevanti per sicurezza — non leggere tutto il file
    const content = safeRead(f, 30000) || "";
    const lines = content.split("\n");
    const relevant = lines.filter((line) =>
      /fetch\(|axios\.|\.get\(|\.post\(|apiUrl|API_URL|endpoint|\/api\/|\/v[0-9]\/|Authorization|Bearer|jwt|token|localStorage|sessionStorage/.test(line)
    );
    if (relevant.length > 0) {
      samples.push({ file: path.relative(sourceDir, f), lines: relevant.slice(0, 30).join("\n") });
    }
  }

  if (samples.length === 0) return null;

  const prompt = `You are a security researcher extracting API surface information from JavaScript source code.

Relevant lines from JS files:
${samples.map((s) => `\n--- ${s.file} ---\n${s.lines}`).join("\n")}

Respond with a JSON object:
{
  "api_endpoints": [
    {
      "path": "/api/endpoint",
      "method": "GET|POST|PUT|DELETE|PATCH|unknown",
      "auth_required": true,
      "interesting_params": ["param1", "param2"],
      "security_note": "brief note on why this is interesting"
    }
  ],
  "auth_patterns": [
    {
      "type": "JWT|OAuth|API_key|session_cookie|basic|none",
      "location": "header|localStorage|cookie|body",
      "note": "any security concern"
    }
  ],
  "hardcoded_secrets": [
    {
      "type": "api_key|token|password|secret",
      "context": "brief excerpt showing the secret pattern (no actual values)"
    }
  ]
}

Return { "api_endpoints": [], "auth_patterns": [], "hardcoded_secrets": [] } if nothing notable.`;

  try {
    return await callLLMJson(prompt, { timeoutMs: 90000 });
  } catch {
    return null;
  }
}

// ─── Analisi header e fingerprinting ─────────────────────────────────────────

async function analyzeTarget(targetUrl) {
  if (!targetUrl || !targetUrl.startsWith("http")) return null;

  // Fetch leggero dei soli header (HEAD request)
  let headerOutput = "";
  try {
    const result = spawnSync("curl", [
      "-sI", "--max-time", "10", "--max-redirs", "3",
      "-A", "Mozilla/5.0 (compatible; security-researcher/1.0)",
      targetUrl
    ], { encoding: "utf8", timeout: 15000 });
    headerOutput = result.stdout || "";
  } catch {
    return null;
  }

  if (!headerOutput) return null;

  const prompt = `You are a security researcher fingerprinting a web target from its HTTP response headers.

HTTP Headers:
${headerOutput.slice(0, 3000)}

Respond with a JSON object:
{
  "detected_stack": ["technology1", "framework2"],
  "security_headers_missing": ["Content-Security-Policy", "X-Frame-Options"],
  "information_leakage": [
    {
      "header": "Server",
      "value": "exact value",
      "risk": "what this reveals"
    }
  ],
  "interesting_observations": ["observation1", "observation2"]
}`;

  try {
    return await callLLMJson(prompt, { timeoutMs: 45000 });
  } catch {
    return null;
  }
}

// ─── Formatter dell'output per il Researcher ─────────────────────────────────

function formatExplorerContextForPrompt(explorerResult) {
  if (!explorerResult) return "";

  const parts = [];

  if (explorerResult.dependencies) {
    const { vulnerable_deps, interesting_deps } = explorerResult.dependencies;
    if (vulnerable_deps && vulnerable_deps.length > 0) {
      parts.push("VULNERABLE DEPENDENCIES (Explorer pre-analysis):");
      for (const dep of vulnerable_deps) {
        parts.push(`  • ${dep.package} ${dep.version_found} — ${dep.severity} — CVEs: ${dep.cve_ids.join(", ")}`);
        parts.push(`    Attack surface: ${dep.exploit_surface}`);
      }
    }
    if (interesting_deps && interesting_deps.length > 0) {
      parts.push("INTERESTING DEPENDENCIES:");
      for (const dep of interesting_deps) {
        parts.push(`  • ${dep.package}: ${dep.reason}`);
      }
    }
  }

  if (explorerResult.jsAnalysis) {
    const { api_endpoints, auth_patterns, hardcoded_secrets } = explorerResult.jsAnalysis;
    if (api_endpoints && api_endpoints.length > 0) {
      parts.push("\nAPI ENDPOINTS (from JS analysis):");
      for (const ep of api_endpoints.slice(0, 15)) {
        parts.push(`  • ${ep.method || "?"} ${ep.path}${ep.auth_required ? " [auth]" : " [no-auth?]"}${ep.security_note ? ` — ${ep.security_note}` : ""}`);
      }
    }
    if (auth_patterns && auth_patterns.length > 0) {
      parts.push("\nAUTH PATTERNS:");
      for (const ap of auth_patterns) {
        parts.push(`  • ${ap.type} in ${ap.location}${ap.note ? ` — ${ap.note}` : ""}`);
      }
    }
    if (hardcoded_secrets && hardcoded_secrets.length > 0) {
      parts.push("\n⚠️  HARDCODED SECRET PATTERNS DETECTED:");
      for (const s of hardcoded_secrets) {
        parts.push(`  • ${s.type}: ${s.context}`);
      }
    }
  }

  if (explorerResult.targetFingerprint) {
    const { detected_stack, security_headers_missing, information_leakage } = explorerResult.targetFingerprint;
    if (detected_stack && detected_stack.length > 0) {
      parts.push(`\nDETECTED STACK: ${detected_stack.join(", ")}`);
    }
    if (security_headers_missing && security_headers_missing.length > 0) {
      parts.push(`MISSING SECURITY HEADERS: ${security_headers_missing.join(", ")}`);
    }
    if (information_leakage && information_leakage.length > 0) {
      parts.push("INFORMATION LEAKAGE VIA HEADERS:");
      for (const leak of information_leakage) {
        parts.push(`  • ${leak.header}: ${leak.risk}`);
      }
    }
  }

  if (parts.length === 0) return "";

  return `\n\nEXPLORER AGENT PRE-ANALYSIS\n${"─".repeat(40)}\n${parts.join("\n")}\n${"─".repeat(40)}\nUse the above to prioritize your analysis. Do not re-verify what Explorer already confirmed.\n`;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/**
 * Esegui l'Explorer in parallelo alla researcher pass.
 *
 * @param {object} assetContext — context del pipeline (asset, target, mode, ...)
 * @param {string} projectRoot  — root del progetto (per trovare i lib)
 * @returns {string} testo da iniettare nel Researcher prompt, o "" se Explorer ha fallito
 */
async function runExplorer(assetContext, projectRoot) {
  if (!process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY_1) {
    log("skipped — no OPENROUTER_API_KEY set");
    return "";
  }

  log("starting parallel surface analysis...");
  const t0 = Date.now();

  const result = {};

  // Esegui le analisi in parallelo — ogni fallimento è isolato
  const tasks = [];

  // Analisi dipendenze (whitebox e blackbox parziale)
  if (assetContext.target && fs.existsSync(assetContext.target)) {
    tasks.push(
      analyzeDependencies(assetContext.target)
        .then((r) => { if (r) result.dependencies = r; })
        .catch((e) => log(`dependency analysis error: ${e.message}`))
    );

    // Analisi endpoint JS (whitebox)
    if (assetContext.mode === "whitebox") {
      tasks.push(
        analyzeJsEndpoints(assetContext.target)
          .then((r) => { if (r) result.jsAnalysis = r; })
          .catch((e) => log(`js endpoint analysis error: ${e.message}`))
      );
    }
  }

  // Fingerprinting target URL (blackbox e whitebox con target URL)
  const targetUrl = assetContext.target && assetContext.target.startsWith("http")
    ? assetContext.target
    : null;
  if (targetUrl) {
    tasks.push(
      analyzeTarget(targetUrl)
        .then((r) => { if (r) result.targetFingerprint = r; })
        .catch((e) => log(`target fingerprint error: ${e.message}`))
    );
  }

  // Attendi tutte le task con timeout globale di 120s
  await Promise.race([
    Promise.allSettled(tasks),
    new Promise((resolve) => setTimeout(resolve, 120000))
  ]);

  const elapsed = Math.round((Date.now() - t0) / 1000);
  const parts = Object.keys(result);

  if (parts.length === 0) {
    log(`completed in ${elapsed}s — no significant surface data found`);
    return "";
  }

  log(`completed in ${elapsed}s — ${parts.join(", ")} analyzed`);
  return formatExplorerContextForPrompt(result);
}

module.exports = { runExplorer };
```

---

## FILE DA MODIFICARE

### `scripts/run-pipeline.js`

#### Modifica 1 — Aggiungi import dell'Explorer

Trova il blocco degli import esistenti (circa riga 44):

```javascript
const { runHybridRecon, formatReconContextForPrompt } = require("./lib/hybrid-recon");
```

Aggiungi immediatamente dopo:

```javascript
const { runExplorer } = require("./lib/explorer");
```

#### Modifica 2 — Lancia Explorer in parallelo nel runResearcherPhase

Trova dentro `runResearcherPhase` questo blocco:

```javascript
  // Run Phase 0+1 via free LLM to save Claude tokens
  try {
    logEvent(runLog, "Running hybrid recon (Phase 0+1) via free LLM...");
    const reconContext = await runHybridRecon(assetContext, path.resolve(__dirname, ".."));
```

Sostituiscilo con:

```javascript
  // Run Explorer + Hybrid Recon in parallelo — entrambi usano free LLM
  // Explorer: surface mapping (deps, JS endpoints, fingerprinting)
  // Hybrid Recon: calibration + source inventory (Phase 0+1)
  let explorerHint = "";
  let reconText = "";

  try {
    logEvent(runLog, "Running Explorer + Hybrid Recon in parallel (free LLM)...");

    const [explorerResult, reconResult] = await Promise.allSettled([
      runExplorer(assetContext, path.resolve(__dirname, "..")),
      runHybridRecon(assetContext, path.resolve(__dirname, ".."))
    ]);

    if (explorerResult.status === "fulfilled" && explorerResult.value) {
      explorerHint = explorerResult.value;
      logEvent(runLog, "Explorer surface analysis injected into researcher prompt", "ok");
    } else if (explorerResult.status === "rejected") {
      logEvent(runLog, `Explorer error: ${explorerResult.reason?.message} — skipped`, "warn");
    }

    if (reconResult.status === "fulfilled" && reconResult.value) {
      reconText = formatReconContextForPrompt(reconResult.value) || "";
      if (reconText) logEvent(runLog, "Hybrid recon injected into researcher prompt", "ok");
    } else if (reconResult.status === "rejected") {
      logEvent(runLog, `Hybrid recon error: ${reconResult.reason?.message} — Claude handles Phase 0+1`, "warn");
    }

  } catch (e) {
    logEvent(runLog, `Parallel pre-analysis error: ${e.message} — Claude handles Phase 0+1`, "warn");
  }

  if (explorerHint) extraText += explorerHint;
  if (reconText) extraText += reconText;
```

Poi **rimuovi** il vecchio blocco try/catch dell'hybrid recon che segue
(quello che termina con `extraText += reconText`), dato che è ora sostituito
dal blocco parallelo sopra.

#### Modifica 3 — Aggiorna il briefing iniziale

Trova nel briefing iniziale di `main()` questa riga:

```javascript
    process.stdout.write(`    ${C.yellow}2.${C.reset} Researcher    — Claude analyses each asset (whitebox/blackbox)\n`);
```

Sostituiscila con:

```javascript
    process.stdout.write(`    ${C.yellow}2.${C.reset} Explorer      — ${hasOpenRouter ? `${C.bgreen}enabled${C.reset} (surface mapping: deps, JS endpoints, fingerprinting)` : `${C.gray}disabled${C.reset} (no OPENROUTER_API_KEY set)`}\n`);
    process.stdout.write(`       ${C.dim}Runs in parallel with Hybrid Recon — feeds surface intel to Researcher${C.reset}\n`);
    process.stdout.write(`    ${C.yellow}3.${C.reset} Researcher    — Claude analyses each asset (whitebox/blackbox)\n`);
```

---

## VERIFICA FINALE

```bash
# Syntax check
node --check scripts/run-pipeline.js && echo "Pipeline syntax OK"
node --check scripts/lib/explorer.js && echo "Explorer syntax OK"

# Verifica import e funzioni
grep -n "runExplorer\|explorer\|Explorer\|parallel" scripts/run-pipeline.js | head -15

# Test che il modulo si carichi senza errori
node -e "const e = require('./scripts/lib/explorer'); console.log('Explorer loaded:', typeof e.runExplorer)"
```

Nessun altro file deve essere stato modificato o creato oltre a:
- `scripts/lib/explorer.js` (nuovo)
- `scripts/run-pipeline.js` (modificato)
