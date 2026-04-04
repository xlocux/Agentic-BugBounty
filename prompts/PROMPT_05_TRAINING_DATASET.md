# PROMPT 05 — Training Dataset Export
# Esegui dopo i prompt 01-04, o in qualsiasi momento su sessioni accumulate.
# Crea scripts/export-training-data.js e scripts/lib/dataset.js
# Non modifica nessun file esistente.

---

Sei un ingegnere che sta evolvendo il framework Agentic-BugBounty.
Il tuo task è implementare un sistema di export del dataset di training
da tutte le sessioni accumulate dal framework.

Ogni sessione produce dati preziosi: surface map dell'Explorer, findings
del Researcher con PoC, chain trovate, verdetti del Triager. Questi dati
sono il materiale grezzo per fine-tunare un LLM leggero specializzato
nel surface discovery e nell'estrazione strutturata.

---

## ARCHITETTURA DEL DATASET

Il dataset è composto da tre tipi di esempio, uno per ogni task
che il modello leggero deve imparare:

### Tipo A — Surface Extraction
```
INPUT:  contenuto grezzo (HTTP headers, JS snippet, package.json, file listing)
OUTPUT: JSON strutturato { endpoints, auth_patterns, technologies, deps_vulnerable }
```
Sorgente: output dell'Explorer (ogni sessione) + recon context dell'Hybrid Recon.
Usato per: fine-tunare il task di structured extraction dal contenuto HTTP/codice.

### Tipo B — Candidate Triage
```
INPUT:  finding candidate con summary, affected_component, poc_type, observed_result
OUTPUT: { verdict, severity, rationale, missing_evidence }
```
Sorgente: triage_result.json — ogni verdetto del Triager è un esempio etichettato.
Usato per: fine-tunare il task di classificazione/validazione finding.

### Tipo C — Chain Hypothesis
```
INPUT:  lista di candidati con primitivi assegnati
OUTPUT: { chain_pairs: [...], rationale, estimated_severity }
```
Sorgente: chain finding dal report_bundle (quelli con chain_meta.is_chain = true).
Usato per: fine-tunare il task di chain synthesis.

---

## FORMATO OUTPUT

Ogni esempio è una riga JSONL nel formato **ChatML** (compatibile con
LM Studio, Ollama, llama.cpp, Axolotl, Unsloth):

```jsonl
{"messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}
```

Vengono prodotti tre file separati (uno per tipo) più un file combinato:

```
data/training/
  surface_extraction.jsonl     ← Tipo A
  candidate_triage.jsonl       ← Tipo B
  chain_hypothesis.jsonl       ← Tipo C
  combined.jsonl               ← tutti e tre mescolati e shuffled
  manifest.json                ← stats, timestamp, conteggi per asset_type
```

---

## FILE DA CREARE

### `scripts/lib/dataset.js`

```javascript
"use strict";

/**
 * dataset.js — Generazione dataset di training da sessioni Agentic-BugBounty.
 *
 * Tre tipi di esempio:
 *   A) Surface Extraction   — input grezzo → JSON strutturato
 *   B) Candidate Triage     — finding candidate → verdetto
 *   C) Chain Hypothesis     — lista candidati → chain pairs
 *
 * Output: JSONL in formato ChatML (compatibile LM Studio / Axolotl / Unsloth).
 */

const fs   = require("node:fs");
const path = require("node:path");

// ─── System prompts per tipo ──────────────────────────────────────────────────

const SYSTEM_PROMPTS = {
  surface_extraction: `You are a security-focused surface extraction engine.
Given raw HTTP response headers, JavaScript code snippets, dependency manifests,
or file listings from a target application, extract structured intelligence
about the attack surface.
Always respond with valid JSON only. No explanation, no markdown, no preamble.`,

  candidate_triage: `You are a bug bounty triage specialist.
Given a security finding candidate with its evidence, assess its validity,
assign a severity, and explain what additional evidence is needed if any.
Always respond with valid JSON only. No explanation, no markdown, no preamble.`,

  chain_hypothesis: `You are a vulnerability chain analyst.
Given a list of security finding candidates with their primitives,
identify realistic exploit chains where combining two or more findings
achieves higher impact than any single finding alone.
Always respond with valid JSON only. No explanation, no markdown, no preamble.`,
};

// ─── Schema degli output attesi per ogni tipo ─────────────────────────────────

const OUTPUT_SCHEMAS = {
  surface_extraction: {
    endpoints: "array of {path, method, auth_required, interesting_params, security_note}",
    auth_patterns: "array of {type, location, note}",
    technologies: "array of {name, version, category}",
    deps_vulnerable: "array of {package, version, cve_ids, severity, exploit_surface}",
  },
  candidate_triage: {
    verdict: "TRIAGED | INFORMATIVE | NOT_APPLICABLE | NEEDS_MORE_INFO",
    severity: "Critical | High | Medium | Low | Informative",
    rationale: "string — why this verdict",
    missing_evidence: "array of strings — what would upgrade verdict",
    cvss_notes: "string — which CVSS metrics are affected",
  },
  chain_hypothesis: {
    chain_pairs: "array of {step_1_id, step_1_primitive, step_2_id, step_2_primitive, chain_result, estimated_severity}",
    rationale: "string — why these combinations are viable",
  },
};

// ─── Builder Tipo A — Surface Extraction ─────────────────────────────────────

/**
 * Genera esempi di tipo A da un file di recon context o da output dell'Explorer.
 * Il recon context è già salvato in intelligence/recon_updates.json.
 * L'Explorer output è injected nei log come plain text.
 */
function buildSurfaceExtractionExamples(bundlePath, intelligenceDir, assetType) {
  const examples = [];

  // Leggi i finding confermati — il loro affected_component + researcher_notes
  // contengono già surface data estratta con successo dall'agente
  let bundle = null;
  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  } catch {
    return examples;
  }

  const findings = bundle.findings || [];

  for (const finding of findings) {
    // Costruisci un input sintetico dal finding confermato
    const component = finding.affected_component || "";
    const notes = finding.researcher_notes || "";
    const summary = finding.summary || "";
    const vulnClass = finding.vulnerability_class || "";

    if (!component || !summary) continue;

    // Input: descrizione del componente vulnerabile come se fosse output di un tool
    const userContent = buildSurfaceInputFromFinding(finding, assetType);
    if (!userContent) continue;

    // Output: struttura JSON di quello che si sarebbe dovuto estrarre
    const assistantContent = JSON.stringify({
      endpoints: extractEndpointsFromFinding(finding),
      auth_patterns: extractAuthPatternsFromFinding(finding),
      technologies: extractTechFromFinding(finding),
      deps_vulnerable: [],
    }, null, 2);

    examples.push({
      messages: [
        { role: "system", content: SYSTEM_PROMPTS.surface_extraction },
        { role: "user", content: userContent },
        { role: "assistant", content: assistantContent },
      ],
      _meta: {
        type: "surface_extraction",
        asset_type: assetType,
        source: "confirmed_finding",
        report_id: finding.report_id,
        vuln_class: vulnClass,
      },
    });
  }

  // Leggi recon_updates.json se presente
  const reconPath = path.join(intelligenceDir, "recon_updates.json");
  if (fs.existsSync(reconPath)) {
    try {
      const reconUpdates = JSON.parse(fs.readFileSync(reconPath, "utf8"));
      for (const update of reconUpdates) {
        if (!update.signal) continue;
        examples.push({
          messages: [
            { role: "system", content: SYSTEM_PROMPTS.surface_extraction },
            {
              role: "user",
              content: `Analyze this reconnaissance signal and extract structured surface intelligence:\n\n${update.signal}`,
            },
            {
              role: "assistant",
              content: JSON.stringify({
                endpoints: [],
                auth_patterns: [],
                technologies: extractTechFromSignal(update.signal),
                deps_vulnerable: [],
              }, null, 2),
            },
          ],
          _meta: {
            type: "surface_extraction",
            asset_type: assetType,
            source: "recon_update",
            detected_at: update.detected_at,
          },
        });
      }
    } catch { /* ignora */ }
  }

  return examples;
}

function buildSurfaceInputFromFinding(finding, assetType) {
  const component = finding.affected_component || "";
  const notes = finding.researcher_notes || "";
  const summary = finding.summary || "";

  if (assetType === "webapp" || assetType === "domains") {
    return [
      `Target asset type: ${assetType}`,
      `Analyze the following HTTP endpoint information and extract surface intelligence:`,
      ``,
      `Component: ${component}`,
      notes ? `Researcher notes: ${notes}` : "",
      `Summary context: ${summary}`,
    ].filter(Boolean).join("\n");
  }

  if (assetType === "mobileapp") {
    return [
      `Target asset type: mobile application`,
      `Analyze the following mobile application component and extract surface intelligence:`,
      ``,
      `Component: ${component}`,
      notes ? `Context: ${notes}` : "",
    ].filter(Boolean).join("\n");
  }

  if (assetType === "browserext") {
    return [
      `Target asset type: browser extension`,
      `Analyze the following browser extension component:`,
      ``,
      `Component: ${component}`,
      notes ? `Context: ${notes}` : "",
    ].filter(Boolean).join("\n");
  }

  if (assetType === "executable") {
    return [
      `Target asset type: binary/executable`,
      `Analyze the following binary component:`,
      ``,
      `Component: ${component}`,
      notes ? `Context: ${notes}` : "",
    ].filter(Boolean).join("\n");
  }

  return null;
}

function extractEndpointsFromFinding(finding) {
  const component = finding.affected_component || "";
  const endpoints = [];

  // Estrai endpoint dall'affected_component se è un path HTTP
  if (component.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\s*\/[^\s]*/)) {
    const parts = component.split(/\s+/);
    const method = parts.length > 1 ? parts[0] : "unknown";
    const path_part = parts.length > 1 ? parts[1] : parts[0];
    endpoints.push({
      path: path_part,
      method: method,
      auth_required: !["informative", "low"].includes(
        (finding.severity_claimed || "").toLowerCase()
      ),
      interesting_params: extractParamsFromPoC(finding.poc_code || ""),
      security_note: (finding.summary || "").slice(0, 100),
    });
  }

  return endpoints;
}

function extractParamsFromPoC(pocCode) {
  const params = [];
  const matches = pocCode.match(/[?&]([a-z_][a-z0-9_]*)=/gi) || [];
  for (const m of matches) {
    const param = m.replace(/[?&]/, "").replace("=", "");
    if (!params.includes(param)) params.push(param);
  }
  return params.slice(0, 5);
}

function extractAuthPatternsFromFinding(finding) {
  const patterns = [];
  const text = [
    finding.summary || "",
    finding.researcher_notes || "",
    finding.poc_code || "",
  ].join(" ").toLowerCase();

  if (text.includes("jwt") || text.includes("json web token")) {
    patterns.push({ type: "JWT", location: "header", note: "JWT authentication detected" });
  }
  if (text.includes("bearer ")) {
    patterns.push({ type: "API_key", location: "header", note: "Bearer token authentication" });
  }
  if (text.includes("session") && text.includes("cookie")) {
    patterns.push({ type: "session_cookie", location: "cookie", note: "Session cookie authentication" });
  }
  if (text.includes("oauth") || text.includes("authorization_code")) {
    patterns.push({ type: "OAuth", location: "header", note: "OAuth 2.0 flow detected" });
  }

  return patterns;
}

function extractTechFromFinding(finding) {
  const tech = [];
  const text = [
    finding.summary || "",
    finding.researcher_notes || "",
    finding.vulnerable_code_snippet?.file || "",
  ].join(" ");

  const techPatterns = [
    { pattern: /\blaravel\b/i, name: "Laravel", category: "framework" },
    { pattern: /\bdjango\b/i, name: "Django", category: "framework" },
    { pattern: /\bspring\b/i, name: "Spring", category: "framework" },
    { pattern: /\bnext\.?js\b/i, name: "Next.js", category: "framework" },
    { pattern: /\breact\b/i, name: "React", category: "frontend" },
    { pattern: /\bexpress\b/i, name: "Express", category: "framework" },
    { pattern: /\bphp\b/i, name: "PHP", category: "language" },
    { pattern: /\bnode\.?js\b/i, name: "Node.js", category: "runtime" },
    { pattern: /\bpython\b/i, name: "Python", category: "language" },
    { pattern: /\bruby\b/i, name: "Ruby", category: "language" },
    { pattern: /\bgraphql\b/i, name: "GraphQL", category: "api" },
    { pattern: /\bmongo(db)?\b/i, name: "MongoDB", category: "database" },
    { pattern: /\bpostgres\b/i, name: "PostgreSQL", category: "database" },
    { pattern: /\bmysql\b/i, name: "MySQL", category: "database" },
    { pattern: /\bredis\b/i, name: "Redis", category: "cache" },
    { pattern: /\belasticsearch\b/i, name: "Elasticsearch", category: "search" },
    { pattern: /\bkubernetes\b/i, name: "Kubernetes", category: "infrastructure" },
    { pattern: /\baws\b/i, name: "AWS", category: "cloud" },
  ];

  for (const { pattern, name, category } of techPatterns) {
    if (pattern.test(text) && !tech.find((t) => t.name === name)) {
      tech.push({ name, version: null, category });
    }
  }

  return tech;
}

function extractTechFromSignal(signal) {
  const tech = [];
  const techPatterns = [
    { pattern: /Laravel|Django|Spring|Next\.js|Express|Rails|Flask|FastAPI/i },
    { pattern: /PHP|Node\.js|Python|Ruby|Java|Go|Rust/i },
    { pattern: /MongoDB|PostgreSQL|MySQL|Redis|Elasticsearch/i },
    { pattern: /Kubernetes|Docker|AWS|GCP|Azure/i },
  ];

  for (const { pattern } of techPatterns) {
    const match = signal.match(pattern);
    if (match) {
      tech.push({ name: match[0], version: null, category: "detected" });
    }
  }

  return tech;
}

// ─── Builder Tipo B — Candidate Triage ───────────────────────────────────────

/**
 * Genera esempi di tipo B dal triage_result.json.
 * Ogni verdetto del Triager è un esempio input→output etichettato.
 */
function buildCandidateTriageExamples(bundlePath, triagePath, assetType) {
  const examples = [];

  let bundle = null;
  let triageResult = null;

  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  } catch { return examples; }

  try {
    triageResult = fs.existsSync(triagePath)
      ? JSON.parse(fs.readFileSync(triagePath, "utf8"))
      : null;
  } catch { /* ignora */ }

  const findings = bundle.findings || [];
  const triageResults = (triageResult?.results || []);

  for (const finding of findings) {
    const triage = triageResults.find((r) => r.report_id === finding.report_id);

    // Input: il finding candidate come lo vedrebbe il Triager
    const userContent = buildTriageInput(finding, assetType);

    // Output: il verdetto del Triager (reale se disponibile, derivato altrimenti)
    const verdict = triage
      ? buildTriageOutputFromResult(finding, triage)
      : buildTriageOutputFromFinding(finding);

    if (!userContent || !verdict) continue;

    examples.push({
      messages: [
        { role: "system", content: SYSTEM_PROMPTS.candidate_triage },
        { role: "user", content: userContent },
        { role: "assistant", content: JSON.stringify(verdict, null, 2) },
      ],
      _meta: {
        type: "candidate_triage",
        asset_type: assetType,
        source: triage ? "real_triage" : "derived",
        report_id: finding.report_id,
        vuln_class: finding.vulnerability_class,
        severity: finding.severity_claimed,
      },
    });
  }

  // Aggiungi anche i candidati non confermati come esempi negativi
  const unconfirmed = bundle.unconfirmed_candidates || [];
  for (const candidate of unconfirmed) {
    if (!candidate.reason_not_confirmed) continue;
    if (candidate.reason_not_confirmed.startsWith("absorbed into chain")) continue;

    const userContent = buildTriageInput(candidate, assetType);
    if (!userContent) continue;

    const verdict = {
      verdict: "NEEDS_MORE_INFO",
      severity: candidate.severity_claimed || "Low",
      rationale: candidate.reason_not_confirmed,
      missing_evidence: ["Working PoC demonstrating actual impact", "Evidence of exploitability"],
      cvss_notes: "Cannot assign CVSS without confirmed exploitation path",
    };

    examples.push({
      messages: [
        { role: "system", content: SYSTEM_PROMPTS.candidate_triage },
        { role: "user", content: userContent },
        { role: "assistant", content: JSON.stringify(verdict, null, 2) },
      ],
      _meta: {
        type: "candidate_triage",
        asset_type: assetType,
        source: "unconfirmed_candidate",
        vuln_class: candidate.vulnerability_class,
      },
    });
  }

  return examples;
}

function buildTriageInput(finding, assetType) {
  if (!finding.finding_title && !finding.vulnerability_class) return null;

  return JSON.stringify({
    asset_type: assetType,
    report_id: finding.report_id || "UNKNOWN",
    finding_title: finding.finding_title || "",
    vulnerability_class: finding.vulnerability_class || "",
    affected_component: finding.affected_component || "",
    severity_claimed: finding.severity_claimed || "",
    cvss_vector_claimed: finding.cvss_vector_claimed || "",
    summary: finding.summary || "",
    steps_to_reproduce: finding.steps_to_reproduce || [],
    poc_type: finding.poc_type || "",
    poc_code: (finding.poc_code || "").slice(0, 500), // tronca i PoC lunghi
    observed_result: finding.observed_result || "",
    impact_claimed: finding.impact_claimed || "",
  }, null, 2);
}

function buildTriageOutputFromResult(finding, triage) {
  return {
    verdict: triage.triage_verdict || "INFORMATIVE",
    severity: triage.analyst_severity || finding.severity_claimed,
    rationale: triage.triage_summary
      ? triage.triage_summary.slice(0, 300)
      : "Finding validated by triage agent",
    missing_evidence: triage.nmi_questions || [],
    cvss_notes: triage.analyst_cvss_vector
      ? `Analyst CVSS: ${triage.analyst_cvss_vector} (score: ${triage.analyst_cvss_score})`
      : "CVSS confirmed as claimed",
  };
}

function buildTriageOutputFromFinding(finding) {
  // Deriva il verdetto dal finding stesso (confirmed = TRIAGED)
  if (finding.confirmation_status === "confirmed") {
    return {
      verdict: "TRIAGED",
      severity: finding.severity_claimed || "Medium",
      rationale: `${finding.vulnerability_class} confirmed with working PoC. ${(finding.summary || "").slice(0, 200)}`,
      missing_evidence: [],
      cvss_notes: `CVSS vector: ${finding.cvss_vector_claimed || "not specified"}`,
    };
  }
  return null;
}

// ─── Builder Tipo C — Chain Hypothesis ───────────────────────────────────────

/**
 * Genera esempi di tipo C dai chain finding (chain_meta.is_chain = true).
 * Ogni chain confermata è un esempio di come ragionare sulla composizione.
 */
function buildChainHypothesisExamples(bundlePath, assetType) {
  const examples = [];

  let bundle = null;
  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  } catch { return examples; }

  const findings = bundle.findings || [];
  const chainFindings = findings.filter(
    (f) => f.chain_meta && f.chain_meta.is_chain === true
  );

  if (chainFindings.length === 0) return examples;

  // Per ogni chain finding, costruisci l'esempio come:
  // INPUT:  lista dei candidati individuali con i loro primitivi
  // OUTPUT: la chain hypothesis che è stata confermata
  for (const chainFinding of chainFindings) {
    const meta = chainFinding.chain_meta;
    if (!meta.chain_steps || meta.chain_steps.length < 2) continue;

    // Ricostruisci i candidati originali dai dati della chain
    const candidates = meta.chain_steps.map((step) => ({
      id: step.report_id_source,
      vuln_class: step.vuln_class,
      component: step.component,
      primitive: step.primitive_provided,
      precondition: step.precondition,
    }));

    // Aggiungi altri finding non-chain come "distractors" nell'input
    const otherFindings = findings
      .filter((f) => !f.chain_meta?.is_chain && !meta.absorbed_finding_ids?.includes(f.report_id))
      .slice(0, 3)
      .map((f) => ({
        id: f.report_id,
        vuln_class: f.vulnerability_class || "unknown",
        component: f.affected_component || "unknown",
        primitive: derivePrimitive(f.vulnerability_class),
        precondition: null,
      }));

    const allCandidates = [...candidates, ...otherFindings];

    const userContent = [
      `Asset type: ${assetType}`,
      ``,
      `You have the following security finding candidates. Identify which ones can be chained for higher impact:`,
      ``,
      JSON.stringify(allCandidates, null, 2),
    ].join("\n");

    const assistantContent = JSON.stringify({
      chain_pairs: meta.chain_steps.map((step, i) => {
        if (i === 0) return null;
        return {
          step_1_id: meta.chain_steps[i - 1].report_id_source,
          step_1_primitive: meta.chain_steps[i - 1].primitive_provided,
          step_2_id: step.report_id_source,
          step_2_primitive: step.primitive_provided,
          chain_result: chainFinding.finding_title || "Chained exploitation path",
          estimated_severity: chainFinding.severity_claimed || "High",
        };
      }).filter(Boolean),
      rationale: meta.chain_severity_rationale || chainFinding.summary || "",
    }, null, 2);

    examples.push({
      messages: [
        { role: "system", content: SYSTEM_PROMPTS.chain_hypothesis },
        { role: "user", content: userContent },
        { role: "assistant", content: assistantContent },
      ],
      _meta: {
        type: "chain_hypothesis",
        asset_type: assetType,
        source: "confirmed_chain",
        report_id: chainFinding.report_id,
        chain_length: meta.chain_steps.length,
        primitives: meta.primitives_used || [],
      },
    });
  }

  return examples;
}

function derivePrimitive(vulnClass) {
  if (!vulnClass) return "unknown";
  const vc = vulnClass.toLowerCase();

  const map = {
    "open_redirect": "redirect_control",
    "ssrf": "server_request",
    "xss": "js_execution",
    "stored_xss": "js_execution",
    "reflected_xss": "js_execution",
    "dom_xss": "js_execution",
    "csrf": "request_forgery",
    "cors": "origin_escalation",
    "idor": "id_control",
    "broken_access_control": "id_control",
    "sql_injection": "sql_injection",
    "sqli": "sql_injection",
    "path_traversal": "file_read",
    "lfi": "file_read",
    "rce": "code_exec",
    "ssti": "template_injection",
    "xxe": "xxe",
    "deserialization": "deserialization",
    "http_smuggling": "desync",
    "prototype_pollution": "prototype_pollution",
    "jwt": "token_theft",
    "session": "token_theft",
    "race_condition": "race_condition",
    "auth_bypass": "auth_bypass",
    "info_disclosure": "info_leak",
    "information_disclosure": "info_leak",
    "command_injection": "command_injection",
    "crlf": "header_injection",
    "file_upload": "file_write",
    "mass_assignment": "id_control",
    "nosql_injection": "nosql_injection",
    "ldap_injection": "ldap_injection",
  };

  for (const [key, primitive] of Object.entries(map)) {
    if (vc.includes(key)) return primitive;
  }
  return "unknown";
}

// ─── Writer JSONL ─────────────────────────────────────────────────────────────

function writeJsonl(filePath, examples) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });

  // Rimuovi il campo _meta dal JSONL finale (è solo per stats)
  const lines = examples.map((ex) => {
    const { _meta, ...rest } = ex;
    return JSON.stringify(rest);
  });

  fs.writeFileSync(filePath, lines.join("\n") + "\n", "utf8");
  return lines.length;
}

function writeManifest(manifestPath, stats) {
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(manifestPath, JSON.stringify(stats, null, 2) + "\n", "utf8");
}

// ─── Shuffle ──────────────────────────────────────────────────────────────────

function shuffleArray(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/**
 * Genera il dataset completo da una sessione del pipeline.
 *
 * @param {object} opts
 * @param {string} opts.bundlePath       — path al report_bundle.json
 * @param {string} opts.triagePath       — path al triage_result.json
 * @param {string} opts.intelligenceDir  — path alla cartella intelligence/ del target
 * @param {string} opts.assetType        — webapp | mobileapp | browserext | executable | domains
 * @param {string} opts.outputDir        — cartella di output (default: data/training)
 * @param {boolean} opts.append          — se true, appende ai file esistenti
 * @param {boolean} opts.includeMeta     — se true, include _meta nei file di output
 * @returns {{ surfaceCount, triageCount, chainCount, totalCount }}
 */
function exportDataset(opts) {
  const {
    bundlePath,
    triagePath,
    intelligenceDir,
    assetType,
    outputDir = path.resolve("data", "training"),
    append = true,
    includeMeta = false,
  } = opts;

  if (!fs.existsSync(bundlePath)) {
    throw new Error(`Bundle not found: ${bundlePath}`);
  }

  const surfaceExamples = buildSurfaceExtractionExamples(bundlePath, intelligenceDir, assetType);
  const triageExamples  = buildCandidateTriageExamples(bundlePath, triagePath, assetType);
  const chainExamples   = buildChainHypothesisExamples(bundlePath, assetType);

  fs.mkdirSync(outputDir, { recursive: true });

  const writeOrAppend = (filePath, examples) => {
    if (examples.length === 0) return 0;
    const lines = examples.map((ex) => {
      const data = includeMeta ? ex : (() => { const { _meta, ...rest } = ex; return rest; })();
      return JSON.stringify(data);
    });
    const content = lines.join("\n") + "\n";
    if (append && fs.existsSync(filePath)) {
      fs.appendFileSync(filePath, content, "utf8");
    } else {
      fs.writeFileSync(filePath, content, "utf8");
    }
    return lines.length;
  };

  const surfaceCount = writeOrAppend(
    path.join(outputDir, "surface_extraction.jsonl"), surfaceExamples
  );
  const triageCount = writeOrAppend(
    path.join(outputDir, "candidate_triage.jsonl"), triageExamples
  );
  const chainCount = writeOrAppend(
    path.join(outputDir, "chain_hypothesis.jsonl"), chainExamples
  );

  // Scrivi/aggiorna il combined.jsonl con tutti gli esempi shuffled
  const allExamples = shuffleArray([...surfaceExamples, ...triageExamples, ...chainExamples]);
  writeOrAppend(path.join(outputDir, "combined.jsonl"), allExamples);

  // Aggiorna il manifest
  const manifestPath = path.join(outputDir, "manifest.json");
  let manifest = {};
  try {
    if (fs.existsSync(manifestPath)) {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    }
  } catch { /* ignora */ }

  const now = new Date().toISOString();
  manifest.last_updated = now;
  manifest.total_examples = (manifest.total_examples || 0) + surfaceCount + triageCount + chainCount;
  manifest.by_type = {
    surface_extraction: (manifest.by_type?.surface_extraction || 0) + surfaceCount,
    candidate_triage:   (manifest.by_type?.candidate_triage   || 0) + triageCount,
    chain_hypothesis:   (manifest.by_type?.chain_hypothesis    || 0) + chainCount,
  };
  manifest.by_asset_type = manifest.by_asset_type || {};
  manifest.by_asset_type[assetType] = (manifest.by_asset_type[assetType] || 0)
    + surfaceCount + triageCount + chainCount;
  manifest.sessions = manifest.sessions || [];
  manifest.sessions.push({
    exported_at: now,
    asset_type: assetType,
    bundle_path: bundlePath,
    surface: surfaceCount,
    triage: triageCount,
    chain: chainCount,
  });

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");

  return { surfaceCount, triageCount, chainCount, totalCount: surfaceCount + triageCount + chainCount };
}

module.exports = { exportDataset, derivePrimitive };
```

---

### `scripts/export-training-data.js`

```javascript
#!/usr/bin/env node
"use strict";

/**
 * export-training-data.js
 *
 * Esporta il dataset di training da sessioni accumulate del framework.
 * Supporta tutti gli asset type: webapp, mobileapp, browserext, executable, domains.
 *
 * Usage:
 *   # Esporta da un target specifico
 *   node scripts/export-training-data.js --target <n>
 *
 *   # Esporta da tutti i target
 *   node scripts/export-training-data.js --all
 *
 *   # Esporta da un bundle specifico
 *   node scripts/export-training-data.js --bundle path/to/report_bundle.json --asset webapp
 *
 *   # Sovrascrive invece di appendere
 *   node scripts/export-training-data.js --all --no-append
 *
 *   # Specifica output directory
 *   node scripts/export-training-data.js --all --out data/my-dataset
 *
 *   # Mostra stats senza esportare
 *   node scripts/export-training-data.js --stats
 */

const fs   = require("node:fs");
const path = require("node:path");
const { exportDataset } = require("./lib/dataset");

// ─── Colori ───────────────────────────────────────────────────────────────────

const C = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  cyan:    "\x1b[36m",
  yellow:  "\x1b[33m",
  green:   "\x1b[32m",
  red:     "\x1b[31m",
  magenta: "\x1b[35m",
};

function log(msg)  { process.stdout.write(`${msg}\n`); }
function ok(msg)   { log(`  ${C.green}✓${C.reset}  ${msg}`); }
function warn(msg) { log(`  ${C.yellow}⚠${C.reset}  ${msg}`); }
function err(msg)  { log(`  ${C.red}✗${C.reset}  ${msg}`); }
function dim(msg)  { log(`  ${C.dim}${msg}${C.reset}`); }

// ─── Arg parsing ──────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const parsed = {
    target:   null,
    all:      false,
    bundle:   null,
    asset:    null,
    out:      path.resolve("data", "training"),
    append:   true,
    stats:    false,
    help:     false,
  };

  for (let i = 2; i < argv.length; i++) {
    const v = argv[i];
    if (v === "--target")     parsed.target   = argv[++i];
    else if (v === "--all")   parsed.all      = true;
    else if (v === "--bundle") parsed.bundle  = argv[++i];
    else if (v === "--asset") parsed.asset    = argv[++i];
    else if (v === "--out")   parsed.out      = path.resolve(argv[++i]);
    else if (v === "--no-append") parsed.append = false;
    else if (v === "--stats") parsed.stats    = true;
    else if (v === "--help")  parsed.help     = true;
  }

  return parsed;
}

// ─── Resolvers ────────────────────────────────────────────────────────────────

function resolveTargetDir(targetRef) {
  // Prova come numero intero (targets/1/), come path diretto, o come nome
  const asInt = parseInt(targetRef, 10);
  if (!isNaN(asInt)) {
    return path.resolve("targets", String(asInt));
  }
  if (fs.existsSync(targetRef)) return path.resolve(targetRef);
  return path.resolve("targets", targetRef);
}

function resolveTargetConfig(targetDir) {
  const configPath = path.join(targetDir, "target.json");
  if (!fs.existsSync(configPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return null;
  }
}

function collectSessionsFromTarget(targetDir) {
  const sessions = [];
  const config = resolveTargetConfig(targetDir);
  const assetType = config?.asset_type || "webapp";
  const findingsBase = path.join(targetDir, "findings");

  // Bundle principale
  const bundlePath = path.join(findingsBase, "confirmed", "report_bundle.json");
  const triagePath = path.join(findingsBase, "triage_result.json");
  const intelligenceDir = path.join(targetDir, "intelligence");

  if (fs.existsSync(bundlePath)) {
    sessions.push({ bundlePath, triagePath, intelligenceDir, assetType, targetDir });
  }

  return sessions;
}

function collectAllTargets() {
  const targetsDir = path.resolve("targets");
  if (!fs.existsSync(targetsDir)) return [];

  return fs.readdirSync(targetsDir)
    .map((name) => path.join(targetsDir, name))
    .filter((p) => fs.statSync(p).isDirectory())
    .flatMap((targetDir) => collectSessionsFromTarget(targetDir));
}

// ─── Stats display ────────────────────────────────────────────────────────────

function showStats(outputDir) {
  const manifestPath = path.join(outputDir, "manifest.json");

  if (!fs.existsSync(manifestPath)) {
    warn("No manifest found. Run an export first.");
    return;
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const bar = "─".repeat(60);

  log(`\n${C.bold}${C.cyan}TRAINING DATASET STATS${C.reset}`);
  log(bar);
  log(`  Output dir    : ${outputDir}`);
  log(`  Last updated  : ${manifest.last_updated || "unknown"}`);
  log(`  Total examples: ${C.bold}${manifest.total_examples || 0}${C.reset}`);
  log(``);
  log(`  ${C.bold}By type:${C.reset}`);
  for (const [type, count] of Object.entries(manifest.by_type || {})) {
    log(`    ${type.padEnd(25)} ${C.yellow}${count}${C.reset} examples`);
  }
  log(``);
  log(`  ${C.bold}By asset type:${C.reset}`);
  for (const [asset, count] of Object.entries(manifest.by_asset_type || {})) {
    log(`    ${asset.padEnd(25)} ${C.yellow}${count}${C.reset} examples`);
  }
  log(``);
  log(`  ${C.bold}Sessions exported:${C.reset} ${(manifest.sessions || []).length}`);

  // Mostra dimensioni dei file
  log(``);
  log(`  ${C.bold}Files:${C.reset}`);
  const files = [
    "surface_extraction.jsonl",
    "candidate_triage.jsonl",
    "chain_hypothesis.jsonl",
    "combined.jsonl",
  ];
  for (const file of files) {
    const filePath = path.join(outputDir, file);
    if (fs.existsSync(filePath)) {
      const size = fs.statSync(filePath).size;
      const lines = fs.readFileSync(filePath, "utf8").split("\n").filter(Boolean).length;
      log(`    ${file.padEnd(30)} ${lines} rows, ${(size / 1024).toFixed(1)} KB`);
    } else {
      log(`    ${file.padEnd(30)} ${C.dim}(not yet generated)${C.reset}`);
    }
  }

  log(`\n  ${C.dim}LM Studio: load combined.jsonl as fine-tuning dataset${C.reset}`);
  log(`  ${C.dim}Axolotl:   set dataset_type: chat_template, format: chatml${C.reset}`);
  log(bar + "\n");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    log(`\n${C.bold}export-training-data.js${C.reset} — Export fine-tuning dataset from pipeline sessions\n`);
    log(`Usage:`);
    log(`  node scripts/export-training-data.js --target <n>        Export from target N`);
    log(`  node scripts/export-training-data.js --all               Export from all targets`);
    log(`  node scripts/export-training-data.js --bundle <path> --asset <type>`);
    log(`  node scripts/export-training-data.js --stats             Show dataset stats`);
    log(`  node scripts/export-training-data.js --all --no-append   Overwrite existing dataset`);
    log(`  node scripts/export-training-data.js --all --out <dir>   Custom output directory\n`);
    log(`Asset types: webapp | mobileapp | browserext | executable | domains\n`);
    return;
  }

  if (args.stats) {
    showStats(args.out);
    return;
  }

  const bar = "═".repeat(60);
  log(`\n${C.magenta}${bar}${C.reset}`);
  log(`${C.bold}${C.magenta}TRAINING DATASET EXPORT${C.reset}`);
  log(`${C.magenta}${bar}${C.reset}\n`);
  log(`  Output dir : ${args.out}`);
  log(`  Mode       : ${args.append ? "append" : "overwrite"}\n`);

  let sessions = [];

  if (args.bundle) {
    // Esporta da bundle specifico
    if (!args.asset) {
      err("--bundle requires --asset <type>");
      process.exit(1);
    }
    const triagePath = path.join(path.dirname(path.dirname(args.bundle)), "triage_result.json");
    const intelligenceDir = path.join(path.dirname(path.dirname(args.bundle)), "intelligence");
    sessions = [{ bundlePath: path.resolve(args.bundle), triagePath, intelligenceDir, assetType: args.asset }];

  } else if (args.target) {
    const targetDir = resolveTargetDir(args.target);
    if (!fs.existsSync(targetDir)) {
      err(`Target directory not found: ${targetDir}`);
      process.exit(1);
    }
    sessions = collectSessionsFromTarget(targetDir);

  } else if (args.all) {
    sessions = collectAllTargets();

  } else {
    err("Specify --target <n>, --all, or --bundle <path> --asset <type>");
    err("Use --help for usage information.");
    process.exit(1);
  }

  if (sessions.length === 0) {
    warn("No sessions found with confirmed findings. Run the pipeline first.");
    return;
  }

  log(`  Found ${C.bold}${sessions.length}${C.reset} session(s) to export\n`);

  let totalSurface = 0;
  let totalTriage  = 0;
  let totalChain   = 0;

  for (const session of sessions) {
    const label = path.relative(process.cwd(), session.bundlePath);
    process.stdout.write(`  Exporting ${C.dim}${label}${C.reset} [${session.assetType}]... `);

    try {
      const result = exportDataset({
        bundlePath:      session.bundlePath,
        triagePath:      session.triagePath,
        intelligenceDir: session.intelligenceDir,
        assetType:       session.assetType,
        outputDir:       args.out,
        append:          args.append,
      });

      process.stdout.write(
        `${C.green}✓${C.reset} +${result.surfaceCount}A +${result.triageCount}B +${result.chainCount}C\n`
      );

      totalSurface += result.surfaceCount;
      totalTriage  += result.triageCount;
      totalChain   += result.chainCount;

    } catch (e) {
      process.stdout.write(`${C.red}✗${C.reset} ${e.message}\n`);
    }
  }

  const total = totalSurface + totalTriage + totalChain;

  log(`\n${"─".repeat(60)}`);
  log(`${C.bold}Export complete${C.reset}`);
  log(`  Surface extraction (A) : ${C.yellow}${totalSurface}${C.reset} examples`);
  log(`  Candidate triage   (B) : ${C.yellow}${totalTriage}${C.reset} examples`);
  log(`  Chain hypothesis   (C) : ${C.yellow}${totalChain}${C.reset} examples`);
  log(`  Total                  : ${C.bold}${C.yellow}${total}${C.reset} examples`);
  log(``);
  log(`  ${C.bold}Output files:${C.reset}`);
  log(`    ${args.out}/surface_extraction.jsonl`);
  log(`    ${args.out}/candidate_triage.jsonl`);
  log(`    ${args.out}/chain_hypothesis.jsonl`);
  log(`    ${args.out}/combined.jsonl        ← use this for LM Studio`);
  log(`    ${args.out}/manifest.json`);
  log(``);
  log(`  ${C.dim}LM Studio: File → Open Dataset → combined.jsonl${C.reset}`);
  log(`  ${C.dim}Axolotl:   dataset_type: chat_template, format: chatml${C.reset}`);
  log(`  ${C.dim}Unsloth:   from datasets import load_dataset; load_dataset("json", data_files="combined.jsonl")${C.reset}`);
  log(`${"─".repeat(60)}\n`);
}

main().catch((e) => {
  process.stderr.write(`Error: ${e.message}\n`);
  process.exit(1);
});
```

---

## MODIFICA A `package.json`

Trova il blocco `"scripts"` nel `package.json` della root del progetto.
Aggiungi queste voci:

```json
"dataset:export":     "node scripts/export-training-data.js --all",
"dataset:export:new": "node scripts/export-training-data.js --all --no-append",
"dataset:stats":      "node scripts/export-training-data.js --stats"
```

---

## MODIFICA A `scripts/run-pipeline.js`

### Auto-export al termine del pipeline

Trova il blocco finale di `main()` che stampa i report completati:

```javascript
  const readyCount = fs.existsSync(context.reportsDir)
    ? fs.readdirSync(context.reportsDir).filter((entry) => entry.endsWith(".md")).length
    : 0;
  printFlavour("pipeline_complete");
  logEvent(runLog, `Pipeline complete with ${readyCount} H1-ready report(s)`, "ok");
```

Sostituiscilo con:

```javascript
  const readyCount = fs.existsSync(context.reportsDir)
    ? fs.readdirSync(context.reportsDir).filter((entry) => entry.endsWith(".md")).length
    : 0;
  printFlavour("pipeline_complete");
  logEvent(runLog, `Pipeline complete with ${readyCount} H1-ready report(s)`, "ok");

  // Auto-export dataset di training al termine di ogni pipeline completato
  try {
    const { exportDataset } = require("./lib/dataset");
    const datasetResult = exportDataset({
      bundlePath:      bundlePath,
      triagePath:      triagePath,
      intelligenceDir: context.intelligenceDir,
      assetType:       context.asset,
      outputDir:       path.resolve("data", "training"),
      append:          true,
    });
    if (datasetResult.totalCount > 0) {
      logEvent(runLog, `Training dataset: +${datasetResult.totalCount} examples exported (A:${datasetResult.surfaceCount} B:${datasetResult.triageCount} C:${datasetResult.chainCount})`, "ok");
      process.stdout.write(`  ${C.cyan}[dataset]${C.reset} +${datasetResult.totalCount} training examples → data/training/\n`);
    }
  } catch (datasetErr) {
    logEvent(runLog, `Training dataset export failed: ${datasetErr.message}`, "warn");
  }
```

---

## VERIFICA FINALE

```bash
# Syntax check
node --check scripts/lib/dataset.js      && echo "dataset.js OK"
node --check scripts/export-training-data.js && echo "export script OK"

# Test di caricamento moduli
node -e "
  const { exportDataset } = require('./scripts/lib/dataset');
  console.log('exportDataset:', typeof exportDataset);
"

# Test su un target esistente (se presente)
node scripts/export-training-data.js --stats

# Export da tutti i target
node scripts/export-training-data.js --all

# Verifica struttura output
ls -la data/training/ 2>/dev/null || echo "No sessions yet — run the pipeline first"
```

Dopo aver eseguito almeno una sessione del pipeline completa:

```bash
# Conta le righe per tipo
wc -l data/training/*.jsonl

# Valida che il formato sia JSONL valido (ogni riga deve essere JSON)
node -e "
  const fs = require('fs');
  const lines = fs.readFileSync('data/training/combined.jsonl', 'utf8')
    .split('\n').filter(Boolean);
  let ok = 0, fail = 0;
  for (const line of lines) {
    try { JSON.parse(line); ok++; } catch { fail++; }
  }
  console.log('Valid:', ok, 'Invalid:', fail);
"
```

Nessun file esistente deve essere stato modificato tranne `package.json`
e `scripts/run-pipeline.js`.
