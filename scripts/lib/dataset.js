"use strict";

/**
 * dataset.js — Training dataset generation from Agentic-BugBounty sessions.
 *
 * Three example types:
 *   A) Surface Extraction   — raw input → structured JSON
 *   B) Candidate Triage     — finding candidate → verdict
 *   C) Chain Hypothesis     — candidate list → chain pairs
 *
 * Output: JSONL in ChatML format (compatible with LM Studio / Axolotl / Unsloth).
 */

const fs   = require("node:fs");
const path = require("node:path");

// ─── System prompts per type ──────────────────────────────────────────────────

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

// ─── Expected output schemas per type ─────────────────────────────────────────

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

// ─── Builder Type A — Surface Extraction ─────────────────────────────────────

/**
 * Generates Type A examples from a recon context file or Explorer output.
 * Recon context is already saved in intelligence/recon_updates.json.
 * Explorer output is injected into logs as plain text.
 */
function buildSurfaceExtractionExamples(bundlePath, intelligenceDir, assetType) {
  const examples = [];

  // Read confirmed findings — their affected_component + researcher_notes
  // already contain surface data successfully extracted by the agent
  let bundle = null;
  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  } catch {
    return examples;
  }

  const findings = bundle.findings || [];

  for (const finding of findings) {
    // Build a synthetic input from the confirmed finding
    const component = finding.affected_component || "";
    const summary = finding.summary || "";
    const vulnClass = finding.vulnerability_class || "";

    if (!component || !summary) continue;

    // Input: description of the vulnerable component as if it were tool output
    const userContent = buildSurfaceInputFromFinding(finding, assetType);
    if (!userContent) continue;

    // Output: JSON structure of what should have been extracted
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

  // Read recon_updates.json if present
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
    } catch { /* ignore */ }
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

  // Extract endpoint from affected_component if it is an HTTP path
  if (component.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\s*\/[^\s]*/)) {
    const parts = component.split(/\s+/);
    const method = parts.length > 1 ? parts[0] : "unknown";
    const pathPart = parts.length > 1 ? parts[1] : parts[0];
    endpoints.push({
      path: pathPart,
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

// ─── Builder Type B — Candidate Triage ───────────────────────────────────────

/**
 * Generates Type B examples from triage_result.json.
 * Each Triager verdict is a labeled input→output example.
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
  } catch { /* ignore */ }

  const findings = bundle.findings || [];
  const triageResults = (triageResult?.results || []);

  for (const finding of findings) {
    const triage = triageResults.find((r) => r.report_id === finding.report_id);

    // Input: the candidate finding as the Triager would see it
    const userContent = buildTriageInput(finding, assetType);

    // Output: the Triager verdict (real if available, derived otherwise)
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

  // Also add unconfirmed candidates as negative examples
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
    poc_code: (finding.poc_code || "").slice(0, 500), // truncate long PoCs
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
  // Derive verdict from the finding itself (confirmed = TRIAGED)
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

// ─── Builder Type C — Chain Hypothesis ───────────────────────────────────────

/**
 * Generates Type C examples from chain findings (chain_meta.is_chain = true).
 * Each confirmed chain is an example of how to reason about composition.
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

  // For each chain finding, build the example as:
  // INPUT:  list of individual candidates with their primitives
  // OUTPUT: the chain hypothesis that was confirmed
  for (const chainFinding of chainFindings) {
    const meta = chainFinding.chain_meta;
    if (!meta.chain_steps || meta.chain_steps.length < 2) continue;

    // Reconstruct original candidates from chain data
    const candidates = meta.chain_steps.map((step) => ({
      id: step.report_id_source,
      vuln_class: step.vuln_class,
      component: step.component,
      primitive: step.primitive_provided,
      precondition: step.precondition,
    }));

    // Add other non-chain findings as "distractors" in the input
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

// ─── JSONL Writer ─────────────────────────────────────────────────────────────

function writeJsonl(filePath, examples) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });

  // Remove _meta field from final JSONL (only used for stats)
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
 * Generates the complete dataset from a pipeline session.
 *
 * @param {object} opts
 * @param {string} opts.bundlePath       — path to report_bundle.json
 * @param {string} opts.triagePath       — path to triage_result.json
 * @param {string} opts.intelligenceDir  — path to target intelligence/ folder
 * @param {string} opts.assetType        — webapp | mobileapp | browserext | executable | domains
 * @param {string} opts.outputDir        — output folder (default: data/training)
 * @param {boolean} opts.append          — if true, appends to existing files
 * @param {boolean} opts.includeMeta     — if true, includes _meta in output files
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

  // Write/update combined.jsonl with all shuffled examples
  const allExamples = shuffleArray([...surfaceExamples, ...triageExamples, ...chainExamples]);
  writeOrAppend(path.join(outputDir, "combined.jsonl"), allExamples);

  // Update manifest
  const manifestPath = path.join(outputDir, "manifest.json");
  let manifest = {};
  try {
    if (fs.existsSync(manifestPath)) {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    }
  } catch { /* ignore */ }

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
