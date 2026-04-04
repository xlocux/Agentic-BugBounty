"use strict";

const { validate } = require("./schema-validator");

// ── Surface structure ─────────────────────────────────────────────────────────

/**
 * Returns an empty, schema-valid attack_surface.json v2 skeleton.
 * @param {string} target
 * @returns {object}
 */
function buildEmptySurface(target) {
  return {
    schema_version:   2,
    generated_at:     new Date().toISOString(),
    target,
    http_layer:       [],
    authentication:   [],
    authorization:    [],
    input_parsing:    [],
    async_ipc:        [],
    third_party:      [],
    environment:      [],
    javascript_sinks: [],
    external_domains: []
  };
}

/**
 * Deep-merges two surface objects by concatenating all category arrays.
 * Does not deduplicate — caller is responsible if needed.
 * @param {object} base
 * @param {object} addition
 * @returns {object} merged surface
 */
function mergeSurface(base, addition) {
  const categories = [
    "http_layer", "authentication", "authorization", "input_parsing",
    "async_ipc", "third_party", "environment", "javascript_sinks", "external_domains"
  ];
  const merged = { ...base, generated_at: new Date().toISOString() };
  for (const cat of categories) {
    merged[cat] = [...(base[cat] || []), ...(addition[cat] || [])];
  }
  return merged;
}

/**
 * Validates and returns the surface. Throws if invalid.
 * @param {object} surface
 * @returns {object}
 */
function normalizeSurface(surface) {
  validate("attack-surface", surface);
  return surface;
}

/**
 * Builds the LLM prompt for a batch of files.
 * Instructs the cheap model to extract structured attack surface entries.
 *
 * @param {string}   target
 * @param {object[]} files   subset of file_manifest.json files
 * @param {string[]} contents  file contents (same order as files)
 * @returns {string} prompt text
 */
function buildSurfacePrompt(target, files, contents) {
  const fileBlocks = files.map((f, i) =>
    `### ${f.path} (${f.language})\n\`\`\`\n${contents[i].slice(0, 8000)}\n\`\`\``
  ).join("\n\n");

  return `You are a security analyst performing attack surface mapping for target: ${target}

Analyze the following source files and extract ALL security-relevant entries.
Output a single JSON object with ONLY these keys (all values are arrays):

{
  "http_layer":       [],  // { method, path, params:[], file, line }
  "authentication":   [],  // { flow, file, line, notes }
  "authorization":    [],  // { check_type, file, line, skippable: bool }
  "input_parsing":    [],  // { type, library, file, line }
  "async_ipc":        [],  // { type, file, line }
  "third_party":      [],  // { name, url_from_input: bool, file, line }
  "environment":      [],  // { var_name, used_in_security: bool, file, line }
  "javascript_sinks": [],  // { sink, input_source, file, line }
  "external_domains": []   // { url, context, file, line }
}

Rules:
- Include file:line for EVERY entry
- When in doubt, include — missing a surface costs more than a false entry
- Do NOT include analysis, explanation, or any key not listed above
- Output ONLY valid JSON, nothing else

FILES TO ANALYZE:
${fileBlocks}
`;
}

module.exports = { buildEmptySurface, mergeSurface, normalizeSurface, buildSurfacePrompt };
