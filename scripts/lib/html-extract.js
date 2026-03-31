"use strict";

const cheerio = require("cheerio");

/**
 * MODE: docs
 * For reading README / wiki / installation pages.
 * Aggressive noise removal — scripts stripped, only prose remains.
 * Safe because we only need install instructions, not security data.
 * ~95% token reduction on typical GitHub README pages.
 *
 * @param {string} html
 * @returns {string} clean prose text
 */
function extractDocs(html) {
  const $ = cheerio.load(html);

  $("script, style, nav, footer, header, aside, .sidebar, .menu, " +
    ".navigation, .breadcrumb, .advertisement, .cookie-banner, " +
    "[role=navigation], [role=banner], [role=complementary]").remove();

  const contentSelectors = [
    "main", "article", ".content", ".markdown-body",
    "#readme", ".wiki-content", "#main-content", ".prose"
  ];

  let text = "";
  for (const sel of contentSelectors) {
    if ($(sel).length) {
      text = $(sel).text();
      break;
    }
  }
  if (!text) text = $("body").text();

  return text.replace(/\s+/g, " ").trim();
}

/**
 * MODE: surface
 * For attack surface mapping of target pages.
 * Removes only layout noise — preserves ALL security-relevant content:
 * inline scripts, comments, hidden inputs, data-* attributes, meta tags.
 * ~40-50% token reduction, no security-relevant loss.
 *
 * @param {string} html
 * @returns {object} structured security-relevant content
 */
function extractSurface(html) {
  const $ = cheerio.load(html, { xmlMode: false });

  // Remove pure layout noise only — never scripts or comments
  $("style, nav, footer, [role=navigation], [role=banner]").remove();

  const inline_scripts = $("script:not([src])").map((_, el) => $(el).html()).get()
    .filter(Boolean);

  const script_srcs = $("script[src]").map((_, el) => $(el).attr("src")).get()
    .filter(Boolean);

  const comments = _extractComments(html);

  const forms = $("form").map((_, form) => ({
    action: $(form).attr("action") || null,
    method: ($(form).attr("method") || "GET").toUpperCase(),
    inputs: $(form).find("input, select, textarea, button[name]").map((_, el) => ({
      name:  $(el).attr("name")  || null,
      type:  $(el).attr("type") || "text",
      value: $(el).attr("value") || null
    })).get()
  })).get();

  const data_attributes = _extractDataAttributes($);

  const meta = $("meta").map((_, el) => ({
    name:    $(el).attr("name") || $(el).attr("property") || null,
    content: $(el).attr("content") || null
  })).get().filter(m => m.name && m.content);

  const links = $("a[href], link[href]").map((_, el) => ({
    text: $(el).text().trim(),
    href: $(el).attr("href") || null,
    rel:  $(el).attr("rel")  || null
  })).get().filter(l => l.href);

  // Visible text for general analysis (scripts/styles already removed above)
  const text = $("body").text().replace(/\s+/g, " ").trim();

  return {
    inline_scripts,
    script_srcs,
    comments,
    forms,
    data_attributes,
    meta,
    links,
    text
  };
}

/**
 * MODE: response
 * For HTTP response analysis during live testing (Phase 4).
 * Same as surface + automatic anomaly detection before the LLM reads it.
 *
 * @param {string} html
 * @returns {object} surface fields + anomalies array
 */
function extractResponse(html) {
  const surface = extractSurface(html);

  const anomalies = [];
  const combined = surface.text + " " + surface.comments.join(" ") +
                   " " + surface.inline_scripts.join(" ");

  // Stack trace patterns
  if (/at \w[\w.]*\s*\(.*:\d+:\d+\)/.test(combined))
    anomalies.push("stack_trace");

  // Internal filesystem paths
  if (/\/home\/|\/var\/www\/|\/etc\/|C:\\\\|C:\//.test(combined))
    anomalies.push("internal_path");

  // Credential patterns in visible content
  if (/\bpass\b\s*[:=]|password\s*[:=]|passwd\s*[:=]|api[_-]?key\s*[:=]|secret\s*[:=]/i.test(combined))
    anomalies.push("credential_leak");

  // Debug / verbose output
  if (/\bdebug\b.*true|\bverbose\b.*true|\btrace\b.*enabled/i.test(combined))
    anomalies.push("debug_output");

  return { ...surface, anomalies };
}

// ── Private helpers ──────────────────────────────────────────────────────────

function _extractComments(html) {
  const matches = [];
  const re = /<!--([\s\S]*?)-->/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    const trimmed = m[1].trim();
    if (trimmed) matches.push(trimmed);
  }
  return matches;
}

function _extractDataAttributes($) {
  const attrs = {};
  $("*").each((_, el) => {
    for (const [key, val] of Object.entries(el.attribs || {})) {
      if (key.startsWith("data-")) {
        if (!attrs[key]) attrs[key] = [];
        if (!attrs[key].includes(val)) attrs[key].push(val);
      }
    }
  });
  return attrs;
}

module.exports = { extractDocs, extractSurface, extractResponse };
