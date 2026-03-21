"use strict";

const https = require("node:https");
const path = require("node:path");
const {
  initDatabase,
  openDatabase,
  readDisclosedDatasetFromDb,
  readProgramIntelFromDb,
  replaceDisclosedReports,
  replaceProgramIntel,
  resolveDatabasePath,
  resolveGlobalDatabasePath
} = require("./db");
const { ensureDir, readJson, writeJson } = require("./io");

const API_BASE_URL = "https://api.hackerone.com";
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 10;
const FULL_SYNC_SAFETY_MAX_PAGES = 1000;
const DISCLOSED_QUERY_HARD_CAP = 30;
const DEFAULT_DISCLOSED_HISTORY_START = "2012-01-01";

function getCredentialsFromEnv() {
  const username = process.env.H1_API_USERNAME || process.env.HACKERONE_API_USERNAME;
  const token = process.env.H1_API_TOKEN || process.env.HACKERONE_API_TOKEN;

  if (!username || !token) {
    return null;
  }

  return { username, token };
}

function requestJson(pathname, options = {}) {
  const credentials = options.credentials || getCredentialsFromEnv();
  if (!credentials) {
    throw new Error(
      "Missing HackerOne API credentials. Set H1_API_USERNAME and H1_API_TOKEN."
    );
  }

  const url = new URL(pathname, API_BASE_URL);
  if (options.searchParams) {
    for (const [key, value] of Object.entries(options.searchParams)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const auth = Buffer.from(`${credentials.username}:${credentials.token}`).toString("base64");

  return new Promise((resolve, reject) => {
    const request = https.request(
      url,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `Basic ${auth}`,
          "User-Agent": "Agentic-BugBounty/0.1"
        }
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
        });
        response.on("end", () => {
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(
              new Error(`HackerOne API request failed (${response.statusCode}): ${body.slice(0, 500)}`)
            );
            return;
          }

          try {
            resolve(JSON.parse(body));
          } catch (error) {
            reject(new Error(`Failed to parse HackerOne API response: ${error.message}`));
          }
        });
      }
    );

    request.on("error", reject);
    request.end();
  });
}

async function collectPaginatedResource(pathname, options = {}) {
  const pageSize = options.pageSize || DEFAULT_PAGE_SIZE;
  const maxPages =
    options.maxPages === undefined || options.maxPages === null
      ? DEFAULT_MAX_PAGES
      : options.maxPages;
  const data = [];

  for (let pageNumber = 1; pageNumber <= maxPages; pageNumber += 1) {
    const payload = await requestJson(pathname, {
      credentials: options.credentials,
      searchParams: {
        ...options.searchParams,
        "page[size]": pageSize,
        "page[number]": pageNumber
      }
    });

    const items = Array.isArray(payload.data) ? payload.data : [];
    data.push(...items);

    const nextLink = payload.links && typeof payload.links.next === "string" ? payload.links.next : null;
    if (items.length < pageSize && !nextLink) {
      break;
    }
    if (items.length === 0) {
      break;
    }
  }

  return data;
}

function getAttributes(item) {
  return item && typeof item === "object" ? item.attributes || {} : {};
}

function getRelationshipId(item, relationshipName) {
  const relationship = item?.relationships?.[relationshipName]?.data;
  if (!relationship) return null;
  if (Array.isArray(relationship)) return relationship[0]?.id || null;
  return relationship.id || null;
}

function getRelationshipAttributes(item, relationshipName) {
  const relationship = item?.relationships?.[relationshipName]?.data;
  if (!relationship || Array.isArray(relationship)) {
    return null;
  }
  return relationship.attributes || null;
}

function extractProgramHandle(item, fallbackHandle = null) {
  const attributes = getAttributes(item);
  const programAttributes = getRelationshipAttributes(item, "program");
  return (
    programAttributes?.handle ||
    programAttributes?.team_handle ||
    attributes.team_handle ||
    attributes.program_handle ||
    attributes.handle ||
    getRelationshipId(item, "team") ||
    fallbackHandle
  );
}

function extractWeakness(attributes) {
  const weakness = attributes.weakness;
  if (typeof weakness === "string") {
    return weakness;
  }
  if (weakness && typeof weakness === "object") {
    return weakness.name || weakness.short_name || weakness.id || null;
  }
  return null;
}

function extractSeverityRating(item, attributes) {
  const severityAttributes = getRelationshipAttributes(item, "severity");
  return severityAttributes?.rating || attributes.severity_rating || attributes.severity || null;
}

function extractWeaknessFromItem(item, attributes) {
  const weaknessAttributes = getRelationshipAttributes(item, "weakness");
  return (
    weaknessAttributes?.name ||
    weaknessAttributes?.external_id ||
    extractWeakness(attributes)
  );
}

function normalizeStructuredScope(item, programHandle) {
  const attributes = getAttributes(item);
  return {
    id: item.id || null,
    program_handle: programHandle,
    asset_type: attributes.asset_type || null,
    asset_identifier: attributes.asset_identifier || attributes.identifier || null,
    instruction: attributes.instruction || attributes.instructions || null,
    eligible_for_submission:
      attributes.eligible_for_submission ?? attributes.eligible ?? attributes.in_scope ?? null,
    max_severity: attributes.max_severity || null,
    created_at: attributes.created_at || null,
    updated_at: attributes.updated_at || null
  };
}

function normalizeHistoryItem(item, source, fallbackHandle) {
  const attributes = getAttributes(item);
  const programAttributes = getRelationshipAttributes(item, "program");
  return {
    id: item.id || null,
    source,
    program_handle: extractProgramHandle(item, fallbackHandle),
    program_name: programAttributes?.name || programAttributes?.handle || null,
    program_url: programAttributes?.profile?.url || programAttributes?.url || null,
    title: attributes.title || attributes.report_title || attributes.headline || null,
    state: attributes.state || attributes.main_state || null,
    severity_rating: extractSeverityRating(item, attributes),
    cwe: attributes.cwe || attributes.cwe_id || null,
    weakness: extractWeaknessFromItem(item, attributes),
    disclosed_at: attributes.disclosed_at || null,
    created_at: attributes.created_at || null,
    updated_at: attributes.updated_at || null,
    url: attributes.url || attributes.html_url || null
  };
}

function compactHistory(items) {
  const seen = new Set();
  const compacted = [];

  for (const item of items) {
    const dedupeKey = [
      item.program_handle || "",
      item.title || "",
      item.weakness || "",
      item.cwe || "",
      item.source || ""
    ]
      .join("::")
      .toLowerCase();

    if (seen.has(dedupeKey)) {
      continue;
    }

    seen.add(dedupeKey);
    compacted.push(item);
  }

  return compacted;
}

function formatIsoDate(date) {
  return new Date(date).toISOString().slice(0, 10);
}

function addDays(isoDate, days) {
  const date = new Date(`${isoDate}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return formatIsoDate(date);
}

function daysBetween(startIso, endIso) {
  const start = new Date(`${startIso}T00:00:00Z`);
  const end = new Date(`${endIso}T00:00:00Z`);
  return Math.max(1, Math.round((end - start) / 86400000));
}

function buildDisclosedWindowQuery(startDate, endDate) {
  return `disclosed:true AND disclosed_at:>=${startDate} AND disclosed_at:<${endDate}`;
}

async function fetchDisclosedWindow(startDate, endDate, options = {}) {
  const hacktivity = await collectPaginatedResource("/v1/hackers/hacktivity", {
    credentials: options.credentials,
    pageSize: options.pageSize,
    maxPages: options.maxPages || FULL_SYNC_SAFETY_MAX_PAGES,
    searchParams: {
      queryString: buildDisclosedWindowQuery(startDate, endDate)
    }
  });

  return hacktivity.map((item) => normalizeHistoryItem(item, "disclosed", null));
}

async function collectDisclosedHistoryAdaptive(startDate, endDate, options = {}, stats = { windows: 0, splits: 0 }) {
  stats.windows += 1;
  const items = await fetchDisclosedWindow(startDate, endDate, options);
  const rangeDays = daysBetween(startDate, endDate);

  if (items.length < DISCLOSED_QUERY_HARD_CAP || rangeDays <= 1) {
    return { items, stats };
  }

  stats.splits += 1;
  const midpoint = addDays(startDate, Math.ceil(rangeDays / 2));
  const left = await collectDisclosedHistoryAdaptive(startDate, midpoint, options, stats);
  const right = await collectDisclosedHistoryAdaptive(midpoint, endDate, options, stats);
  return {
    items: [...left.items, ...right.items],
    stats
  };
}

function buildSkillSuggestions(history) {
  const catalog = [
    { key: "graphql", skill: "graphql", patterns: [/graphql/i, /cwe-89/i] },
    { key: "idor", skill: "auth_flaws", patterns: [/\bidor\b/i, /access control/i, /authorization/i] },
    { key: "csrf", skill: "csrf", patterns: [/\bcsrf\b/i, /cross-site request forgery/i] },
    { key: "oauth", skill: "oauth", patterns: [/\boauth\b/i, /\boidc\b/i, /openid/i] },
    { key: "saml", skill: "saml", patterns: [/\bsaml\b/i] },
    { key: "host-header", skill: "host_header", patterns: [/host header/i, /\bpassword reset poisoning\b/i] },
    { key: "ssrf", skill: "ssrf_filter_evasion", patterns: [/\bssrf\b/i, /server-side request forgery/i] },
    { key: "sqli", skill: "sqli_filter_evasion", patterns: [/\bsql injection\b/i, /\bsqli\b/i] },
    { key: "xss", skill: "xss_filter_evasion", patterns: [/\bxss\b/i, /cross-site scripting/i] },
    { key: "postmessage", skill: "postmessage", patterns: [/postmessage/i] },
    { key: "prototype-pollution", skill: "prototype_pollution", patterns: [/prototype pollution/i] },
    { key: "file-upload", skill: "file_upload", patterns: [/file upload/i, /unrestricted upload/i] },
    { key: "deserialization", skill: "deserialization", patterns: [/deserialization/i] },
    { key: "business-logic", skill: "business_logic", patterns: [/business logic/i, /workflow bypass/i] },
    { key: "race-condition", skill: "race_condition", patterns: [/race condition/i, /time of check/i] }
  ];

  const suggestions = [];
  for (const entry of catalog) {
    const matches = history.filter((item) => {
      const haystack = [item.title, item.weakness, item.cwe].filter(Boolean).join(" ");
      return entry.patterns.some((pattern) => pattern.test(haystack));
    });

    if (matches.length === 0) {
      continue;
    }

    suggestions.push({
      key: entry.key,
      skill: entry.skill,
      evidence_count: matches.length,
      sample_titles: matches.slice(0, 3).map((item) => item.title).filter(Boolean),
      reason: `Historical HackerOne data shows repeated ${entry.key} patterns for this target.`
    });
  }

  return suggestions.sort((left, right) => right.evidence_count - left.evidence_count);
}

async function syncGlobalDisclosedReports(options = {}) {
  if (options.fullHistory) {
    return syncGlobalDisclosedReportsFullHistory(options);
  }

  const maxPages =
    options.maxPages === undefined || options.maxPages === null
      ? FULL_SYNC_SAFETY_MAX_PAGES
      : options.maxPages;
  const hacktivity = (
    await collectPaginatedResource("/v1/hackers/hacktivity", {
      credentials: options.credentials,
      pageSize: options.pageSize,
      maxPages,
      searchParams: {
        queryString: "disclosed:true"
      }
    })
  ).map((item) => normalizeHistoryItem(item, "disclosed", null));

  const disclosedReports = compactHistory(
    hacktivity.filter((item) => item.disclosed_at || item.program_handle || item.title)
  );

  return {
    meta: {
      synced_at: new Date().toISOString(),
      paging: {
        page_size: options.pageSize || DEFAULT_PAGE_SIZE,
        max_pages_requested: maxPages
      },
      counts: {
        disclosed_reports: disclosedReports.length
      }
    },
    disclosed_reports: disclosedReports
  };
}

async function syncGlobalDisclosedReportsFullHistory(options = {}) {
  const startDate = options.startDate || DEFAULT_DISCLOSED_HISTORY_START;
  const endDate = options.endDate || addDays(formatIsoDate(new Date()), 1);
  const stepDays = options.windowDays || 31;
  const allItems = [];
  const aggregateStats = { windows: 0, splits: 0 };

  for (let cursor = startDate; cursor < endDate; cursor = addDays(cursor, stepDays)) {
    const windowEnd = addDays(cursor, stepDays);
    const boundedEnd = windowEnd < endDate ? windowEnd : endDate;
    const { items, stats } = await collectDisclosedHistoryAdaptive(cursor, boundedEnd, options, aggregateStats);
    allItems.push(...items);
    aggregateStats.windows = stats.windows;
    aggregateStats.splits = stats.splits;
  }

  const disclosedReports = compactHistory(
    allItems.filter((item) => item.disclosed_at || item.program_handle || item.title)
  );

  return {
    meta: {
      synced_at: new Date().toISOString(),
      mode: "full-history",
      range: {
        start_date: startDate,
        end_date: endDate
      },
      adaptive: {
        base_window_days: stepDays,
        hard_cap_assumption: DISCLOSED_QUERY_HARD_CAP,
        windows_queried: aggregateStats.windows,
        window_splits: aggregateStats.splits
      },
      paging: {
        page_size: options.pageSize || DEFAULT_PAGE_SIZE,
        max_pages_requested:
          options.maxPages === undefined || options.maxPages === null
            ? FULL_SYNC_SAFETY_MAX_PAGES
            : options.maxPages
      },
      counts: {
        disclosed_reports: disclosedReports.length
      }
    },
    disclosed_reports: disclosedReports
  };
}

async function syncProgramIntel(programHandle, options = {}) {
  const scopes = (
    await collectPaginatedResource(`/v1/hackers/programs/${programHandle}/structured_scopes`, {
      credentials: options.credentials,
      pageSize: options.pageSize,
      maxPages: options.maxPages
    })
  ).map((item) => normalizeStructuredScope(item, programHandle));

  const hacktivity = (
    await collectPaginatedResource("/v1/hackers/hacktivity", {
      credentials: options.credentials,
      pageSize: options.pageSize,
      maxPages: options.maxPages,
      searchParams: {
        queryString: `team:${programHandle}`
      }
    })
  ).map((item) => normalizeHistoryItem(item, "hacktivity", programHandle));

  const reports = (
    await collectPaginatedResource("/v1/hackers/me/reports", {
      credentials: options.credentials,
      pageSize: options.pageSize,
      maxPages: options.maxPages
    })
  )
    .map((item) => normalizeHistoryItem(item, "report", null))
    .filter((item) => !item.program_handle || item.program_handle === programHandle);

  const history = compactHistory([...hacktivity, ...reports]);
  return {
    meta: {
      program_handle: programHandle,
      synced_at: new Date().toISOString(),
      sources: {
        scopes: scopes.length,
        hacktivity: hacktivity.length,
        reports: reports.length
      }
    },
    scopes,
    history,
    skill_suggestions: buildSkillSuggestions(history)
  };
}

function writeProgramIntel(intelligenceDir, intel) {
  ensureDir(intelligenceDir);
  writeJson(path.join(intelligenceDir, "h1_scope_snapshot.json"), {
    meta: intel.meta,
    scopes: intel.scopes
  });
  writeJson(path.join(intelligenceDir, "h1_vulnerability_history.json"), {
    meta: intel.meta,
    history: intel.history
  });
  writeJson(path.join(intelligenceDir, "h1_skill_suggestions.json"), {
    meta: intel.meta,
    skill_suggestions: intel.skill_suggestions
  });
}

function persistProgramIntel(targetConfig, intelligenceDir, intel) {
  writeProgramIntel(intelligenceDir, intel);
  const databasePath = resolveDatabasePath(intelligenceDir);
  const db = openDatabase(databasePath);
  initDatabase(db);
  replaceProgramIntel(db, targetConfig, intel);
  db.close();
  return databasePath;
}

function persistDisclosedDataset(baseDir, payload) {
  ensureDir(baseDir);
  writeJson(path.join(baseDir, "h1_disclosed_reports.json"), payload);
  const databasePath = resolveGlobalDatabasePath(baseDir);
  const db = openDatabase(databasePath);
  initDatabase(db);
  replaceDisclosedReports(db, payload);
  db.close();
  return databasePath;
}

function loadDisclosedDataset(baseDir = path.resolve("data", "global-intelligence")) {
  const databasePath = resolveGlobalDatabasePath(baseDir);

  try {
    const db = openDatabase(databasePath);
    initDatabase(db);
    const dataset = readDisclosedDatasetFromDb(db);
    db.close();
    if (dataset) {
      return dataset;
    }
  } catch {
    // Fall back to JSON snapshot below.
  }

  try {
    return readJson(path.join(baseDir, "h1_disclosed_reports.json"));
  } catch {
    return null;
  }
}

function loadProgramIntel(intelligenceDir, programHandle = null) {
  const databasePath = resolveDatabasePath(intelligenceDir);

  try {
    const db = openDatabase(databasePath);
    initDatabase(db);
    if (programHandle) {
      const dbIntel = readProgramIntelFromDb(db, programHandle);
      db.close();
      if (dbIntel) {
        return {
          scopeSnapshot: { meta: dbIntel.meta, scopes: dbIntel.scopes },
          historySnapshot: { meta: dbIntel.meta, history: dbIntel.history },
          skillSnapshot: { meta: dbIntel.meta, skill_suggestions: dbIntel.skill_suggestions }
        };
      }
    } else {
      db.close();
    }
  } catch {
    // Fall back to JSON snapshots below.
  }

  try {
    const scopeSnapshot = readJson(path.join(intelligenceDir, "h1_scope_snapshot.json"));
    const historySnapshot = readJson(path.join(intelligenceDir, "h1_vulnerability_history.json"));
    const skillSnapshot = readJson(path.join(intelligenceDir, "h1_skill_suggestions.json"));

    return {
      scopeSnapshot,
      historySnapshot,
      skillSnapshot
    };
  } catch {
    return null;
  }
}

module.exports = {
  buildSkillSuggestions,
  collectPaginatedResource,
  getCredentialsFromEnv,
  loadDisclosedDataset,
  loadProgramIntel,
  persistDisclosedDataset,
  persistProgramIntel,
  requestJson,
  syncGlobalDisclosedReports,
  syncGlobalDisclosedReportsFullHistory,
  syncProgramIntel,
  writeProgramIntel
};
