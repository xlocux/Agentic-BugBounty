"use strict";

function normalizeText(value) {
  return String(value || "").toLowerCase();
}

function tokenize(value) {
  const stopwords = new Set([
    "app",
    "com",
    "edge",
    "firefox",
    "github",
    "http",
    "https",
    "ios",
    "net",
    "org",
    "play",
    "store",
    "www"
  ]);

  return Array.from(
    new Set(
      normalizeText(value)
        .split(/[^a-z0-9]+/i)
        .map((token) => token.trim())
        .filter((token) => token.length >= 3 && !stopwords.has(token))
    )
  );
}

function inferAssetBucket(scope) {
  const assetType = String(scope?.asset_type || "").toUpperCase();
  const identifier = normalizeText(scope?.asset_identifier);

  if (assetType === "SOURCE_CODE" || identifier.includes("github.com")) {
    return "source_code";
  }
  if (assetType.includes("APP_ID") || identifier.includes(".android") || identifier.includes(".ios")) {
    return "mobile_app";
  }
  if (assetType === "CHROME_EXTENSION_ID" || assetType === "FIREFOX_EXTENSION_ID") {
    return "browser_extension";
  }
  if (assetType === "WILDCARD" || assetType === "URL" || identifier.includes("http")) {
    return "web_surface";
  }
  return "other";
}

function scoreScope(scope, context = {}) {
  let score = 0;
  const bucket = inferAssetBucket(scope);

  if (scope.eligible_for_submission === true) score += 15;
  if (scope.max_severity === "critical") score += 8;
  if (scope.max_severity === "high") score += 6;

  if (bucket === "source_code") score += 12;
  else if (bucket === "web_surface") score += 9;
  else if (bucket === "mobile_app") score += 7;
  else if (bucket === "browser_extension") score += 7;
  else score += 4;

  score += Math.min(context.localMatches || 0, 5) * 4;
  score += Math.min(context.disclosedMatches || 0, 5) * 3;
  if (context.isUncovered) score += 10;

  return score;
}

function matchesScope(scope, item) {
  const identifier = normalizeText(scope?.asset_identifier);
  const haystack = normalizeText([item?.title, item?.url, item?.program_name, item?.program_handle].join(" "));
  if (!identifier || !haystack) {
    return false;
  }

  if (haystack.includes(identifier)) {
    return true;
  }

  const tokens = tokenize(identifier);
  const tokenHits = tokens.filter((token) => haystack.includes(token));
  return tokenHits.length >= Math.min(2, tokens.length) && tokenHits.length > 0;
}

function topWeaknesses(items, limit = 5) {
  const counts = new Map();
  for (const item of items || []) {
    const label = item?.weakness || item?.cwe || null;
    if (!label) continue;
    counts.set(label, (counts.get(label) || 0) + 1);
  }

  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([label, count]) => ({ label, count }));
}

function buildResearchBrief(config, intelligence, disclosedDataset) {
  const scopes = intelligence?.scopeSnapshot?.scopes || [];
  const localHistory = intelligence?.historySnapshot?.history || [];
  const localSkills = intelligence?.skillSnapshot?.skill_suggestions || [];
  const programHandle = intelligence?.scopeSnapshot?.meta?.program_handle ||
    intelligence?.historySnapshot?.meta?.program_handle ||
    config?.hackerone?.program_handle ||
    null;

  const disclosedReports = disclosedDataset?.disclosed_reports || [];
  const sameProgramDisclosed = disclosedReports.filter(
    (item) => item.program_handle && programHandle && item.program_handle === programHandle
  );

  const prioritizedAssets = scopes
    .map((scope) => {
      const localMatches = localHistory.filter((item) => matchesScope(scope, item));
      const disclosedMatches = sameProgramDisclosed.filter((item) => matchesScope(scope, item));
      const isUncovered = localMatches.length === 0;
      const priorityScore = scoreScope(scope, {
        localMatches: localMatches.length,
        disclosedMatches: disclosedMatches.length,
        isUncovered
      });

      const reasons = [];
      if (isUncovered) reasons.push("No target-local history is mapped to this asset yet.");
      if (scope.eligible_for_submission === true) reasons.push("Structured scope marks this asset as eligible for submission.");
      if (scope.max_severity) reasons.push(`Structured scope allows up to ${scope.max_severity} severity.`);
      if (inferAssetBucket(scope) === "source_code") reasons.push("Source code assets are high-leverage starting points for variant analysis.");
      if (localMatches.length > 0) reasons.push(`Local intelligence already contains ${localMatches.length} matching historical signal(s).`);
      if (disclosedMatches.length > 0) reasons.push(`Global disclosed history contains ${disclosedMatches.length} same-program match(es).`);

      return {
        asset_identifier: scope.asset_identifier || scope.id || "(unknown asset)",
        asset_type: scope.asset_type || null,
        priority_score: priorityScore,
        coverage_status: isUncovered ? "uncovered" : "partially_covered",
        local_history_matches: localMatches.length,
        same_program_disclosed_matches: disclosedMatches.length,
        reasons
      };
    })
    .sort((left, right) => right.priority_score - left.priority_score || left.asset_identifier.localeCompare(right.asset_identifier));

  const uncoveredAssets = prioritizedAssets.filter((item) => item.coverage_status === "uncovered");

  return {
    target_name: config?.target_name || null,
    asset_type: config?.asset_type || null,
    program_handle: programHandle,
    overview: {
      structured_scope_assets: scopes.length,
      local_history_items: localHistory.length,
      same_program_disclosed_items: sameProgramDisclosed.length,
      uncovered_assets: uncoveredAssets.length
    },
    priority_bug_families: localSkills.map((item) => ({
      module_hint: item.skill,
      evidence_count: item.evidence_count,
      reason: item.reason,
      sample_titles: item.sample_titles || []
    })),
    same_program_disclosed_top_weaknesses: topWeaknesses(sameProgramDisclosed),
    local_top_weaknesses: topWeaknesses(localHistory),
    prioritized_assets: prioritizedAssets,
    uncovered_assets: uncoveredAssets.slice(0, 10),
    recommended_starting_points: prioritizedAssets.slice(0, 5).map((item, index) => ({
      order: index + 1,
      asset_identifier: item.asset_identifier,
      asset_type: item.asset_type,
      rationale: item.reasons[0] || "High priority by combined local and disclosed intelligence."
    }))
  };
}

module.exports = {
  buildResearchBrief
};
