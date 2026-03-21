"use strict";

const { SEVERITIES } = require("./constants");
const { isNonEmptyString, isWebUrl } = require("./validators");

// H1 universal out-of-scope patterns (case-insensitive keyword detection)
const SELF_XSS_PATTERNS = [/\bself[-_]?xss\b/i, /\bself injection\b/i];
const DOS_PATTERNS = [
  /\bdo[st]\b/i,
  /\bdenial.of.service\b/i,
  /\brate.?limit(ing)?\b/i,
  /\bcrash(es|ing)?\b/i
];

function isSelfXss(finding) {
  const haystack = [finding.finding_title, finding.vulnerability_class, finding.summary]
    .filter(Boolean)
    .join(" ");
  return SELF_XSS_PATTERNS.some((re) => re.test(haystack));
}

function isDosFinding(finding) {
  const haystack = [finding.finding_title, finding.vulnerability_class, finding.summary]
    .filter(Boolean)
    .join(" ");
  return DOS_PATTERNS.some((re) => re.test(haystack));
}

function isTheoreticalFinding(finding) {
  const haystack = [
    finding.summary,
    finding.observed_result,
    finding.impact_claimed,
    finding.researcher_notes
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return (
    haystack.includes("could") ||
    haystack.includes("potential") ||
    haystack.includes("theoretical")
  );
}

function buildFindingHaystack(finding) {
  return [
    finding.finding_title,
    finding.vulnerability_class,
    finding.summary,
    finding.affected_component,
    finding.cwe_claimed
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function getScopesFromIntelligence(intelligence) {
  return intelligence?.scopeSnapshot?.scopes || [];
}

function getHistoryFromIntelligence(intelligence) {
  return intelligence?.historySnapshot?.history || [];
}

function scopeEntryText(entry) {
  return [entry.asset_identifier, entry.instruction, entry.asset_type]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function allowsKeywordInScope(intelligence, patterns) {
  return getScopesFromIntelligence(intelligence).some((entry) => {
    if (entry.eligible_for_submission !== true) {
      return false;
    }

    const haystack = scopeEntryText(entry);
    return patterns.some((pattern) => pattern.test(haystack));
  });
}

function findScopeConflict(finding, intelligence) {
  const haystack = buildFindingHaystack(finding);

  for (const entry of getScopesFromIntelligence(intelligence)) {
    if (entry.eligible_for_submission !== false) {
      continue;
    }

    const entryText = scopeEntryText(entry);
    if (!entryText) {
      continue;
    }

    const hasIdentifierMatch =
      entry.asset_identifier && haystack.includes(String(entry.asset_identifier).toLowerCase());
    const hasKeywordMatch =
      haystack.includes("self-xss") && entryText.includes("self-xss") ||
      haystack.includes("denial of service") && entryText.includes("denial of service") ||
      haystack.includes("dos") && /\bdos\b/.test(entryText) ||
      haystack.includes("clickjacking") && entryText.includes("clickjacking");

    if (hasIdentifierMatch || hasKeywordMatch) {
      return entry;
    }
  }

  return null;
}

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function findHistoricalMatches(finding, intelligence) {
  const history = getHistoryFromIntelligence(intelligence);
  const title = normalizeText(finding.finding_title);
  const vulnClass = normalizeText(finding.vulnerability_class);
  const cwe = normalizeText(finding.cwe_claimed);

  return history.filter((item) => {
    const itemTitle = normalizeText(item.title);
    const itemWeakness = normalizeText(item.weakness);
    const itemCwe = normalizeText(item.cwe);

    return (
      (title && itemTitle && title === itemTitle) ||
      (vulnClass && itemWeakness && vulnClass === itemWeakness) ||
      (cwe && itemCwe && cwe === itemCwe)
    );
  });
}

function severityToScore(severity) {
  return SEVERITIES.indexOf(severity);
}

function downgradeSeverity(severity, steps = 1) {
  const nextIndex = Math.max(0, severityToScore(severity) - steps);
  return SEVERITIES[nextIndex];
}

function buildNmiQuestions(finding) {
  const questions = [];

  if (!Array.isArray(finding.steps_to_reproduce) || finding.steps_to_reproduce.length < 3) {
    questions.push(
      "Please provide at least three deterministic reproduction steps with preconditions and expected result."
    );
  }
  if (!isNonEmptyString(finding.poc_code)) {
    questions.push(
      "Please provide a self-contained PoC that another analyst can run without guessing missing context."
    );
  }
  if (!isNonEmptyString(finding.observed_result)) {
    questions.push(
      "Please describe the observed runtime result, not only the expected security impact."
    );
  }

  return questions.slice(0, 3);
}

function triageFinding(finding, bundle, seenKeys) {
  const scopeCheck = isWebUrl(bundle.meta.program_url) ? "PASS" : "FAIL";
  const nmiQuestions = buildNmiQuestions(finding);
  const completenessCheck = nmiQuestions.length === 0 ? "PASS" : "NEEDS_MORE_INFO";

  const dedupeKey = `${finding.vulnerability_class}::${finding.affected_component}`.toLowerCase();
  const isDuplicate = seenKeys.has(dedupeKey);
  seenKeys.add(dedupeKey);

  let triageVerdict = "TRIAGED";
  let validityCheck = "VALID";
  let analystSeverity = finding.severity_claimed;
  let analystCvssScore = finding.cvss_score_claimed;
  let duplicateReference = null;
  const keyDiscrepancies = [];

  if (scopeCheck === "FAIL") {
    triageVerdict = "NOT_APPLICABLE";
    validityCheck = "NOT_APPLICABLE";
    analystSeverity = "N/A";
    analystCvssScore = 0;
  } else if (isSelfXss(finding)) {
    // H1 universal rule: self-XSS is always out of scope
    triageVerdict = "NOT_APPLICABLE";
    validityCheck = "NOT_APPLICABLE";
    analystSeverity = "N/A";
    analystCvssScore = 0;
    keyDiscrepancies.push(
      "Self-XSS is out of scope per H1 universal rules: requires the attacker to inject into their own session with no path to victim impact."
    );
  } else if (isDosFinding(finding)) {
    // H1 universal rule: DoS is out of scope unless program scope explicitly includes it
    triageVerdict = "NOT_APPLICABLE";
    validityCheck = "NOT_APPLICABLE";
    analystSeverity = "N/A";
    analystCvssScore = 0;
    keyDiscrepancies.push(
      "Denial-of-service findings are out of scope per H1 universal rules unless the program scope explicitly lists them as in-scope."
    );
  } else if (completenessCheck === "NEEDS_MORE_INFO") {
    triageVerdict = "NEEDS_MORE_INFO";
  } else if (isDuplicate) {
    triageVerdict = "DUPLICATE";
    validityCheck = "DUPLICATE";
    analystSeverity = downgradeSeverity(finding.severity_claimed);
    analystCvssScore = Math.max(0, finding.cvss_score_claimed - 1);
    duplicateReference =
      "Duplicate within current bundle: same vulnerability class and affected component.";
  } else if (isTheoreticalFinding(finding)) {
    triageVerdict = "INFORMATIVE";
    validityCheck = "INFORMATIVE";
    analystSeverity = downgradeSeverity(finding.severity_claimed, 2);
    analystCvssScore = Math.max(0, finding.cvss_score_claimed - 2);
    keyDiscrepancies.push(
      "Claimed impact is more speculative than the observed runtime evidence."
    );
  }

  if (triageVerdict === "TRIAGED" && finding.cvss_score_claimed >= 9 && finding.poc_type === "html") {
    analystSeverity = downgradeSeverity(finding.severity_claimed);
    analystCvssScore = Math.max(0, finding.cvss_score_claimed - 1);
    keyDiscrepancies.push(
      "Client-side execution requires user interaction, so the original severity appears slightly overstated."
    );
  }

  const severityDelta = Number((analystCvssScore - finding.cvss_score_claimed).toFixed(1));
  const readyToSubmit = triageVerdict === "TRIAGED";
  const analystCvssVector = readyToSubmit ? finding.cvss_vector_claimed : "N/A";
  const triageSummary = readyToSubmit
    ? [
        "TRIAGE SUMMARY",
        "",
        `Report ID:           ${finding.report_id}`,
        "Verdict:             TRIAGED",
        `Analyst CVSS:        ${analystCvssScore.toFixed(1)} ${finding.cvss_vector_claimed}`,
        `Analyst Severity:    ${analystSeverity}`,
        `CWE:                 ${finding.cwe_claimed}`,
        "",
        "ISSUE SUMMARY:",
        finding.summary,
        "",
        "REPRODUCTION CONFIRMED: YES",
        finding.observed_result,
        "",
        "IMPACT ANALYSIS:",
        finding.impact_claimed,
        "",
        "SEVERITY ADJUSTMENT:",
        keyDiscrepancies.length === 0
          ? "Researcher CVSS is accurate."
          : keyDiscrepancies.join(" "),
        "",
        "REMEDIATION RECOMMENDATION:",
        finding.remediation_suggested
      ].join("\n")
    : "";

  let responseToResearcher = "";
  if (triageVerdict === "TRIAGED") {
    responseToResearcher = `We reproduced ${finding.report_id} and validated the issue at ${analystSeverity} severity. The report is ready for program review.`;
  } else if (triageVerdict === "NEEDS_MORE_INFO") {
    responseToResearcher = `We need a bit more detail before we can complete triage on ${finding.report_id}. Please answer the requested follow-up questions.`;
  } else if (triageVerdict === "DUPLICATE") {
    responseToResearcher = `Thanks for the report. ${finding.report_id} appears to duplicate an issue already captured in this bundle, so we are marking it as duplicate for now.`;
  } else if (triageVerdict === "INFORMATIVE") {
    responseToResearcher = `Thanks for the submission. The behavior looks technically interesting, but the current evidence does not yet demonstrate a material exploit path.`;
  } else {
    responseToResearcher = `Thanks for the report. The current evidence indicates this issue is not applicable for program triage.`;
  }

  return {
    report_id: finding.report_id,
    triage_verdict: triageVerdict,
    analyst_severity: analystSeverity,
    analyst_cvss_score: Number(analystCvssScore.toFixed(1)),
    analyst_cvss_vector: analystCvssVector,
    cwe_confirmed: finding.cwe_claimed,
    scope_check: scopeCheck,
    completeness_check: completenessCheck,
    validity_check: validityCheck,
    duplicate_reference: duplicateReference,
    severity_delta: severityDelta,
    nmi_questions: nmiQuestions,
    key_discrepancies: keyDiscrepancies,
    ready_to_submit: readyToSubmit,
    triage_summary: triageSummary,
    response_to_researcher: responseToResearcher
  };
}

function triageBundle(bundle, options = {}) {
  const intelligence = options.intelligence || null;
  const seenKeys = new Set();
  const results = (bundle.findings || []).map((finding) => {
    const scopeCheck = isWebUrl(bundle.meta.program_url) ? "PASS" : "FAIL";
    const nmiQuestions = buildNmiQuestions(finding);
    const completenessCheck = nmiQuestions.length === 0 ? "PASS" : "NEEDS_MORE_INFO";
    const dedupeKey = `${finding.vulnerability_class}::${finding.affected_component}`.toLowerCase();
    const isDuplicate = seenKeys.has(dedupeKey);
    seenKeys.add(dedupeKey);

    let triageVerdict = "TRIAGED";
    let validityCheck = "VALID";
    let analystSeverity = finding.severity_claimed;
    let analystCvssScore = finding.cvss_score_claimed;
    let duplicateReference = null;
    const keyDiscrepancies = [];

    const scopeConflict = findScopeConflict(finding, intelligence);
    const historicalMatches = findHistoricalMatches(finding, intelligence);
    const allowsSelfXss = allowsKeywordInScope(intelligence, [/\bself[- ]?xss\b/i]);
    const allowsDos = allowsKeywordInScope(intelligence, [/\bdos\b/i, /denial of service/i]);

    if (scopeCheck === "FAIL") {
      triageVerdict = "NOT_APPLICABLE";
      validityCheck = "NOT_APPLICABLE";
      analystSeverity = "N/A";
      analystCvssScore = 0;
    } else if (scopeConflict) {
      triageVerdict = "NOT_APPLICABLE";
      validityCheck = "NOT_APPLICABLE";
      analystSeverity = "N/A";
      analystCvssScore = 0;
      keyDiscrepancies.push(
        `Structured scope marks this target or bug class as out of scope: ${scopeConflict.asset_identifier || scopeConflict.instruction || scopeConflict.id}.`
      );
    } else if (isSelfXss(finding) && !allowsSelfXss) {
      triageVerdict = "NOT_APPLICABLE";
      validityCheck = "NOT_APPLICABLE";
      analystSeverity = "N/A";
      analystCvssScore = 0;
      keyDiscrepancies.push(
        "Self-XSS is out of scope per H1 universal rules unless the program explicitly allows it."
      );
    } else if (isDosFinding(finding) && !allowsDos) {
      triageVerdict = "NOT_APPLICABLE";
      validityCheck = "NOT_APPLICABLE";
      analystSeverity = "N/A";
      analystCvssScore = 0;
      keyDiscrepancies.push(
        "Denial-of-service findings are out of scope unless the program explicitly marks them in scope."
      );
    } else if (completenessCheck === "NEEDS_MORE_INFO") {
      triageVerdict = "NEEDS_MORE_INFO";
    } else if (isDuplicate) {
      triageVerdict = "DUPLICATE";
      validityCheck = "DUPLICATE";
      analystSeverity = downgradeSeverity(finding.severity_claimed);
      analystCvssScore = Math.max(0, finding.cvss_score_claimed - 1);
      duplicateReference =
        "Duplicate within current bundle: same vulnerability class and affected component.";
    } else if (historicalMatches.some((item) => normalizeText(item.title) === normalizeText(finding.finding_title))) {
      triageVerdict = "DUPLICATE";
      validityCheck = "DUPLICATE";
      analystSeverity = downgradeSeverity(finding.severity_claimed);
      analystCvssScore = Math.max(0, finding.cvss_score_claimed - 1);
      duplicateReference = `Potential historical duplicate from HackerOne intelligence: ${historicalMatches[0].title || historicalMatches[0].id}.`;
    } else if (isTheoreticalFinding(finding)) {
      triageVerdict = "INFORMATIVE";
      validityCheck = "INFORMATIVE";
      analystSeverity = downgradeSeverity(finding.severity_claimed, 2);
      analystCvssScore = Math.max(0, finding.cvss_score_claimed - 2);
      keyDiscrepancies.push(
        "Claimed impact is more speculative than the observed runtime evidence."
      );
    }

    if (historicalMatches.length > 0 && triageVerdict === "TRIAGED") {
      keyDiscrepancies.push(
        `Historical HackerOne matches found for this bug family (${historicalMatches.length}); verify whether the root cause is genuinely new.`
      );
    }

    if (triageVerdict === "TRIAGED" && finding.cvss_score_claimed >= 9 && finding.poc_type === "html") {
      analystSeverity = downgradeSeverity(finding.severity_claimed);
      analystCvssScore = Math.max(0, finding.cvss_score_claimed - 1);
      keyDiscrepancies.push(
        "Client-side execution requires user interaction, so the original severity appears slightly overstated."
      );
    }

    const severityDelta = Number((analystCvssScore - finding.cvss_score_claimed).toFixed(1));
    const readyToSubmit = triageVerdict === "TRIAGED";
    const analystCvssVector = readyToSubmit ? finding.cvss_vector_claimed : "N/A";
    const triageSummary = readyToSubmit
      ? [
          "TRIAGE SUMMARY",
          "",
          `Report ID:           ${finding.report_id}`,
          "Verdict:             TRIAGED",
          `Analyst CVSS:        ${analystCvssScore.toFixed(1)} ${finding.cvss_vector_claimed}`,
          `Analyst Severity:    ${analystSeverity}`,
          `CWE:                 ${finding.cwe_claimed}`,
          "",
          "ISSUE SUMMARY:",
          finding.summary,
          "",
          "REPRODUCTION CONFIRMED: YES",
          finding.observed_result,
          "",
          "IMPACT ANALYSIS:",
          finding.impact_claimed,
          "",
          "SEVERITY ADJUSTMENT:",
          keyDiscrepancies.length === 0
            ? "Researcher CVSS is accurate."
            : keyDiscrepancies.join(" "),
          "",
          "REMEDIATION RECOMMENDATION:",
          finding.remediation_suggested
        ].join("\n")
      : "";

    let responseToResearcher = "";
    if (triageVerdict === "TRIAGED") {
      responseToResearcher = `We reproduced ${finding.report_id} and validated the issue at ${analystSeverity} severity. The report is ready for program review.`;
    } else if (triageVerdict === "NEEDS_MORE_INFO") {
      responseToResearcher = `We need a bit more detail before we can complete triage on ${finding.report_id}. Please answer the requested follow-up questions.`;
    } else if (triageVerdict === "DUPLICATE") {
      responseToResearcher = `Thanks for the report. ${finding.report_id} appears to overlap with an existing issue, so we are marking it as duplicate for now.`;
    } else if (triageVerdict === "INFORMATIVE") {
      responseToResearcher = `Thanks for the submission. The behavior looks technically interesting, but the current evidence does not yet demonstrate a material exploit path.`;
    } else {
      responseToResearcher = `Thanks for the report. The current evidence indicates this issue is not applicable for program triage.`;
    }

    return {
      report_id: finding.report_id,
      triage_verdict: triageVerdict,
      analyst_severity: analystSeverity,
      analyst_cvss_score: Number(analystCvssScore.toFixed(1)),
      analyst_cvss_vector: analystCvssVector,
      cwe_confirmed: finding.cwe_claimed,
      scope_check: scopeCheck,
      completeness_check: completenessCheck,
      validity_check: validityCheck,
      duplicate_reference: duplicateReference,
      severity_delta: severityDelta,
      nmi_questions: nmiQuestions,
      key_discrepancies: keyDiscrepancies,
      ready_to_submit: readyToSubmit,
      triage_summary: triageSummary,
      response_to_researcher: responseToResearcher
    };
  });
  const calibrationModule =
    options.calibrationModule || `triager/calibration/${bundle.meta.asset_type}.md`;

  const meta = {
    triaged_at: new Date().toISOString(),
    asset_type: bundle.meta.asset_type,
    calibration_module: calibrationModule,
    total_findings_received: results.length,
    triaged: results.filter((item) => item.triage_verdict === "TRIAGED").length,
    not_applicable: results.filter((item) => item.triage_verdict === "NOT_APPLICABLE").length,
    needs_more_info: results.filter((item) => item.triage_verdict === "NEEDS_MORE_INFO").length,
    duplicate: results.filter((item) => item.triage_verdict === "DUPLICATE").length,
    informative: results.filter((item) => item.triage_verdict === "INFORMATIVE").length,
    ready_to_submit: results.filter((item) => item.ready_to_submit).length
  };

  return { meta, results };
}

module.exports = {
  triageBundle,
  triageFinding,
  isSelfXss,
  isDosFinding,
  isTheoreticalFinding
};
