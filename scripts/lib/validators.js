"use strict";

const {
  ASSET_TYPES,
  ANALYSIS_MODES,
  SEVERITIES,
  TRIAGE_VERDICTS,
  REPORT_PREFIX_BY_ASSET,
  CVSS_REGEX,
  CWE_REGEX,
  ISO_DATE_REGEX,
  URL_PROTOCOLS,
  REPORT_ID_REGEX
} = require("./constants");

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isIsoDate(value) {
  return isNonEmptyString(value) && ISO_DATE_REGEX.test(value);
}

function isWebUrl(value) {
  if (!isNonEmptyString(value)) return false;
  try {
    const parsed = new URL(value);
    return URL_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}

function err(pathName, message) {
  return `${pathName}: ${message}`;
}

function validateReportId(reportId, assetType, isCandidate) {
  const prefix = REPORT_PREFIX_BY_ASSET[assetType];
  const suffix = isCandidate ? "-CANDIDATE" : "";
  const pattern = new RegExp(`^${prefix}-\\d{3}${suffix}$`);
  return pattern.test(reportId);
}

function validateFindingCommon(finding, assetType, pathName, options = {}) {
  const errors = [];
  const isCandidate = options.isCandidate ?? false;
  const minSteps = isCandidate ? 2 : 3;

  if (!finding || typeof finding !== "object" || Array.isArray(finding)) {
    return [err(pathName, "must be an object")];
  }

  const requiredStringFields = [
    "report_id",
    "finding_title",
    "severity_claimed",
    "cvss_vector_claimed",
    "cwe_claimed",
    "vulnerability_class",
    "affected_component",
    "summary",
    "poc_code",
    "poc_type",
    "observed_result",
    "impact_claimed",
    "remediation_suggested",
    "researcher_notes",
    "confirmation_status"
  ];

  for (const field of requiredStringFields) {
    if (!isNonEmptyString(finding[field])) {
      errors.push(err(`${pathName}.${field}`, "must be a non-empty string"));
    }
  }

  if (!validateReportId(finding.report_id || "", assetType, isCandidate)) {
    errors.push(
      err(
        `${pathName}.report_id`,
        `must match ${REPORT_PREFIX_BY_ASSET[assetType]}-NNN${isCandidate ? "-CANDIDATE" : ""}`
      )
    );
  }

  if (!SEVERITIES.includes(finding.severity_claimed)) {
    errors.push(err(`${pathName}.severity_claimed`, "must be a known severity"));
  }

  if (!CVSS_REGEX.test(finding.cvss_vector_claimed || "")) {
    errors.push(err(`${pathName}.cvss_vector_claimed`, "must be a valid CVSS 3.1 vector"));
  }

  if (
    typeof finding.cvss_score_claimed !== "number" ||
    Number.isNaN(finding.cvss_score_claimed) ||
    finding.cvss_score_claimed < 0 ||
    finding.cvss_score_claimed > 10
  ) {
    errors.push(err(`${pathName}.cvss_score_claimed`, "must be a number between 0 and 10"));
  }

  if (!CWE_REGEX.test(finding.cwe_claimed || "")) {
    errors.push(err(`${pathName}.cwe_claimed`, "must match CWE-XXX: Name"));
  }

  if (!Array.isArray(finding.steps_to_reproduce) || finding.steps_to_reproduce.length < minSteps) {
    errors.push(err(`${pathName}.steps_to_reproduce`, `must contain at least ${minSteps} steps`));
  } else {
    finding.steps_to_reproduce.forEach((step, index) => {
      if (!isNonEmptyString(step)) {
        errors.push(err(`${pathName}.steps_to_reproduce[${index}]`, "must be a non-empty string"));
      }
    });
  }

  if (!Array.isArray(finding.attachments)) {
    errors.push(err(`${pathName}.attachments`, "must be an array"));
  }

  const confirmationStatus = finding.confirmation_status;
  if (isCandidate) {
    if (confirmationStatus !== "unconfirmed") {
      errors.push(err(`${pathName}.confirmation_status`, "must be 'unconfirmed' for candidates"));
    }
    if (!isNonEmptyString(finding.reason_not_confirmed)) {
      errors.push(err(`${pathName}.reason_not_confirmed`, "must explain why confirmation failed"));
    }
  } else {
    if (confirmationStatus !== "confirmed") {
      errors.push(err(`${pathName}.confirmation_status`, "must be 'confirmed' for findings"));
    }
    if (finding.reason_not_confirmed !== null) {
      errors.push(err(`${pathName}.reason_not_confirmed`, "must be null for confirmed findings"));
    }
  }

  if (
    isNonEmptyString(finding.severity_claimed) &&
    ["Critical", "High"].includes(finding.severity_claimed)
  ) {
    if (!isNonEmptyString(finding.observed_result) || !isNonEmptyString(finding.impact_claimed)) {
      errors.push(
        err(pathName, "high-impact findings need concrete observed_result and impact_claimed")
      );
    }
  }

  return errors;
}

function validateBundle(bundle) {
  const errors = [];

  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    return [err("bundle", "must be an object")];
  }

  const meta = bundle.meta;
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    errors.push(err("meta", "must be an object"));
  } else {
    if (meta.schema_version !== "2.0") {
      errors.push(err("meta.schema_version", "must be '2.0'"));
    }
    if (!isIsoDate(meta.generated_at)) {
      errors.push(err("meta.generated_at", "must be an ISO8601 UTC timestamp"));
    }
    if (!ASSET_TYPES.has(meta.asset_type)) {
      errors.push(err("meta.asset_type", "must be one of webapp, mobileapp, chromeext, executable"));
    }
    if (!ANALYSIS_MODES.has(meta.analysis_mode)) {
      errors.push(err("meta.analysis_mode", "must be whitebox or blackbox"));
    }
    for (const field of ["target_name", "target_version", "researcher_agent"]) {
      if (!isNonEmptyString(meta[field])) {
        errors.push(err(`meta.${field}`, "must be a non-empty string"));
      }
    }
    if (!isWebUrl(meta.program_url)) {
      errors.push(err("meta.program_url", "must be an http(s) URL"));
    }
  }

  const assetType = meta?.asset_type;

  if (!Array.isArray(bundle.findings)) {
    errors.push(err("findings", "must be an array"));
  } else if (assetType) {
    bundle.findings.forEach((finding, index) => {
      errors.push(...validateFindingCommon(finding, assetType, `findings[${index}]`));
    });
  }

  if (!Array.isArray(bundle.unconfirmed_candidates)) {
    errors.push(err("unconfirmed_candidates", "must be an array"));
  } else if (assetType) {
    bundle.unconfirmed_candidates.forEach((candidate, index) => {
      // Agents sometimes write string IDs instead of full objects — skip those entries
      // rather than aborting the pipeline; they carry no submission-relevant data.
      if (typeof candidate === "string") return;
      errors.push(
        ...validateFindingCommon(candidate, assetType, `unconfirmed_candidates[${index}]`, {
          isCandidate: true
        })
      );
    });
  }

  const summary = bundle.analysis_summary;
  if (!summary || typeof summary !== "object" || Array.isArray(summary)) {
    errors.push(err("analysis_summary", "must be an object"));
  } else {
    for (const field of [
      "files_analyzed",
      "grep_hits_total",
      "candidates_found",
      "confirmed_findings",
      "time_spent_minutes"
    ]) {
      if (typeof summary[field] !== "number" || Number.isNaN(summary[field]) || summary[field] < 0) {
        errors.push(err(`analysis_summary.${field}`, "must be a non-negative number"));
      }
    }
  }

  if (
    Array.isArray(bundle.findings) &&
    summary &&
    typeof summary.confirmed_findings === "number"
  ) {
    if (summary.confirmed_findings !== bundle.findings.length) {
      errors.push(
        err(
          "analysis_summary.confirmed_findings",
          "must equal findings.length for deterministic downstream use"
        )
      );
    }
  }

  return errors;
}

function validateTargetConfig(config) {
  const errors = [];

  if (!config || typeof config !== "object" || Array.isArray(config)) {
    return [err("target_config", "must be an object")];
  }

  if (config.schema_version !== "1.0") {
    errors.push(err("schema_version", "must be '1.0'"));
  }
  if (!isNonEmptyString(config.target_name)) {
    errors.push(err("target_name", "must be a non-empty string"));
  }
  if (!ASSET_TYPES.has(config.asset_type)) {
    errors.push(err("asset_type", "must be a supported asset type"));
  }
  if (!ANALYSIS_MODES.has(config.default_mode)) {
    errors.push(err("default_mode", "must be whitebox or blackbox"));
  }
  if (!Array.isArray(config.allowed_modes) || config.allowed_modes.length === 0) {
    errors.push(err("allowed_modes", "must be a non-empty array"));
  } else {
    config.allowed_modes.forEach((mode, index) => {
      if (!ANALYSIS_MODES.has(mode)) {
        errors.push(err(`allowed_modes[${index}]`, "must be whitebox or blackbox"));
      }
    });
    if (!config.allowed_modes.includes(config.default_mode)) {
      errors.push(err("allowed_modes", "must include default_mode"));
    }
  }
  if (!isWebUrl(config.program_url)) {
    errors.push(err("program_url", "must be an http(s) URL"));
  }
  for (const field of ["source_path", "findings_dir", "h1_reports_dir", "logs_dir"]) {
    if (!isNonEmptyString(config[field])) {
      errors.push(err(field, "must be a non-empty string"));
    }
  }
  if (config.intelligence_dir !== undefined && !isNonEmptyString(config.intelligence_dir)) {
    errors.push(err("intelligence_dir", "must be a non-empty string when provided"));
  }

  const scope = config.scope;
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) {
    errors.push(err("scope", "must be an object"));
  } else {
    for (const field of ["in_scope", "out_of_scope"]) {
      if (!Array.isArray(scope[field])) {
        errors.push(err(`scope.${field}`, "must be an array"));
      }
    }
  }

  if (!Array.isArray(config.rules) || config.rules.length === 0) {
    errors.push(err("rules", "must list at least one runtime rule"));
  }

  if (config.hackerone !== undefined) {
    const hackerone = config.hackerone;
    if (!hackerone || typeof hackerone !== "object" || Array.isArray(hackerone)) {
      errors.push(err("hackerone", "must be an object when provided"));
    } else {
      if (
        hackerone.program_handle !== undefined &&
        !isNonEmptyString(hackerone.program_handle)
      ) {
        errors.push(err("hackerone.program_handle", "must be a non-empty string"));
      }
      if (
        hackerone.sync_enabled !== undefined &&
        typeof hackerone.sync_enabled !== "boolean"
      ) {
        errors.push(err("hackerone.sync_enabled", "must be boolean"));
      }
    }
  }

  return errors;
}

function validateTriageResult(triageResult, bundle = null) {
  const errors = [];

  if (!triageResult || typeof triageResult !== "object" || Array.isArray(triageResult)) {
    return [err("triage_result", "must be an object")];
  }

  const meta = triageResult.meta;
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    errors.push(err("meta", "must be an object"));
  } else {
    if (!isIsoDate(meta.triaged_at)) {
      errors.push(err("meta.triaged_at", "must be an ISO8601 UTC timestamp"));
    }
    if (!ASSET_TYPES.has(meta.asset_type)) {
      errors.push(err("meta.asset_type", "must be a supported asset type"));
    }
    if (!isNonEmptyString(meta.calibration_module)) {
      errors.push(err("meta.calibration_module", "must be a non-empty string"));
    }
    for (const field of [
      "total_findings_received",
      "triaged",
      "not_applicable",
      "needs_more_info",
      "duplicate",
      "informative",
      "ready_to_submit"
    ]) {
      if (typeof meta[field] !== "number" || Number.isNaN(meta[field]) || meta[field] < 0) {
        errors.push(err(`meta.${field}`, "must be a non-negative number"));
      }
    }
  }

  if (!Array.isArray(triageResult.results)) {
    errors.push(err("results", "must be an array"));
    return errors;
  }

  triageResult.results.forEach((result, index) => {
    const pathName = `results[${index}]`;

    if (!result || typeof result !== "object" || Array.isArray(result)) {
      errors.push(err(pathName, "must be an object"));
      return;
    }

    // Validate report_id format to prevent path traversal in downstream file writers
    if (!isNonEmptyString(result.report_id) || !REPORT_ID_REGEX.test(result.report_id)) {
      errors.push(
        err(`${pathName}.report_id`, "must match PREFIX-NNN or PREFIX-NNN-CANDIDATE format")
      );
    }
    if (!TRIAGE_VERDICTS.has(result.triage_verdict)) {
      errors.push(err(`${pathName}.triage_verdict`, "must be a known verdict"));
    }
    if (
      !["Critical", "High", "Medium", "Low", "Informative", "N/A"].includes(result.analyst_severity)
    ) {
      errors.push(err(`${pathName}.analyst_severity`, "must be a known severity"));
    }
    if (
      typeof result.analyst_cvss_score !== "number" ||
      Number.isNaN(result.analyst_cvss_score) ||
      result.analyst_cvss_score < 0 ||
      result.analyst_cvss_score > 10
    ) {
      errors.push(err(`${pathName}.analyst_cvss_score`, "must be a number between 0 and 10"));
    }
    if (!isNonEmptyString(result.analyst_cvss_vector)) {
      errors.push(err(`${pathName}.analyst_cvss_vector`, "must be a non-empty string"));
    }
    if (!isNonEmptyString(result.cwe_confirmed)) {
      errors.push(err(`${pathName}.cwe_confirmed`, "must be a non-empty string"));
    }
    if (!["PASS", "FAIL"].includes(result.scope_check)) {
      errors.push(err(`${pathName}.scope_check`, "must be PASS or FAIL"));
    }
    if (!["PASS", "NEEDS_MORE_INFO"].includes(result.completeness_check)) {
      errors.push(err(`${pathName}.completeness_check`, "must be PASS or NEEDS_MORE_INFO"));
    }
    if (
      !["VALID", "INFORMATIVE", "NOT_APPLICABLE", "DUPLICATE"].includes(result.validity_check)
    ) {
      errors.push(err(`${pathName}.validity_check`, "must be a known validity value"));
    }
    if (result.duplicate_reference !== null && !isNonEmptyString(result.duplicate_reference)) {
      errors.push(err(`${pathName}.duplicate_reference`, "must be null or a non-empty string"));
    }
    if (typeof result.severity_delta !== "number" || Number.isNaN(result.severity_delta)) {
      errors.push(err(`${pathName}.severity_delta`, "must be numeric"));
    }
    if (!Array.isArray(result.nmi_questions)) {
      errors.push(err(`${pathName}.nmi_questions`, "must be an array"));
    }
    if (!Array.isArray(result.key_discrepancies)) {
      errors.push(err(`${pathName}.key_discrepancies`, "must be an array"));
    }
    if (typeof result.ready_to_submit !== "boolean") {
      errors.push(err(`${pathName}.ready_to_submit`, "must be boolean"));
    }
    if (typeof result.triage_summary !== "string") {
      errors.push(err(`${pathName}.triage_summary`, "must be a string"));
    }
    if (!isNonEmptyString(result.response_to_researcher)) {
      errors.push(err(`${pathName}.response_to_researcher`, "must be a non-empty string"));
    }
    if (result.triage_verdict === "NEEDS_MORE_INFO" && result.nmi_questions.length === 0) {
      errors.push(
        err(`${pathName}.nmi_questions`, "must contain at least one question for NMI verdicts")
      );
    }
    if (result.ready_to_submit && !isNonEmptyString(result.triage_summary)) {
      errors.push(
        err(`${pathName}.triage_summary`, "must be populated for ready_to_submit results")
      );
    }
  });

  if (bundle) {
    const expectedIds = new Set((bundle.findings || []).map((item) => item.report_id));
    const actualIds = new Set(triageResult.results.map((item) => item.report_id));

    for (const reportId of expectedIds) {
      if (!actualIds.has(reportId)) {
        errors.push(err("results", `missing triage entry for ${reportId}`));
      }
    }
    if (triageResult.meta.total_findings_received !== expectedIds.size) {
      errors.push(err("meta.total_findings_received", "must equal bundle findings count"));
    }
  }

  return errors;
}

module.exports = {
  isNonEmptyString,
  isIsoDate,
  isWebUrl,
  validateReportId,
  validateFindingCommon,
  validateBundle,
  validateTargetConfig,
  validateTriageResult
};
