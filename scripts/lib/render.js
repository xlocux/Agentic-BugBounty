"use strict";

function renderH1ReportMarkdown(finding, triageResult) {
  return [
    `# ${finding.finding_title}`,
    "",
    `- Report ID: ${finding.report_id}`,
    `- Analyst Severity: ${triageResult.analyst_severity}`,
    `- Analyst CVSS: ${triageResult.analyst_cvss_score.toFixed(1)} ${triageResult.analyst_cvss_vector}`,
    `- CWE: ${triageResult.cwe_confirmed}`,
    "",
    "## Summary",
    finding.summary,
    "",
    "## Steps To Reproduce",
    ...finding.steps_to_reproduce.map((step) => `- ${step}`),
    "",
    "## PoC",
    "```text",
    finding.poc_code,
    "```",
    "",
    "## Observed Result",
    finding.observed_result,
    "",
    "## Impact",
    finding.impact_claimed,
    "",
    "## Remediation",
    finding.remediation_suggested,
    "",
    "## Triage Summary",
    triageResult.triage_summary,
    "",
    "## Researcher Notes",
    finding.researcher_notes
  ].join("\n");
}

module.exports = { renderH1ReportMarkdown };
