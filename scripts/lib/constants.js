"use strict";

const ASSET_TYPES = new Set(["webapp", "mobileapp", "browserext", "executable"]);
const ANALYSIS_MODES = new Set(["whitebox", "blackbox"]);
const SEVERITIES = ["Informative", "Low", "Medium", "High", "Critical"];
const TRIAGE_VERDICTS = new Set([
  "TRIAGED",
  "NOT_APPLICABLE",
  "NEEDS_MORE_INFO",
  "DUPLICATE",
  "INFORMATIVE"
]);
const REPORT_PREFIX_BY_ASSET = {
  webapp: "WEB",
  mobileapp: "MOB",
  browserext: "EXT",
  executable: "EXE"
};

const CVSS_REGEX =
  /^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/;
const CWE_REGEX = /^CWE-\d+: .+$/;
const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const URL_PROTOCOLS = new Set(["http:", "https:"]);

// Safe report ID pattern — used to prevent path traversal in downstream file writers
const REPORT_ID_REGEX = /^[A-Z]+-\d{3}(-CANDIDATE)?$/;

module.exports = {
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
};
