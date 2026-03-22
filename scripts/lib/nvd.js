"use strict";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RATE_DELAY_MS = 7000; // 5 req/30s without key → ~1 req/7s

/**
 * Search NVD for CVEs matching a keyword string.
 * Returns array of normalized CVE objects.
 */
async function searchCves(keywords, { resultsPerPage = 20 } = {}) {
  const url = `${NVD_BASE}?keywordSearch=${encodeURIComponent(keywords)}&resultsPerPage=${resultsPerPage}`;
  const res = await fetch(url, {
    headers: { "Accept": "application/json", "User-Agent": "agentic-bugbounty/1.0" }
  });
  if (!res.ok) throw new Error(`NVD API error: HTTP ${res.status}`);
  const data = await res.json();
  return (data.vulnerabilities || []).map(normalizeCve);
}

function normalizeCve(item) {
  const cve = item.cve;
  const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || null;
  const cweId = cve.weaknesses?.[0]?.description?.[0]?.value || null;
  const desc = cve.descriptions?.find((d) => d.lang === "en")?.value || "";
  const versions = [];
  for (const config of (cve.configurations || [])) {
    for (const node of (config.nodes || [])) {
      for (const match of (node.cpeMatch || [])) {
        if (match.versionStartIncluding || match.versionEndExcluding) {
          versions.push({
            cpe: match.criteria,
            from: match.versionStartIncluding || null,
            to: match.versionEndExcluding || null
          });
        }
      }
    }
  }
  return {
    cve_id: cve.id,
    description: desc,
    cvss_score: metrics?.cvssData?.baseScore || null,
    cvss_vector: metrics?.cvssData?.vectorString || null,
    cwe_id: cweId,
    affected_versions: versions,
    published_date: cve.published || null
  };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { searchCves, RATE_DELAY_MS, delay };
