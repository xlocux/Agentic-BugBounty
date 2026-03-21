#!/usr/bin/env node
"use strict";

const { requestJson } = require("./lib/hackerone");

function redact(value) {
  if (!value) return "(missing)";
  if (value.length <= 8) return "********";
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

async function main() {
  const username = process.env.H1_API_USERNAME || process.env.HACKERONE_API_USERNAME || "";
  const token = process.env.H1_API_TOKEN || process.env.HACKERONE_API_TOKEN || "";

  console.log("HackerOne Doctor");
  console.log(`- username present: ${username ? "yes" : "no"}`);
  console.log(`- token present: ${token ? "yes" : "no"}`);
  console.log(`- username preview: ${redact(username)}`);
  console.log(`- token preview: ${redact(token)}`);

  if (!username || !token) {
    console.log("");
    console.log("Set credentials with:");
    console.log('  H1_API_USERNAME="<api username>"');
    console.log('  H1_API_TOKEN="<api token>"');
    process.exit(1);
  }

  try {
    const report = await requestJson("/v1/hackers/reports/688894");
    console.log("");
    console.log("Report endpoint check: OK");
    console.log(`- report id: ${report.data?.id || "unknown"}`);
    console.log(`- type: ${report.data?.type || "unknown"}`);
  } catch (error) {
    console.log("");
    console.log("Report endpoint check: FAILED");
    console.log(`- error: ${error.message}`);
    process.exit(1);
  }

  try {
    const programs = await requestJson("/v1/hackers/programs", {
      searchParams: { "page[size]": 1, "page[number]": 1 }
    });
    console.log("");
    console.log("Programs endpoint check: OK");
    console.log(`- programs returned: ${Array.isArray(programs.data) ? programs.data.length : 0}`);
  } catch (error) {
    console.log("");
    console.log("Programs endpoint check: FAILED");
    console.log(`- error: ${error.message}`);
    process.exit(1);
  }

  console.log("");
  console.log("Diagnosis: credentials are valid and core HackerOne API endpoints respond correctly.");
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
