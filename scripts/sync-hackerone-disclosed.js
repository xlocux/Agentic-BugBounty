#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const {
  persistDisclosedDataset,
  syncGlobalDisclosedReports
} = require("./lib/contracts");

function parseArgs(argv) {
  const parsed = {
    fullHistory: false,
    maxPages: undefined,
    pageSize: undefined,
    startDate: undefined,
    endDate: undefined,
    windowDays: undefined,
    outDir: path.resolve("data", "global-intelligence")
  };

  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--full-history") {
      parsed.fullHistory = true;
    } else
    if (value.startsWith("--max-pages=")) {
      parsed.maxPages = Number(value.split("=")[1]);
    } else if (value === "--max-pages") {
      parsed.maxPages = Number(argv[++index]);
    } else if (value.startsWith("--page-size=")) {
      parsed.pageSize = Number(value.split("=")[1]);
    } else if (value === "--page-size") {
      parsed.pageSize = Number(argv[++index]);
    } else if (value.startsWith("--start-date=")) {
      parsed.startDate = value.split("=")[1];
    } else if (value === "--start-date") {
      parsed.startDate = argv[++index];
    } else if (value.startsWith("--end-date=")) {
      parsed.endDate = value.split("=")[1];
    } else if (value === "--end-date") {
      parsed.endDate = argv[++index];
    } else if (value.startsWith("--window-days=")) {
      parsed.windowDays = Number(value.split("=")[1]);
    } else if (value === "--window-days") {
      parsed.windowDays = Number(argv[++index]);
    } else if (value === "--out-dir") {
      parsed.outDir = path.resolve(argv[++index]);
    } else if (value.startsWith("--out-dir=")) {
      parsed.outDir = path.resolve(value.split("=")[1]);
    }
  }

  return parsed;
}

async function main() {
  const args = parseArgs(process.argv);
  const autoBootstrap =
    !args.fullHistory &&
    !fs.existsSync(path.join(args.outDir, "h1_disclosed_reports.json")) &&
    !fs.existsSync(path.join(args.outDir, "agentic-bugbounty-global.db"));

  const payload = await syncGlobalDisclosedReports({
    fullHistory: args.fullHistory || autoBootstrap,
    maxPages: args.maxPages,
    pageSize: args.pageSize,
    startDate: args.startDate,
    endDate: args.endDate,
    windowDays: args.windowDays
  });
  const databasePath = persistDisclosedDataset(args.outDir, payload);

  console.log("Global HackerOne disclosed dataset synced");
  console.log(`- json snapshot: ${path.join(args.outDir, "h1_disclosed_reports.json")}`);
  console.log(`- sqlite database: ${databasePath}`);
  console.log(`- mode: ${payload.meta.mode || (autoBootstrap ? "full-history" : "latest-window")}`);
  if (payload.meta.range) {
    console.log(`- range: ${payload.meta.range.start_date} -> ${payload.meta.range.end_date}`);
  }
  if (payload.meta.adaptive) {
    console.log(`- adaptive windows queried: ${payload.meta.adaptive.windows_queried}`);
    console.log(`- adaptive splits: ${payload.meta.adaptive.window_splits}`);
  }
  console.log(`- max pages requested: ${payload.meta.paging.max_pages_requested}`);
  console.log(`- page size: ${payload.meta.paging.page_size}`);
  console.log(`- disclosed reports: ${payload.meta.counts.disclosed_reports}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
