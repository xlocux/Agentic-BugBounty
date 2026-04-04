#!/usr/bin/env node
"use strict";

/**
 * setup-tools.js — OS-agnostic first-run tool installer.
 *
 * Usage:
 *   node scripts/setup-tools.js            # install missing tools
 *   node scripts/setup-tools.js --check    # check only, no install
 *   node scripts/setup-tools.js --update   # reinstall/upgrade all tools
 *
 * Output:
 *   - Prints installation report
 *   - Writes tool_status.json to project root
 *   - Updates .env with detected binary paths
 */

process.env.NODE_OPTIONS = `${process.env.NODE_OPTIONS || ""} --no-warnings`.trim();

const fs   = require("node:fs");
const path = require("node:path");
const { execSync } = require("node:child_process");

// Load .env
(function loadDotEnv() {
  const envPath = path.resolve(__dirname, "../.env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const eq = t.indexOf("=");
    if (eq === -1) continue;
    const key = t.slice(0, eq).trim();
    const val = t.slice(eq + 1).trim();
    if (!process.env[key]) process.env[key] = val;
  }
})();

const {
  TOOLS, detectOS, detectPackageManagers,
  isToolInstalled, getToolPath, getToolVersion, buildToolStatus
} = require("./lib/tool-registry");

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const C = {
  reset:  "\x1b[0m",
  green:  "\x1b[32m", bgreen:  "\x1b[92m",
  red:    "\x1b[31m", bred:    "\x1b[91m",
  yellow: "\x1b[33m", byellow: "\x1b[93m",
  cyan:   "\x1b[36m", bold:    "\x1b[1m",
  dim:    "\x1b[2m",  gray:    "\x1b[90m"
};

function parseArgs(argv) {
  return {
    checkOnly: argv.includes("--check"),
    update:    argv.includes("--update")
  };
}

function installTool(name, def, os) {
  const cmd = def.install?.[os];
  if (!cmd) return { ok: false, reason: `no install command for ${os}` };

  try {
    process.stdout.write(`  ${C.cyan}installing ${name}...${C.reset}\n`);
    execSync(cmd, { stdio: "pipe", timeout: 120_000 });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e.message.slice(0, 100) };
  }
}

function updateEnvFile(updates) {
  const envPath = path.resolve(__dirname, "../.env");
  if (!fs.existsSync(envPath)) return;

  let content = fs.readFileSync(envPath, "utf8");
  const toAppend = [];

  for (const [key, value] of Object.entries(updates)) {
    if (!value) continue;
    const re = new RegExp(`^(${key}=).*$`, "m");
    if (re.test(content)) {
      content = content.replace(re, `$1${value}`);
    } else {
      // Key not yet in .env — append it
      toAppend.push(`${key}=${value}`);
    }
  }

  if (toAppend.length > 0) {
    const sep = content.endsWith("\n") ? "" : "\n";
    content += sep + toAppend.join("\n") + "\n";
  }

  fs.writeFileSync(envPath, content, "utf8");
}

async function main() {
  const args    = parseArgs(process.argv);
  const os      = detectOS();
  const pkgMgrs = detectPackageManagers();

  process.stdout.write(`\n${C.bold}${C.cyan}TOOL SETUP${C.reset} — OS: ${os} | Package managers: ${pkgMgrs.join(", ")}\n`);
  process.stdout.write(`${"═".repeat(60)}\n\n`);

  const results    = {};
  const envUpdates = {};

  for (const [name, def] of Object.entries(TOOLS)) {
    const checkCmd  = def.checkCmd || def.bin;
    const isFullCmd = !!def.checkCmd;
    const installed = isToolInstalled(checkCmd, isFullCmd);

    if (args.checkOnly) {
      const pth = installed ? getToolPath(def.bin) : null;
      const ver = installed ? getToolVersion(def.bin) : null;
      results[name] = { installed, path: pth, version: ver, action: "check_only" };
      if (!installed) {
        const fallback = os === "win32" && def.windowsFallback ? ` (${def.windowsFallback} fallback available)` : "";
        process.stdout.write(`  ${C.yellow}⚠${C.reset}  ${name.padEnd(14)} ${C.dim}not found${fallback}${C.reset}\n`);
      } else {
        process.stdout.write(`  ${C.bgreen}✓${C.reset} ${name.padEnd(14)} ${C.dim}${ver || ""}${C.reset}\n`);
        if (def.envKey && pth) envUpdates[def.envKey] = pth;
      }
      continue;
    }

    if (installed && !args.update) {
      const ver  = getToolVersion(def.bin);
      const pth  = getToolPath(def.bin);
      results[name] = { installed: true, path: pth, version: ver, action: "skip" };
      if (def.envKey && pth) envUpdates[def.envKey] = pth;
      process.stdout.write(`  ${C.bgreen}✓${C.reset} ${name.padEnd(14)} ${C.dim}${ver || ""}${C.reset}  ${C.gray}(already installed)${C.reset}\n`);
      continue;
    }

    // Handle Windows tools with no native install
    if (os === "win32" && !def.install?.win32) {
      const fallback = def.windowsFallback === "docker" ? " — Docker/WSL required" : " — manual install required";
      results[name] = { installed: false, path: null, version: null, action: "skip_no_win32" };
      process.stdout.write(`  ${C.yellow}⚠${C.reset}  ${name.padEnd(14)} ${C.dim}no Windows package${fallback}${C.reset}\n`);
      continue;
    }

    const install = installTool(name, def, os);
    if (install.ok) {
      const ver = getToolVersion(def.bin);
      const pth = getToolPath(def.bin);
      results[name] = { installed: true, path: pth, version: ver, action: "installed" };
      if (def.envKey && pth) envUpdates[def.envKey] = pth;
      process.stdout.write(`  ${C.bgreen}✓${C.reset} ${name.padEnd(14)} ${C.dim}${ver || ""}${C.reset}  ${C.green}(installed)${C.reset}\n`);
    } else {
      results[name] = { installed: false, path: null, version: null, action: "failed", reason: install.reason };
      process.stdout.write(`  ${C.bred}✗${C.reset} ${name.padEnd(14)} ${C.dim}${install.reason}${C.reset}\n`);
    }
  }

  // Write tool_status.json
  const statusPath = path.resolve(__dirname, "../tool_status.json");
  fs.writeFileSync(statusPath, JSON.stringify(results, null, 2), "utf8");

  // Update .env
  if (Object.keys(envUpdates).length > 0) updateEnvFile(envUpdates);

  // Summary
  const total     = Object.keys(results).length;
  const available = Object.values(results).filter(r => r.installed).length;
  const failed    = Object.values(results).filter(r => r.action === "failed").length;

  process.stdout.write(`\n${"═".repeat(60)}\n`);
  process.stdout.write(`${available}/${total} tools available`);
  if (failed > 0) process.stdout.write(`  ${C.bred}${failed} failed${C.reset}`);
  process.stdout.write(`\n`);

  if (available >= total * 0.8) {
    process.stdout.write(`${C.bgreen}Pipeline ready to jack in.${C.reset}\n\n`);
  } else {
    process.stdout.write(`${C.yellow}Some tools missing — pipeline will skip unavailable checks.${C.reset}\n\n`);
  }
}

main().catch(e => { process.stderr.write(`setup-tools error: ${e.message}\n`); process.exit(1); });
