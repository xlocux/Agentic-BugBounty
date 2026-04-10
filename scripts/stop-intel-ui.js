#!/usr/bin/env node
"use strict";

const fs   = require("node:fs");
const path = require("node:path");

const PID_FILE = path.resolve(__dirname, "../logs/ui/serve-intel-ui.pid");

function readPidFile() {
  try {
    const [pid, port] = fs.readFileSync(PID_FILE, "utf8").trim().split(":").map(Number);
    return { pid, port };
  } catch {
    return null;
  }
}

function isProcessAlive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

const entry = readPidFile();

if (!entry) {
  console.log("Intel UI is not running (no PID file found).");
  process.exit(0);
}

if (!isProcessAlive(entry.pid)) {
  console.log(`Intel UI is not running (stale PID ${entry.pid}).`);
  try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
  process.exit(0);
}

try {
  process.kill(entry.pid, "SIGTERM");
  // On Windows SIGTERM may not work — fall back to SIGKILL
  setTimeout(() => {
    if (isProcessAlive(entry.pid)) {
      try { process.kill(entry.pid, "SIGKILL"); } catch { /* ignore */ }
    }
    try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
    console.log(`Intel UI stopped (pid ${entry.pid}, port ${entry.port}).`);
  }, 500);
} catch (err) {
  console.error(`Failed to stop process ${entry.pid}: ${err.message}`);
  process.exit(1);
}
