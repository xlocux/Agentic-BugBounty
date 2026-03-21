"use strict";

const fs = require("node:fs");
const path = require("node:path");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function resolveTargetConfigPath(targetArg) {
  const candidate = path.resolve(targetArg);
  const stats = fs.existsSync(candidate) ? fs.statSync(candidate) : null;

  if (stats?.isFile()) {
    return candidate;
  }
  if (stats?.isDirectory()) {
    return path.join(candidate, "target.json");
  }

  return path.resolve("targets", targetArg, "target.json");
}

function deriveProgramHandle(config) {
  if (config?.hackerone?.program_handle) {
    return config.hackerone.program_handle;
  }

  if (typeof config?.program_url === "string") {
    try {
      const parsed = new URL(config.program_url);
      if (parsed.hostname === "hackerone.com") {
        return parsed.pathname.replace(/^\/+|\/+$/g, "") || null;
      }
    } catch {
      return null;
    }
  }

  return null;
}

module.exports = {
  deriveProgramHandle,
  readJson,
  writeJson,
  ensureDir,
  resolveTargetConfigPath
};
