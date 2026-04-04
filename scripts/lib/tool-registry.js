"use strict";

const { execSync } = require("node:child_process");
const os           = require("node:os");
const path         = require("node:path");

// ── Tool definitions ─────────────────────────────────────────────────────────
// Each entry: { bin, type, install: { linux, win32, darwin }, envKey }
// type: "go" | "python" | "ruby" | "rust" | "binary" | "runtime"
// install commands are run as-is via shell; null = manual install required

const TOOLS = {
  // ── Runtimes ────────────────────────────────────────────────────────────────
  node:    { bin: "node",    type: "runtime", install: { linux: null, win32: "winget install OpenJS.NodeJS", darwin: "brew install node" } },
  python3: { bin: process.platform === "win32" ? "python" : "python3", type: "runtime",
             install: { linux: "apt-get install -y python3", win32: "winget install Python.Python.3", darwin: "brew install python3" } },
  go:      { bin: "go",     type: "runtime", install: { linux: "apt-get install -y golang-go", win32: "winget install GoLang.Go", darwin: "brew install go" } },
  docker:  { bin: "docker", type: "binary",  install: { linux: "apt-get install -y docker.io", win32: "winget install Docker.DockerDesktop", darwin: "brew install --cask docker" } },

  // ── Go tools ────────────────────────────────────────────────────────────────
  subfinder:  { bin: "subfinder",  type: "go", install: { linux: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", win32: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", darwin: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" }, envKey: "SUBFINDER_BIN" },
  ffuf:       { bin: "ffuf",       type: "go", install: { linux: "go install github.com/ffuf/ffuf/v2@latest", win32: "go install github.com/ffuf/ffuf/v2@latest", darwin: "go install github.com/ffuf/ffuf/v2@latest" }, envKey: "FFUF_BIN" },
  httpx:      { bin: "httpx",      type: "go", install: { linux: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", win32: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", darwin: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest" }, envKey: "HTTPX_BIN" },
  nuclei:     { bin: "nuclei",     type: "go", install: { linux: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", win32: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", darwin: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" }, envKey: "NUCLEI_BIN" },
  gobuster:   { bin: "gobuster",   type: "go", install: { linux: "go install github.com/OJ/gobuster/v3@latest", win32: "go install github.com/OJ/gobuster/v3@latest", darwin: "go install github.com/OJ/gobuster/v3@latest" }, envKey: "GOBUSTER_BIN" },
  gitleaks:   { bin: "gitleaks",   type: "go", install: { linux: "go install github.com/gitleaks/gitleaks/v8@latest", win32: "go install github.com/gitleaks/gitleaks/v8@latest", darwin: "go install github.com/gitleaks/gitleaks/v8@latest" } },
  dalfox:     { bin: "dalfox",     type: "go", install: { linux: "go install github.com/hahwul/dalfox/v2@latest", win32: "go install github.com/hahwul/dalfox/v2@latest", darwin: "go install github.com/hahwul/dalfox/v2@latest" }, envKey: "DALFOX_BIN" },
  trufflehog: { bin: "trufflehog", type: "go", install: { linux: "go install github.com/trufflesecurity/trufflehog/v3@latest", win32: "go install github.com/trufflesecurity/trufflehog/v3@latest", darwin: "go install github.com/trufflesecurity/trufflehog/v3@latest" } },
  interactsh: { bin: "interactsh-client", type: "go", install: { linux: "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", win32: "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", darwin: "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" }, envKey: "INTERACTSH_BIN" },

  // ── Python tools ─────────────────────────────────────────────────────────────
  sqlmap:   { bin: "sqlmap",   type: "python", install: { linux: "pip3 install sqlmap", win32: "pip install sqlmap", darwin: "pip3 install sqlmap" }, envKey: "SQLMAP_BIN" },
  ghauri:   { bin: "ghauri",   type: "python", install: { linux: "pip3 install ghauri", win32: "pip install ghauri", darwin: "pip3 install ghauri" }, envKey: "GHAURI_BIN" },
  jwt_tool: { bin: "jwt_tool", type: "python", install: { linux: "pip3 install jwt_tool", win32: "pip install jwt_tool", darwin: "pip3 install jwt_tool" } },
  brojack:  { bin: "python3",  type: "python", install: { linux: "pip3 install requests beautifulsoup4", win32: "pip install requests beautifulsoup4", darwin: "pip3 install requests beautifulsoup4" }, envKey: "BROJACK_BIN", checkCmd: "python3 -c \"import requests, bs4\"" },

  // ── Binary tools ─────────────────────────────────────────────────────────────
  nmap:        { bin: "nmap",        type: "binary", install: { linux: "apt-get install -y nmap",        win32: "winget install Insecure.Nmap",            darwin: "brew install nmap" },        envKey: "NMAP_BIN" },
  whatweb:     { bin: "whatweb",     type: "binary", install: { linux: "apt-get install -y whatweb",    win32: null,                                         darwin: "brew install whatweb" },     envKey: "WHATWEB_BIN", windowsFallback: "docker" },
  nikto:       { bin: "nikto",       type: "binary", install: { linux: "apt-get install -y nikto",      win32: null,                                         darwin: "brew install nikto" },       envKey: "NIKTO_BIN",   windowsFallback: "docker" },
  feroxbuster: { bin: "feroxbuster", type: "rust",   install: { linux: "apt-get install -y feroxbuster",win32: "winget install epi052.feroxbuster",          darwin: "brew install feroxbuster" }, envKey: "FEROXBUSTER_BIN" },
  wpscan:      { bin: "wpscan",      type: "ruby",   install: { linux: "gem install wpscan",            win32: "gem install wpscan",                         darwin: "gem install wpscan" },       envKey: "WPSCAN_BIN" },
};

// ── OS detection ─────────────────────────────────────────────────────────────

function detectOS() {
  return process.platform; // "linux" | "win32" | "darwin"
}

// ── Package manager detection ─────────────────────────────────────────────────

function detectPackageManagers() {
  const candidates = process.platform === "win32"
    ? ["winget", "scoop", "choco", "pip", "go"]
    : process.platform === "darwin"
      ? ["brew", "pip3", "go", "gem"]
      : ["apt-get", "dnf", "pacman", "apk", "pip3", "go", "gem"];

  return candidates.filter(cmd => {
    try { execSync(`${cmd} --version 2>&1`, { stdio: "pipe", timeout: 3000 }); return true; }
    catch { return false; }
  });
}

// ── Tool availability check ───────────────────────────────────────────────────

function isToolInstalled(binOrCheckCmd, isFullCmd = false) {
  try {
    const probe = isFullCmd ? binOrCheckCmd : `${binOrCheckCmd} --version 2>&1`;
    execSync(probe, { stdio: "pipe", timeout: 5000 });
    return true;
  } catch {
    if (isFullCmd) return false; // compound commands don't fall through to which/where
    try {
      execSync(`which ${binOrCheckCmd} 2>&1`, { stdio: "pipe", timeout: 3000 });
      return true;
    } catch {
      try {
        execSync(`where ${binOrCheckCmd} 2>&1`, { stdio: "pipe", timeout: 3000 });
        return true;
      } catch {
        return false;
      }
    }
  }
}

function getToolVersion(bin) {
  try {
    const out = execSync(`${bin} --version 2>&1`, { stdio: "pipe", timeout: 5000 }).toString().trim();
    const match = out.match(/[\d]+\.[\d]+[\d.]*/);
    return match ? match[0] : out.slice(0, 30);
  } catch {
    return null;
  }
}

function getToolPath(bin) {
  try {
    const cmd = process.platform === "win32" ? `where ${bin}` : `which ${bin}`;
    return execSync(cmd, { stdio: "pipe", timeout: 3000 }).toString().split("\n")[0].trim();
  } catch {
    return null;
  }
}

// ── Build status snapshot ─────────────────────────────────────────────────────

function buildToolStatus() {
  const status = {};
  for (const [name, def] of Object.entries(TOOLS)) {
    const checkCmd  = def.checkCmd || def.bin;
    const isFullCmd = !!def.checkCmd;
    const installed = isToolInstalled(checkCmd, isFullCmd);
    status[name] = {
      installed,
      path:    installed ? getToolPath(def.bin) : null,
      version: installed ? getToolVersion(def.bin) : null,
      envKey:  def.envKey || null,
      windowsFallback: def.windowsFallback || null
    };
  }
  return status;
}

module.exports = {
  TOOLS,
  detectOS,
  detectPackageManagers,
  isToolInstalled,
  getToolVersion,
  getToolPath,
  buildToolStatus
};
