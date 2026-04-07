#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");
const {
  deriveProgramHandle,
  loadDisclosedDataset,
  loadProgramIntel,
  readJson,
  resolveTargetConfigPath
} = require("./lib/contracts");
const { createJob, startJob, stopJob, getJob, listJobs, tailJob } = require("./lib/ui-jobs");
const { streamChatResponse } = require("./lib/ui-chat");
const { serveBrowse } = require("./lib/ui-static");

const PID_FILE  = path.resolve("logs", "ui", "serve-intel-ui.pid");
const ENV_PATH  = path.resolve(".env");
const UI_DIST   = path.resolve("ui", "dist");

const SETTINGS_WHITELIST = new Set([
  "H1_API_TOKEN", "H1_API_USERNAME",
  "OPENROUTER_API_KEY",
  "OPENROUTER_API_KEY_1", "OPENROUTER_API_KEY_2", "OPENROUTER_API_KEY_3",
  "OPENROUTER_API_KEY_4", "OPENROUTER_API_KEY_5",
  "BBSCOPE_API_KEY",
  "NOTIFY_WEBHOOK_URL"
]);

function readEnvFile() {
  if (!fs.existsSync(ENV_PATH)) return {};
  const entries = {};
  for (const line of fs.readFileSync(ENV_PATH, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim();
    if (key) entries[key] = val;
  }
  return entries;
}

function writeEnvKey(key, value) {
  const entries = readEnvFile();
  entries[key] = value;
  const lines = Object.entries(entries).map(([k, v]) => `${k}=${v}`);
  fs.writeFileSync(ENV_PATH, lines.join("\n") + "\n", "utf8");
}

function maskValue(val) {
  if (!val || val.length < 8) return val ? "****" : "";
  return val.slice(0, 4) + "****" + val.slice(-4);
}

function serveStatic(req, res) {
  const urlPath = req.url.split("?")[0];
  let filePath = path.join(UI_DIST, urlPath === "/" ? "index.html" : urlPath);
  if (!path.extname(filePath) || !fs.existsSync(filePath)) {
    filePath = path.join(UI_DIST, "index.html");
  }
  if (!fs.existsSync(filePath)) { res.writeHead(404); res.end("Not found"); return; }
  const ext  = path.extname(filePath).slice(1);
  const mime = {
    html: "text/html", js: "application/javascript", css: "text/css",
    svg:  "image/svg+xml", png: "image/png", ico: "image/x-icon",
    json: "application/json", woff2: "font/woff2", woff: "font/woff",
    ttf:  "font/ttf", map: "application/json"
  };
  res.writeHead(200, { "Content-Type": mime[ext] || "application/octet-stream" });
  fs.createReadStream(filePath).pipe(res);
}

// SSE session watchers: target → { watcher, clients: Set<res>, lastMtime, pollInterval }
const sessionWatchers = new Map();

function getSessionWatcher(target) {
  if (sessionWatchers.has(target)) return sessionWatchers.get(target);
  const sessionPath = path.resolve("targets", target, "session.json");
  const entry = { watcher: null, clients: new Set(), lastMtime: 0, pollInterval: null };
  sessionWatchers.set(target, entry);

  function broadcast() {
    if (!fs.existsSync(sessionPath)) return;
    try {
      const stat = fs.statSync(sessionPath);
      if (stat.mtimeMs <= entry.lastMtime) return;
      entry.lastMtime = stat.mtimeMs;
      const data  = fs.readFileSync(sessionPath, "utf8");
      const event = `data: ${JSON.stringify({ type: "session_update", data: JSON.parse(data) })}\n\n`;
      for (const client of entry.clients) {
        try { client.write(event); } catch { entry.clients.delete(client); }
      }
    } catch { /* file may be mid-write */ }
  }

  try { entry.watcher = fs.watch(sessionPath, () => broadcast()); } catch { /* polling covers it */ }
  entry.pollInterval = setInterval(broadcast, 2000);
  return entry;
}

function readPidFile() {
  try {
    const raw = fs.readFileSync(PID_FILE, "utf8").trim();
    const [pid, port] = raw.split(":").map(Number);
    return { pid, port };
  } catch {
    return null;
  }
}

function writePidFile(port) {
  fs.mkdirSync(path.dirname(PID_FILE), { recursive: true });
  fs.writeFileSync(PID_FILE, `${process.pid}:${port}`, "utf8");
}

function removePidFile() {
  try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
}

function isProcessAlive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function checkSingleInstance(preferredPort) {
  const existing = readPidFile();
  if (existing && isProcessAlive(existing.pid)) {
    const url = `http://127.0.0.1:${existing.port}`;
    console.log(`Intel UI is already running at ${url} (pid ${existing.pid})`);
    if (preferredPort) openBrowser(url);
    process.exit(0);
  }
  removePidFile();
}

function parseArgs(argv) {
  const parsed = {
    port: 31337,
    target: null,
    globalDir: path.resolve("data", "global-intelligence"),
    open: false
  };

  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--port") parsed.port = Number(argv[++index]);
    else if (value.startsWith("--port=")) parsed.port = Number(value.split("=")[1]);
    else if (value === "--target") parsed.target = argv[++index];
    else if (value.startsWith("--target=")) parsed.target = value.split("=")[1];
    else if (value === "--global-dir") parsed.globalDir = path.resolve(argv[++index]);
    else if (value.startsWith("--global-dir=")) parsed.globalDir = path.resolve(value.split("=")[1]);
    else if (value === "--open") parsed.open = true;
  }

  return parsed;
}

function getTargetContext(targetArg) {
  const configPath = resolveTargetConfigPath(targetArg);
  const config = readJson(configPath);
  const targetDir = path.dirname(configPath);
  const intelligenceDir = path.resolve(targetDir, config.intelligence_dir || "./intelligence");
  const programHandle = deriveProgramHandle(config);
  return {
    config,
    targetDir,
    intelligenceDir,
    programHandle
  };
}

function listTargetDirs() {
  const targetsBase = path.resolve("targets");
  if (!fs.existsSync(targetsBase)) return [];
  return fs.readdirSync(targetsBase)
    .filter(name => fs.existsSync(path.join(targetsBase, name, "target.json")))
    .map(name => {
      const cfgPath  = path.join(targetsBase, name, "target.json");
      const cfg      = (() => { try { return JSON.parse(fs.readFileSync(cfgPath, "utf8")); } catch { return {}; } })();
      const bundlePath = path.join(targetsBase, name, "findings", "confirmed", "report_bundle.json");
      const bundle   = (() => { try { return JSON.parse(fs.readFileSync(bundlePath, "utf8")); } catch { return null; } })();
      const running  = listJobs().find(j => j.target === name && j.status === "running");
      return {
        name,
        asset_type:     cfg.asset_type || "unknown",
        default_mode:   cfg.default_mode || "whitebox",
        finding_count:  bundle?.findings?.length ?? 0,
        status:         running ? "running" : "idle",
        active_job_id:  running?.id || null,
        last_run:       listJobs().find(j => j.target === name)?.started || null
      };
    });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => { data += chunk; });
    req.on("end", () => {
      try { resolve(JSON.parse(data || "{}")); }
      catch { resolve({}); }
    });
    req.on("error", reject);
  });
}

function sseStart(res) {
  res.writeHead(200, {
    "Content-Type":  "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection":    "keep-alive",
    "Access-Control-Allow-Origin": "*"
  });
  res.write(":\n\n");
}

function sseSend(res, obj) {
  res.write(`data: ${JSON.stringify(obj)}\n\n`);
}

function sendJson(response, payload) {
  response.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload, null, 2));
}

function sendHtml(response, html, statusCode = 200) {
  response.writeHead(statusCode, { "Content-Type": "text/html; charset=utf-8" });
  response.end(html);
}

function sendNotFound(response) {
  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Not Found");
}



function buildGlobalSummary(globalDataset) {
  if (!globalDataset) {
    return null;
  }

  return {
    meta: globalDataset.meta,
    summaries: globalDataset.summaries,
    counts: {
      disclosed_reports: globalDataset.meta?.counts?.disclosed_reports || 0,
      programs: (globalDataset.summaries?.top_programs || []).length,
      weaknesses: (globalDataset.summaries?.top_weaknesses || []).length
    }
  };
}

function queryGlobalDataset(globalDataset, params) {
  const reports = globalDataset?.disclosed_reports || [];
  const q = (params.get("q") || "").trim().toLowerCase();
  const program = (params.get("program") || "").trim().toLowerCase();
  const weakness = (params.get("weakness") || "").trim().toLowerCase();
  const severity = (params.get("severity") || "").trim().toLowerCase();
  const page = Math.max(1, Number(params.get("page") || 1));
  const pageSize = Math.min(100, Math.max(10, Number(params.get("page_size") || 25)));

  const filtered = reports.filter((item) => {
    if (program && String(item.program_handle || "").toLowerCase() !== program) {
      return false;
    }
    const weaknessLabel = String(item.weakness || item.cwe || "").toLowerCase();
    if (weakness && weaknessLabel !== weakness) {
      return false;
    }
    if (severity && String(item.severity_rating || "").toLowerCase() !== severity) {
      return false;
    }
    if (q) {
      const haystack = [
        item.program_name,
        item.program_handle,
        item.title,
        item.weakness,
        item.cwe,
        item.url
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(q)) {
        return false;
      }
    }
    return true;
  });

  const start = (page - 1) * pageSize;
  const pageItems = filtered.slice(start, start + pageSize);

  const topPrograms = [...new Set(reports.map((item) => item.program_handle).filter(Boolean))]
    .sort()
    .slice(0, 300);
  const topWeaknesses = [...new Set(reports.map((item) => item.weakness || item.cwe).filter(Boolean))]
    .sort()
    .slice(0, 300);
  const severities = [...new Set(reports.map((item) => item.severity_rating).filter(Boolean))]
    .sort();

  return {
    meta: globalDataset.meta,
    total: filtered.length,
    page,
    page_size: pageSize,
    total_pages: Math.max(1, Math.ceil(filtered.length / pageSize)),
    items: pageItems,
    filters: {
      q,
      program,
      weakness,
      severity
    },
    options: {
      programs: topPrograms,
      weaknesses: topWeaknesses,
      severities
    }
  };
}

function listenWithFallback(server, preferredPort, maxAttempts = 20) {
  return new Promise((resolve, reject) => {
    let currentPort = preferredPort;
    let attempts = 0;

    function tryListen() {
      attempts += 1;
      server.once("error", onError);
      server.listen(currentPort, () => {
        server.removeListener("error", onError);
        resolve(currentPort);
      });
    }

    function onError(error) {
      server.removeListener("error", onError);
      if (error && error.code === "EADDRINUSE" && attempts < maxAttempts) {
        currentPort += 1;
        tryListen();
        return;
      }
      reject(error);
    }

    tryListen();
  });
}

function openBrowser(url) {
  try {
    if (process.platform === "win32") {
      spawn("cmd", ["/c", "start", "", url], {
        detached: true,
        stdio: "ignore"
      }).unref();
      return;
    }
    if (process.platform === "darwin") {
      spawn("open", [url], { detached: true, stdio: "ignore" }).unref();
      return;
    }
    spawn("xdg-open", [url], { detached: true, stdio: "ignore" }).unref();
  } catch {
    // Non-fatal: the URL is still printed to stdout.
  }
}

function main() {
  const args = parseArgs(process.argv);
  checkSingleInstance(args.open);
  const appHtmlPath = path.resolve("docs", "intel-ui.html");
  const targetContext = args.target ? getTargetContext(args.target) : null;
  const roots = {
    global: args.globalDir,
    target: targetContext ? targetContext.intelligenceDir : path.resolve("targets"),
    targets: path.resolve("targets")
  };

  async function handleRequest(request, response) {
    const parsedUrl = new URL(request.url, `http://${request.headers.host || "127.0.0.1"}`);
    const method = request.method;
    const url    = parsedUrl.pathname;

    // ── Static UI (ui/dist/) ───────────────────────────────────────────────
    if (method === "GET" && !url.startsWith("/api/") && !url.startsWith("/static/")) {
      if (fs.existsSync(UI_DIST)) { serveStatic(request, response); return; }
      // fall through to legacy HTML if ui/dist/ not built yet
    }

    // ── Settings ───────────────────────────────────────────────────────────
    if (method === "GET" && url === "/api/settings") {
      const raw = readEnvFile();
      const settings = {};
      for (const key of SETTINGS_WHITELIST) {
        settings[key] = { masked: maskValue(raw[key] || ""), set: Boolean(raw[key]) };
      }
      return sendJson(response, settings);
    }

    if (method === "POST" && url === "/api/settings") {
      let body = "";
      request.on("data", (d) => { body += d; });
      request.on("end", () => {
        let parsed;
        try { parsed = JSON.parse(body); } catch {
          response.writeHead(400, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: "invalid JSON" })); return;
        }
        const { key, value } = parsed;
        if (!key || !SETTINGS_WHITELIST.has(key)) {
          response.writeHead(400, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: `key "${key}" not allowed` })); return;
        }
        writeEnvKey(key, String(value));
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ ok: true, key, masked: maskValue(String(value)) }));
      });
      return;
    }

    // ── Session ────────────────────────────────────────────────────────────
    if (method === "GET" && /^\/api\/session\/[^/]+$/.test(url)) {
      const target = url.replace("/api/session/", "");
      const sessionPath = path.resolve("targets", target, "session.json");
      if (!fs.existsSync(sessionPath)) {
        response.writeHead(404, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ error: "no session" })); return;
      }
      try {
        const data = JSON.parse(fs.readFileSync(sessionPath, "utf8"));
        return sendJson(response, data);
      } catch {
        response.writeHead(500, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ error: "could not read session" })); return;
      }
    }

    if (method === "POST" && /^\/api\/session\/[^/]+\/respond$/.test(url)) {
      const target = url.replace("/api/session/", "").replace("/respond", "");
      const responsePath = path.resolve("targets", target, "session-response.json");
      let body = "";
      request.on("data", (d) => { body += d; });
      request.on("end", () => {
        let payload;
        try { payload = JSON.parse(body); } catch {
          response.writeHead(400, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: "invalid JSON" })); return;
        }
        try {
          fs.mkdirSync(path.dirname(responsePath), { recursive: true });
          fs.writeFileSync(responsePath, JSON.stringify(payload, null, 2), "utf8");
          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ ok: true }));
        } catch (err) {
          response.writeHead(500, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }

    if (method === "GET" && /^\/api\/session\/[^/]+\/stream$/.test(url)) {
      const target = url.replace("/api/session/", "").replace("/stream", "");
      response.writeHead(200, {
        "Content-Type":  "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection":    "keep-alive"
      });
      response.write(": connected\n\n");
      const entry = getSessionWatcher(target);
      entry.clients.add(response);
      request.on("close", () => entry.clients.delete(response));
      return;
    }

    // ── GitHub Repos ───────────────────────────────────────────────────────
    if (method === "GET" && /^\/api\/targets\/[^/]+\/repos$/.test(url)) {
      const target = url.split("/")[3];
      const reposPath = path.resolve("targets", target, "intelligence", "github_repos.json");
      if (!fs.existsSync(reposPath)) {
        return sendJson(response, { repos: [], scanned_at: null });
      }
      try {
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(fs.readFileSync(reposPath, "utf8"));
      } catch {
        response.writeHead(500, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ error: "could not read repos" }));
      }
      return;
    }

    if (method === "POST" && /^\/api\/targets\/[^/]+\/repos\/clone$/.test(url)) {
      const target = url.split("/")[3];
      let body = "";
      request.on("data", (d) => { body += d; });
      request.on("end", () => {
        let parsed;
        try { parsed = JSON.parse(body); } catch {
          response.writeHead(400, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: "invalid JSON" })); return;
        }
        const urls = Array.isArray(parsed.urls) ? parsed.urls : [];
        if (urls.length === 0) {
          response.writeHead(400, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: "urls array required" })); return;
        }
        const cloneJobs = [];
        for (const repoUrl of urls) {
          const repoName = repoUrl.split("/").slice(-1)[0].replace(/\.git$/, "");
          const destPath = path.resolve("targets", target, "src", repoName);
          const job = createJob({
            target,
            script: "git",
            args: ["clone", repoUrl, destPath],
            label: `git clone ${repoName}`
          });
          startJob(job);
          cloneJobs.push({ url: repoUrl, job_id: job.id });
        }
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ clone_jobs: cloneJobs }));
      });
      return;
    }

    // ── Targets ────────────────────────────────────────────────────────────
    if (method === "GET" && url === "/api/targets") {
      return sendJson(response, listTargetDirs());
    }

    if (method === "POST" && url === "/api/targets/create") {
      const body = await readBody(request);
      const { name, program_url } = body;
      if (!name) return sendJson(response, { error: "name required" });

      const scaffoldArgs = ["scripts/new-target.js", name];
      if (program_url) scaffoldArgs.push("--program-url", program_url);
      const scaffoldJob = createJob({ target: name, script: "node", args: scaffoldArgs });
      startJob(scaffoldJob);

      const response_payload = { job_id: scaffoldJob.id, sync_job_id: null, intel_job_id: null };

      if (program_url) {
        // Auto-sync scope from program URL
        const scopeJob = createJob({
          target: name,
          script: "node",
          args: ["scripts/sync-program-scope.js", "--url", program_url]
        });
        startJob(scopeJob);
        response_payload.sync_job_id = scopeJob.id;

        // Auto-sync H1 intel (scope snapshot + disclosed reports) into target intelligence dir
        const intelJob = createJob({
          target: name,
          script: "node",
          args: ["scripts/sync-hackerone-intel.js", "--target", name]
        });
        startJob(intelJob);
        response_payload.intel_job_id = intelJob.id;
      }

      return sendJson(response, response_payload);
    }

    if (method === "POST" && /^\/api\/targets\/([^/]+)\/reset$/.test(url)) {
      const name = url.split("/")[3];
      const job  = createJob({ target: name, script: "node", args: ["scripts/reset-target.js", "--target", name] });
      startJob(job);
      return sendJson(response, { job_id: job.id });
    }

    // ── Run control ────────────────────────────────────────────────────────
    if (method === "POST" && url === "/api/run/start") {
      const body   = await readBody(request);
      const { target, mode, interactive, hitl, resume, skipIntel } = body;
      if (!target) return sendJson(response, { error: "target required" });

      if (!skipIntel) {
        const intelJob = createJob({
          target,
          script: "node",
          args: ["scripts/sync-hackerone-intel.js", "--target", target]
        });
        startJob(intelJob);
      }

      const args = ["scripts/run-pipeline.js", "--target", target, "--cli", "claude"];
      if (mode)        args.push("--mode", mode);
      if (interactive) args.push("--interactive");
      if (hitl)        args.push("--hitl");
      if (resume)      args.push("--resume");

      const runJob = createJob({ target, script: "node", args });
      startJob(runJob);
      return sendJson(response, { job_id: runJob.id });
    }

    if (method === "POST" && /^\/api\/run\/stop\/(.+)$/.test(url)) {
      const jobId = url.replace("/api/run/stop/", "");
      stopJob(jobId);
      return sendJson(response, { ok: true });
    }

    if (method === "GET" && /^\/api\/run\/status\/(.+)$/.test(url)) {
      const target = url.replace("/api/run/status/", "");
      if (target.includes("/") || target.includes("..") || target.includes("\\")) {
        response.writeHead(400); response.end("invalid target name"); return;
      }
      const job    = listJobs().find(j => j.target === target && j.status === "running");
      const bundlePath = path.resolve("targets", target, "findings", "confirmed", "report_bundle.json");
      const bundle = (() => { try { return JSON.parse(fs.readFileSync(bundlePath, "utf8")); } catch { return null; } })();
      return sendJson(response, {
        running:          !!job,
        job_id:           job?.id || null,
        started:          job?.started || null,
        finding_count:    bundle?.findings?.length ?? 0,
        domains_completed: bundle?.meta?.domains_completed ?? []
      });
    }

    // ── SSE stream ─────────────────────────────────────────────────────────
    if (method === "GET" && /^\/api\/stream\/(.+)$/.test(url)) {
      const jobId  = url.replace("/api/stream/", "");
      const from   = Number(parsedUrl.searchParams.get("from") || 0);
      const job    = getJob(jobId);
      if (!job) { response.writeHead(404); response.end("job not found"); return; }

      sseStart(response);
      sseSend(response, { type: "connected", job_id: jobId });

      const cancel = tailJob(jobId, from, (line, offset) => {
        const type = line.includes("✓") || line.includes("confirmed") ? "finding"
                   : line.includes("candidate") ? "candidate"
                   : line.includes("chain") ? "chain"
                   : "log";
        sseSend(response, { type, line, offset, ts: Date.now() });
      }, ({ exit_code }) => {
        sseSend(response, { type: "done", exit_code });
        response.end();
      });

      request.on("close", cancel);
      return;
    }

    // ── Jobs list ──────────────────────────────────────────────────────────
    if (method === "GET" && url === "/api/jobs") {
      return sendJson(response, listJobs().slice(0, 50));
    }

    // ── Per-target intelligence ────────────────────────────────────────────
    if (method === "GET" && /^\/api\/intelligence\/(.+)$/.test(url)) {
      const tgt = url.replace("/api/intelligence/", "");
      if (tgt.includes("/") || tgt.includes("..") || tgt.includes("\\")) {
        response.writeHead(400); response.end("invalid target name"); return;
      }
      try {
        const ctx = getTargetContext(tgt);
        return sendJson(response, {
          config: ctx.config,
          local: loadProgramIntel(ctx.intelligenceDir, ctx.programHandle)
        });
      } catch {
        return sendJson(response, { config: null, local: null });
      }
    }

    // ── Findings ───────────────────────────────────────────────────────────
    if (method === "GET" && /^\/api\/findings\/(.+)$/.test(url)) {
      const target = url.replace("/api/findings/", "");
      if (target.includes("/") || target.includes("..") || target.includes("\\")) {
        response.writeHead(400); response.end("invalid target name"); return;
      }
      const base   = path.resolve("targets", target, "findings");
      const bundle = (() => { try { return JSON.parse(fs.readFileSync(path.join(base, "confirmed", "report_bundle.json"), "utf8")); } catch { return null; } })();
      const triage = (() => { try { return JSON.parse(fs.readFileSync(path.join(base, "triage_result.json"), "utf8")); } catch { return null; } })();
      return sendJson(response, { bundle, triage });
    }

    // ── History ─────────────────────────────────────────────────────────────
    if (method === "GET" && url === "/api/history") {
      return sendJson(response, listJobs());
    }

    if (method === "GET" && /^\/api\/history\/(.+)$/.test(url)) {
      const target = url.replace("/api/history/", "");
      if (target.includes("/") || target.includes("..") || target.includes("\\")) {
        response.writeHead(400); response.end("invalid target name"); return;
      }
      return sendJson(response, listJobs().filter(j => j.target === target));
    }

    // ── Script runner (Tools section) ─────────────────────────────────────
    if (method === "POST" && url === "/api/script/run") {
      const body   = await readBody(request);
      const { script, target } = body;
      if (!script) return sendJson(response, { error: "script required" });
      const npmArgs = ["run", script];
      const job = createJob({ target: target || "global", script: "npm", args: npmArgs });
      startJob(job);
      return sendJson(response, { job_id: job.id });
    }

    // ── AI chat ─────────────────────────────────────────────────────────────
    if (method === "POST" && url === "/api/chat") {
      const body = await readBody(request);
      const { message, target } = body;
      if (!message) { response.writeHead(400); response.end("message required"); return; }
      if (target && (target.includes("/") || target.includes("..") || target.includes("\\"))) {
        response.writeHead(400); response.end("invalid target name"); return;
      }

      const bundlePath = target ? path.resolve("targets", target, "findings", "confirmed", "report_bundle.json") : null;
      const bundle = bundlePath && fs.existsSync(bundlePath)
        ? JSON.parse(fs.readFileSync(bundlePath, "utf8")) : null;
      const runningJob = target ? listJobs().find(j => j.target === target && j.status === "running") : null;

      const ctx = {
        target:          target || "unknown",
        asset_type:      bundle?.meta?.asset_type || "unknown",
        active_run:      runningJob ? { stage: "running", elapsed: "?" } : null,
        recent_findings: (bundle?.findings || []).slice(-5).map(f => ({ id: f.report_id, title: f.finding_title, severity: f.severity_claimed })),
        recent_logs:     []
      };

      sseStart(response);
      streamChatResponse(message, ctx,
        (text) => sseSend(response, { type: "chunk", text }),
        (err)  => { sseSend(response, { type: err ? "error" : "done", error: err?.message }); response.end(); }
      );
      return;
    }

    if (parsedUrl.pathname === "/" || parsedUrl.pathname === "/index.html") {
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      response.end(fs.readFileSync(appHtmlPath, "utf8"));
      return;
    }

    if (parsedUrl.pathname === "/intel-ui.css") {
      const cssPath = path.resolve("docs", "intel-ui.css");
      response.writeHead(200, { "Content-Type": "text/css; charset=utf-8" });
      response.end(fs.readFileSync(cssPath, "utf8"));
      return;
    }

    if (parsedUrl.pathname === "/api/target") {
      if (!targetContext) { sendJson(response, { config: null, local: null, global: null }); return; }
      const globalDataset = loadDisclosedDataset(args.globalDir);
      sendJson(response, {
        config: targetContext.config,
        local: loadProgramIntel(targetContext.intelligenceDir, targetContext.programHandle),
        global: buildGlobalSummary(globalDataset)
      });
      return;
    }

    if (parsedUrl.pathname === "/api/local") {
      if (!targetContext) { sendJson(response, null); return; }
      sendJson(response, loadProgramIntel(targetContext.intelligenceDir, targetContext.programHandle));
      return;
    }

    if (parsedUrl.pathname === "/api/global") {
      sendJson(response, loadDisclosedDataset(args.globalDir));
      return;
    }

    if (parsedUrl.pathname === "/api/global/query") {
      const globalDataset = loadDisclosedDataset(args.globalDir);
      sendJson(response, queryGlobalDataset(globalDataset, parsedUrl.searchParams));
      return;
    }

    if (serveBrowse(roots, parsedUrl, response)) return;

    sendNotFound(response);
  }

  const server = http.createServer((request, response) => {
    handleRequest(request, response).catch((err) => {
      console.error("[serve-intel-ui] unhandled error:", err);
      if (!response.headersSent) {
        response.writeHead(500);
        response.end("Internal Server Error");
      }
    });
  });

  for (const sig of ["exit", "SIGINT", "SIGTERM"]) {
    process.on(sig, removePidFile);
  }

  listenWithFallback(server, args.port)
    .then((actualPort) => {
      writePidFile(actualPort);
      const url = `http://127.0.0.1:${actualPort}`;
      console.log(`Intel UI available at ${url}`);
      if (actualPort !== args.port) {
        console.log(`- requested port ${args.port} was busy, using ${actualPort} instead`);
      }
      if (args.target) console.log(`- target: ${args.target}`);
      console.log(`- global dir: ${args.globalDir}`);
      if (args.open) {
        openBrowser(url);
        console.log("- browser: opening automatically");
      }
    })
    .catch((error) => {
      console.error(`Failed to start Intel UI: ${error.message}`);
      process.exit(1);
    });
}

main();
