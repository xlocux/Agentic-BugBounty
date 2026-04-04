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
const { execSync } = require("node:child_process");
const { createJob, startJob, stopJob, getJob, listJobs, tailJob } = require("./lib/ui-jobs");
const { streamChatResponse } = require("./lib/ui-chat");

function parseArgs(argv) {
  const parsed = {
    port: 31337,
    target: "duckduckgo",
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

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function contentTypeFor(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".json") return "application/json; charset=utf-8";
  if (ext === ".md") return "text/markdown; charset=utf-8";
  if (ext === ".html") return "text/html; charset=utf-8";
  if (ext === ".txt" || ext === ".log") return "text/plain; charset=utf-8";
  return "application/octet-stream";
}

function safeResolveWithinRoot(rootDir, requestedPath) {
  const normalized = String(requestedPath || "")
    .replaceAll("\\", "/")
    .replace(/^\/+/, "");
  const absolute = path.resolve(rootDir, normalized);
  const rootResolved = path.resolve(rootDir);
  const relative = path.relative(rootResolved, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return null;
  }
  return absolute;
}

function renderDirectoryPage(title, rootName, relativePath, entries) {
  const crumbs = relativePath
    .split("/")
    .filter(Boolean)
    .map((segment, index, array) => {
      const href = `/browse/${rootName}/${array.slice(0, index + 1).join("/")}`;
      return `<a href="${href}">${escapeHtml(segment)}</a>`;
    })
    .join(" / ");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --bg: #060816;
      --surface: rgba(12, 18, 38, 0.92);
      --ink: #e8ecff;
      --muted: #8ea0cb;
      --line: rgba(100, 128, 214, 0.26);
      --teal: #39ffd4;
      --cyan: #55c7ff;
      --pink: #ff4fd8;
      --font-body: "IBM Plex Sans", "Segoe UI", sans-serif;
      --font-mono: "JetBrains Mono", Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body {
      font-family: var(--font-body);
      background:
        radial-gradient(circle at top left, rgba(57,255,212,.08), transparent 22%),
        radial-gradient(circle at top right, rgba(255,79,216,.09), transparent 24%),
        linear-gradient(180deg, #050712, #09101f 55%, #050712);
      color: var(--ink);
      margin: 0;
      padding: 24px;
      min-height: 100vh;
    }
    a { color: var(--cyan); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .card {
      background: linear-gradient(180deg, rgba(16,25,51,.94), rgba(10,15,33,.94));
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 18px;
      max-width: 1180px;
      margin: 0 auto;
      box-shadow: 0 0 0 1px rgba(85,199,255,.12), 0 0 24px rgba(85,199,255,.08);
    }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--muted); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; }
    .muted { color: var(--muted); }
    h1 { margin: 0 0 10px; font-size: 22px; letter-spacing: .08em; text-transform: uppercase; }
    .back {
      display: inline-flex;
      padding: 8px 14px;
      border: 1px solid rgba(85,199,255,.25);
      border-radius: 999px;
      background: rgba(85,199,255,.08);
      margin-bottom: 16px;
    }
    .path { font-family: var(--font-mono); font-size: 12px; word-break: break-all; }
  </style>
</head>
<body>
  <div class="card">
    <a class="back" href="/">Back to Intel UI</a>
    <h1>${escapeHtml(title)}</h1>
    <p class="muted path">/${escapeHtml(rootName)}${relativePath ? ` / ${crumbs}` : ""}</p>
    <table>
      <thead><tr><th>Name</th><th>Type</th><th>Open</th></tr></thead>
      <tbody>
        ${relativePath ? `<tr><td>..</td><td>directory</td><td><a href="/browse/${rootName}/${relativePath.split("/").slice(0, -1).join("/")}">Up</a></td></tr>` : ""}
        ${entries.map((entry) => `
          <tr>
            <td>${escapeHtml(entry.name)}</td>
            <td>${entry.isDirectory ? "directory" : "file"}</td>
            <td><a href="${entry.href}">${entry.isDirectory ? "Browse" : "Open"}</a></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  </div>
</body>
</html>`;
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
  const appHtmlPath = path.resolve("docs", "intel-ui.html");
  const targetContext = getTargetContext(args.target);
  const roots = {
    global: args.globalDir,
    target: targetContext.intelligenceDir,
    targets: path.resolve("targets")
  };

  const server = http.createServer(async (request, response) => {
    const parsedUrl = new URL(request.url, `http://${request.headers.host || "127.0.0.1"}`);
    const decodedPathname = (() => {
      try {
        return decodeURIComponent(parsedUrl.pathname);
      } catch {
        return parsedUrl.pathname;
      }
    })();

    const method = request.method;
    const url    = parsedUrl.pathname;

    // ── Targets ────────────────────────────────────────────────────────────
    if (method === "GET" && url === "/api/targets") {
      return sendJson(response, listTargetDirs());
    }

    if (method === "POST" && url === "/api/targets/create") {
      const body = await readBody(request);
      const { name, program_url } = body;
      if (!name) return sendJson(response, { error: "name required" });
      const job = createJob({
        target: name,
        script: "node",
        args: ["scripts/new-target.js", name, "--program-url", program_url || ""]
      });
      startJob(job);
      return sendJson(response, { job_id: job.id });
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

    // ── Findings ───────────────────────────────────────────────────────────
    if (method === "GET" && /^\/api\/findings\/(.+)$/.test(url)) {
      const target = url.replace("/api/findings/", "");
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

    if (parsedUrl.pathname === "/api/target") {
      const globalDataset = loadDisclosedDataset(args.globalDir);
      sendJson(response, {
        config: targetContext.config,
        local: loadProgramIntel(targetContext.intelligenceDir, targetContext.programHandle),
        global: buildGlobalSummary(globalDataset)
      });
      return;
    }

    if (parsedUrl.pathname === "/api/local") {
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

    if (parsedUrl.pathname.startsWith("/browse/")) {
      const suffix = parsedUrl.pathname.slice("/browse/".length);
      const [rootName, ...rest] = suffix.split("/");
      const rootDir = roots[rootName];
      if (!rootDir) {
        sendNotFound(response);
        return;
      }

      const relativePath = rest.join("/");
      const absolutePath = safeResolveWithinRoot(rootDir, relativePath);
      if (!absolutePath || !fs.existsSync(absolutePath)) {
        sendHtml(
          response,
          `<h1>File not found</h1><p>The requested path is not available inside the ${escapeHtml(rootName)} root.</p><p><a href="/browse/${escapeHtml(rootName)}/">Open root</a></p>`,
          404
        );
        return;
      }

      const stat = fs.statSync(absolutePath);
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(absolutePath, { withFileTypes: true })
          .map((entry) => {
            const nextRelative = [relativePath, entry.name].filter(Boolean).join("/");
            return {
              name: entry.name,
              isDirectory: entry.isDirectory(),
              href: entry.isDirectory()
                ? `/browse/${rootName}/${nextRelative}`
                : `/browse/${rootName}/${nextRelative}`
            };
          })
          .sort((left, right) => {
            if (left.isDirectory !== right.isDirectory) {
              return left.isDirectory ? -1 : 1;
            }
            return left.name.localeCompare(right.name);
          });

        sendHtml(response, renderDirectoryPage(`${rootName} files`, rootName, relativePath, entries));
        return;
      }

      response.writeHead(200, { "Content-Type": contentTypeFor(absolutePath) });
      response.end(fs.readFileSync(absolutePath));
      return;
    }

    if (
      parsedUrl.pathname.includes("global-intelligence") ||
      parsedUrl.pathname.includes("%5C") ||
      decodedPathname.includes("\\data") ||
      decodedPathname.includes("global-intelligence")
    ) {
      response.writeHead(302, { Location: "/browse/global/" });
      response.end();
      return;
    }

    sendNotFound(response);
  });

  listenWithFallback(server, args.port)
    .then((actualPort) => {
      const url = `http://127.0.0.1:${actualPort}`;
      console.log(`Intel UI available at ${url}`);
      if (actualPort !== args.port) {
        console.log(`- requested port ${args.port} was busy, using ${actualPort} instead`);
      }
      console.log(`- target: ${args.target}`);
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
