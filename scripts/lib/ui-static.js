"use strict";
/**
 * ui-static.js — static file serving and browse handler for the Intel UI server.
 *
 * Exports: escapeHtml, contentTypeFor, safeResolveWithinRoot, serveBrowse
 */

const fs   = require("node:fs");
const path = require("node:path");

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
  if (ext === ".md")   return "text/markdown; charset=utf-8";
  if (ext === ".html") return "text/html; charset=utf-8";
  if (ext === ".txt" || ext === ".log") return "text/plain; charset=utf-8";
  return "application/octet-stream";
}

function safeResolveWithinRoot(rootDir, requestedPath) {
  const normalized = String(requestedPath || "")
    .replaceAll("\\", "/")
    .replace(/^\/+/, "");
  const absolute    = path.resolve(rootDir, normalized);
  const rootResolved = path.resolve(rootDir);
  const relative    = path.relative(rootResolved, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return null;
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
      --bg: #060816; --surface: rgba(12,18,38,.92); --ink: #e8ecff;
      --muted: #8ea0cb; --line: rgba(100,128,214,.26);
      --teal: #39ffd4; --cyan: #55c7ff; --pink: #ff4fd8;
      --font-body: "IBM Plex Sans","Segoe UI",sans-serif;
      --font-mono: "JetBrains Mono",Consolas,monospace;
    }
    * { box-sizing: border-box; }
    body {
      font-family: var(--font-body);
      background:
        radial-gradient(circle at top left,  rgba(57,255,212,.08), transparent 22%),
        radial-gradient(circle at top right, rgba(255,79,216,.09), transparent 24%),
        linear-gradient(180deg, #050712, #09101f 55%, #050712);
      color: var(--ink); margin: 0; padding: 24px; min-height: 100vh;
    }
    a { color: var(--cyan); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .card {
      background: linear-gradient(180deg,rgba(16,25,51,.94),rgba(10,15,33,.94));
      border: 1px solid var(--line); border-radius: 20px; padding: 18px;
      max-width: 1180px; margin: 0 auto;
      box-shadow: 0 0 0 1px rgba(85,199,255,.12), 0 0 24px rgba(85,199,255,.08);
    }
    table { width:100%; border-collapse:collapse; margin-top:16px; font-size:13px; }
    th, td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
    th { color:var(--muted); font-size:11px; letter-spacing:.1em; text-transform:uppercase; }
    .muted { color: var(--muted); }
    h1 { margin:0 0 10px; font-size:22px; letter-spacing:.08em; text-transform:uppercase; }
    .back {
      display:inline-flex; padding:8px 14px;
      border:1px solid rgba(85,199,255,.25); border-radius:999px;
      background:rgba(85,199,255,.08); margin-bottom:16px;
    }
    .path { font-family:var(--font-mono); font-size:12px; word-break:break-all; }
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
        ${entries.map(entry => `
          <tr>
            <td>${escapeHtml(entry.name)}</td>
            <td>${entry.isDirectory ? "directory" : "file"}</td>
            <td><a href="${entry.href}">${entry.isDirectory ? "Browse" : "Open"}</a></td>
          </tr>`).join("")}
      </tbody>
    </table>
  </div>
</body>
</html>`;
}

/**
 * Handle GET /browse/<rootName>/<path> requests.
 *
 * @param {Record<string,string>} roots  - map of rootName → absolute directory path
 * @param {URL}                   parsed - already-parsed request URL
 * @param {http.ServerResponse}   res
 * @returns {boolean} true if the request was handled (caller should return)
 */
function serveBrowse(roots, parsed, res) {
  // Redirect legacy paths that referenced global-intelligence directly
  const decoded = (() => { try { return decodeURIComponent(parsed.pathname); } catch { return parsed.pathname; } })();
  if (
    parsed.pathname.includes("global-intelligence") ||
    parsed.pathname.includes("%5C") ||
    decoded.includes("\\data") ||
    decoded.includes("global-intelligence")
  ) {
    res.writeHead(302, { Location: "/browse/global/" });
    res.end();
    return true;
  }

  if (!parsed.pathname.startsWith("/browse/")) return false;

  const suffix   = parsed.pathname.slice("/browse/".length);
  const [rootName, ...rest] = suffix.split("/");
  const rootDir  = roots[rootName];

  if (!rootDir) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Unknown browse root");
    return true;
  }

  const relativePath  = rest.join("/");
  const absolutePath  = safeResolveWithinRoot(rootDir, relativePath);
  if (!absolutePath || !fs.existsSync(absolutePath)) {
    res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<h1>File not found</h1><p>The requested path is not available inside the ${escapeHtml(rootName)} root.</p><p><a href="/browse/${escapeHtml(rootName)}/">Open root</a></p>`);
    return true;
  }

  const stat = fs.statSync(absolutePath);
  if (stat.isDirectory()) {
    const entries = fs.readdirSync(absolutePath, { withFileTypes: true })
      .map(entry => {
        const nextRelative = [relativePath, entry.name].filter(Boolean).join("/");
        return {
          name:        entry.name,
          isDirectory: entry.isDirectory(),
          href:        `/browse/${rootName}/${nextRelative}`
        };
      })
      .sort((a, b) => {
        if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderDirectoryPage(`${rootName} files`, rootName, relativePath, entries));
    return true;
  }

  res.writeHead(200, { "Content-Type": contentTypeFor(absolutePath) });
  res.end(fs.readFileSync(absolutePath));
  return true;
}

module.exports = { escapeHtml, contentTypeFor, safeResolveWithinRoot, serveBrowse };
