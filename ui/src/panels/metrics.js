import { apiFetch, openSSE, stripAnsi } from "../modules/api.js";
import { pushLogLine } from "./run-control.js";

let logSSE = null;

export function initMetrics(container) {
  container.innerHTML = `
    <div class="panel-title">Metrics</div>

    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <span style="font-weight:600;">Active Jobs</span>
        <button class="btn btn-secondary" id="metrics-refresh" style="padding:4px 10px;font-size:13px;">&#8635; Refresh</button>
      </div>
      <div id="metrics-job-list"></div>
    </div>

    <div class="card">
      <div style="font-size:13px;color:var(--text-dim);margin-bottom:8px;">
        Log output &mdash; <span id="metrics-job-label" style="color:var(--text);">select a job above</span>
      </div>
      <div id="metrics-log"
           style="font-family:var(--font-mono);font-size:12px;height:320px;overflow-y:auto;color:var(--text-dim);line-height:1.5;">
      </div>
    </div>
  `;

  loadJobs();
  document.getElementById("metrics-refresh").addEventListener("click", loadJobs);
}

async function loadJobs() {
  const el = document.getElementById("metrics-job-list");
  let jobs;
  try { jobs = await apiFetch("/api/jobs"); } catch {
    el.textContent = "Failed to load jobs."; return;
  }
  if (!jobs || jobs.length === 0) {
    el.innerHTML = `<div style="color:var(--text-dim);font-size:13px;">No jobs yet.</div>`;
    return;
  }
  const sorted = [...jobs].sort((a, b) =>
    (b.created_at || "").localeCompare(a.created_at || "")
  );
  el.innerHTML = sorted.map((j) => {
    const badgeClass = j.status === "done"    ? "badge-green"
                     : j.status === "error"   ? "badge-red"
                     : j.status === "running" ? "badge-blue"
                     : "";
    const label = escapeHtml(j.label || j.script || "job");
    const target = escapeHtml(j.target || "");
    return `
      <div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--border);">
        <span class="badge ${badgeClass}" style="min-width:68px;text-align:center;">${j.status}</span>
        <span style="font-size:13px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
          ${label}${target ? ` &middot; ${target}` : ""}
        </span>
        <button class="btn btn-secondary"
                style="padding:3px 10px;font-size:12px;flex-shrink:0;"
                onclick="abbTailJob('${j.id}','${escapeAttr(label)}')">Tail</button>
      </div>`;
  }).join("");
}

window.abbTailJob = function(jobId, label) {
  if (logSSE) { logSSE.close(); logSSE = null; }

  document.getElementById("metrics-job-label").textContent = label || jobId;
  const logEl = document.getElementById("metrics-log");
  logEl.innerHTML = "";

  logSSE = openSSE(
    `/api/stream/${jobId}`,
    (msg) => {
      if (msg.line) {
        const clean = stripAnsi(msg.line);
        const line  = document.createElement("div");
        line.textContent = clean;
        logEl.appendChild(line);
        logEl.scrollTop = logEl.scrollHeight;
        pushLogLine(clean);
      }
    },
    () => {} // ignore connection errors
  );
};

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeAttr(s) {
  return String(s).replace(/'/g, "\\'").replace(/"/g, "&quot;");
}
