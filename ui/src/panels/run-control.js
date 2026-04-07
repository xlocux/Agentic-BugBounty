import { apiFetch, openSSE } from "../modules/api.js";
import { showAlert, showConfirm } from "../modules/modal.js";

const STEPS = ["Setup", "Assets", "Explorer", "Researcher", "Review", "Submit"];
const PHASE_INDEX = { setup: 0, assets: 1, explorer: 2, researcher: 3, triage: 4, submit: 5 };

let activeTarget   = null;
let sessionSSE     = null;
let currentSession = null;
const logBuffer    = [];

export function initRunControl(container) {
  container.innerHTML = `
    <div class="panel-title">Run Control</div>

    <div class="card" style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
      <span style="color:var(--text-dim);font-size:14px;">Target:</span>
      <span id="rc-target-name" style="font-weight:600;color:var(--accent);">&mdash;</span>
      <select id="rc-target-select" style="width:auto;max-width:220px;"></select>
      <span id="rc-src-warning" style="color:var(--warning);font-size:13px;display:none;">&#9888; Source missing — whitebox runs will be skipped</span>
    </div>

    <div class="card" id="rc-stepper">
      <div id="stepper-steps" style="display:flex;gap:0;"></div>
    </div>

    <div class="card" id="rc-approval" style="display:none;">
      <div style="font-weight:600;margin-bottom:10px;font-size:15px;" id="rc-approval-title">Awaiting approval</div>
      <div id="rc-plan-list" style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px;"></div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-primary" id="rc-approve-btn">Approve &amp; proceed</button>
        <button class="btn btn-danger"  id="rc-reject-btn">Stop pipeline</button>
      </div>
    </div>

    <div class="card">
      <div style="font-size:13px;color:var(--text-dim);margin-bottom:8px;">Live log (last 5 lines)</div>
      <div id="rc-log-lines" style="font-family:var(--font-mono);font-size:12px;color:var(--text-dim);min-height:80px;"></div>
    </div>
  `;

  loadTargetSelector();

  document.getElementById("rc-target-select").addEventListener("change", (e) => {
    setActiveTarget(e.target.value);
  });
}

async function loadTargetSelector() {
  const sel = document.getElementById("rc-target-select");
  let targets;
  try { targets = await apiFetch("/api/targets"); } catch { return; }
  sel.innerHTML = '<option value="">Select target</option>' +
    (targets || []).map((t) => {
      const name = typeof t === "string" ? t : (t.name || t);
      return `<option value="${name}">${name}</option>`;
    }).join("");

  const saved = localStorage.getItem("abb-active-target");
  if (saved) {
    sel.value = saved;
    setActiveTarget(saved);
  }
}

async function setActiveTarget(name) {
  if (sessionSSE) { sessionSSE.close(); sessionSSE = null; }
  activeTarget = name;
  document.getElementById("rc-target-name").textContent = name || "—";
  if (!name) return;
  localStorage.setItem("abb-active-target", name);
  checkSourceMissing(name);
  subscribeSessionStream(name);
}

async function checkSourceMissing(name) {
  const warning = document.getElementById("rc-src-warning");
  try {
    const intel  = await apiFetch(`/api/intelligence/${name}`);
    const assets = intel?.target_config?.assets || [];
    const hasWhitebox = assets.some((a) => a.mode === "whitebox");
    const hasRepos    = (intel?.target_config?.github_repos || []).length > 0;
    // Also check if src/ directory has content by looking at repos data
    const repoData    = await apiFetch(`/api/targets/${name}/repos`).catch(() => ({ repos: [] }));
    const hasSrc      = hasRepos || (repoData.repos && repoData.repos.length > 0);
    warning.style.display = (hasWhitebox && !hasSrc) ? "inline" : "none";
  } catch {
    warning.style.display = "none";
  }
}

function subscribeSessionStream(target) {
  // Load current state immediately
  apiFetch(`/api/session/${target}`).then(handleSessionUpdate).catch(() => {});

  sessionSSE = openSSE(
    `/api/session/${target}/stream`,
    (msg) => { if (msg.type === "session_update") handleSessionUpdate(msg.data); },
    () => {} // ignore SSE errors silently
  );
}

function handleSessionUpdate(session) {
  currentSession = session;
  if (!session) return;
  updateStepper(session.phase);
  const needsApproval = session.status === "awaiting_approval" || session.status === "awaiting_assets";
  document.getElementById("rc-approval").style.display = needsApproval ? "block" : "none";
  if (needsApproval) showApprovalPanel(session);
}

function updateStepper(phase) {
  const current = PHASE_INDEX[phase] ?? 0;
  document.getElementById("stepper-steps").innerHTML = STEPS.map((label, i) => {
    const state  = i < current ? "done" : i === current ? "active" : "pending";
    const color  = state === "done"   ? "var(--success)"
                 : state === "active" ? "var(--accent)"
                 : "var(--text-dim)";
    const border = state === "active"
      ? `border-bottom: 2px solid ${color};`
      : `border-bottom: 1px solid var(--border);`;
    return `<div style="flex:1;text-align:center;padding:10px 4px;${border}font-size:13px;color:${color};">
      ${state === "done" ? "&#10003; " : ""}${label}
    </div>`;
  }).join("");
}

function showApprovalPanel(session) {
  document.getElementById("rc-approval-title").textContent =
    session.status === "awaiting_assets"
      ? "Select assets to analyze"
      : `Approve research plan${session.asset_type ? " — " + session.asset_type : ""}`;

  const items = session.plan || session.available_assets || [];
  document.getElementById("rc-plan-list").innerHTML = items.map((item) => `
    <label style="display:flex;align-items:flex-start;gap:10px;font-size:14px;cursor:${item.mandatory ? "default" : "pointer"};padding:6px 0;">
      <input type="checkbox"
        data-id="${item.id}"
        ${item.mandatory ? "checked disabled" : "checked"}
        style="margin-top:2px;width:auto;"
      />
      <span style="flex:1;">${item.label}</span>
      ${item.mandatory ? '<span class="badge badge-red" style="font-size:11px;white-space:nowrap;">REQUIRED</span>' : ""}
      ${item.reason ? `<span style="color:var(--text-dim);font-size:12px;white-space:nowrap;">${item.reason}</span>` : ""}
    </label>
  `).join("");

  document.getElementById("rc-approve-btn").onclick = () => sendApproval(session);
  document.getElementById("rc-reject-btn").onclick  = () => stopPipeline();
}

async function sendApproval(session) {
  const checked    = [...document.querySelectorAll("#rc-plan-list input[type=checkbox]:checked")];
  const approvedOps = checked.map((cb) => cb.dataset.id);

  const payload = {
    schema_version: "1.0",
    request_id:     session.request_id,
    written_at:     new Date().toISOString(),
    written_by:     "ui",
    status:         session.status === "awaiting_assets" ? "assets_selected" : "approved",
    ...(session.status === "awaiting_assets"
      ? { selected_assets: approvedOps }
      : { approved_ops:    approvedOps })
  };

  try {
    await apiFetch(`/api/session/${activeTarget}/respond`, { method: "POST", body: payload });
    document.getElementById("rc-approval").style.display = "none";
  } catch (err) {
    await showAlert("Failed to send approval: " + err.message);
  }
}

async function stopPipeline() {
  const ok = await showConfirm("Stop the pipeline? The current run will be halted.");
  if (!ok || !currentSession) return;
  const payload = {
    schema_version: "1.0",
    request_id:     currentSession.request_id,
    written_at:     new Date().toISOString(),
    written_by:     "ui",
    status:         "rejected"
  };
  await apiFetch(`/api/session/${activeTarget}/respond`, { method: "POST", body: payload }).catch(() => {});
}

// Called by metrics.js to push a log line into the run control live feed
export function pushLogLine(line) {
  const el = document.getElementById("rc-log-lines");
  if (!el) return;
  logBuffer.push(line);
  if (logBuffer.length > 5) logBuffer.shift();
  el.innerHTML = logBuffer
    .map((l) => `<div>${escapeHtml(l)}</div>`)
    .join("");
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
