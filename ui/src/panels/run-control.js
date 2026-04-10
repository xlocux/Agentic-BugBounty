import { apiFetch, openSSE, ansiToHtml } from "../modules/api.js";
import { showAlert, showConfirm } from "../modules/modal.js";

const STEPS = ["Setup", "Assets", "Explorer", "Researcher", "Review", "Submit"];
const PHASE_INDEX = { setup: 0, assets: 1, explorer: 2, researcher: 3, triage: 4, submit: 5 };
const PHASE_KEY   = ["setup", "assets", "explorer", "researcher", "triage", "submit"];

let activeTarget      = null;
let sessionSSE        = null;
let currentSession    = null;
let currentPhaseIndex = -1;
let activeDetailPhase = null;
const logBuffer       = [];

export function initRunControl(container) {
  container.innerHTML = `
    <div class="panel-title">Run Control</div>

    <!-- Target selector row -->
    <div class="card" style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
      <span style="color:var(--text-dim);font-size:14px;">Target:</span>
      <span id="rc-target-name" style="font-weight:600;color:var(--accent);">&mdash;</span>
      <select id="rc-target-select" style="width:auto;max-width:220px;"></select>
      <span id="rc-src-warning" style="color:var(--warning);font-size:13px;display:none;">&#9888; Source missing — whitebox runs will be skipped</span>
      <div style="margin-left:auto;display:flex;gap:6px;">
        <button class="btn btn-secondary" id="rc-reset-btn" title="Reset findings, logs, intel (keeps src + target.json)" style="padding:3px 12px;font-size:12px;display:none;">&#8635; Reset project</button>
      </div>
    </div>

    <!-- Run configuration + start button -->
    <div class="card" id="rc-start-card">
      <div style="font-weight:600;margin-bottom:14px;">Start New Run</div>
      <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;">

        <div style="flex:1;min-width:150px;">
          <label style="font-size:13px;color:var(--text-dim);display:block;margin-bottom:4px;">CLI</label>
          <select id="rc-cli" style="width:100%;">
            <option value="claude">claude</option>
            <option value="gemini">gemini (free)</option>
            <option value="openrouter">openrouter</option>
            <option value="codex">codex</option>
          </select>
        </div>

        <div style="flex:1;min-width:180px;">
          <label style="font-size:13px;color:var(--text-dim);display:block;margin-bottom:4px;">Model</label>
          <select id="rc-model" style="width:100%;"></select>
        </div>

        <div style="flex:1;min-width:150px;">
          <label style="font-size:13px;color:var(--text-dim);display:block;margin-bottom:4px;">Asset type</label>
          <select id="rc-asset-type" style="width:100%;">
            <option value="webapp">webapp</option>
            <option value="browserext">browserext</option>
            <option value="mobileapp">mobileapp</option>
            <option value="executable">executable</option>
          </select>
        </div>

        <div style="flex:1;min-width:130px;">
          <label style="font-size:13px;color:var(--text-dim);display:block;margin-bottom:4px;">Mode</label>
          <select id="rc-mode" style="width:100%;">
            <option value="blackbox">blackbox</option>
            <option value="whitebox">whitebox</option>
          </select>
        </div>

        <div style="display:flex;flex-direction:column;gap:6px;padding-bottom:2px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <input type="checkbox" id="rc-hitl" style="width:auto;" />
            <label for="rc-hitl" style="font-size:14px;cursor:pointer;">HITL</label>
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            <input type="checkbox" id="rc-resume" style="width:auto;" />
            <label for="rc-resume" style="font-size:14px;cursor:pointer;">Resume</label>
            <span id="rc-resume-hint" style="font-size:11px;color:var(--text-dim);display:none;"></span>
          </div>
        </div>

        <div style="display:flex;gap:8px;padding-bottom:2px;">
          <button class="btn btn-primary" id="rc-start-btn">&#9654; Start run</button>
          <button class="btn btn-danger"  id="rc-stop-btn" style="display:none;">&#9646;&#9646; Stop</button>
        </div>
      </div>

      <div id="rc-gemini-hint" style="margin-top:8px;font-size:12px;color:#e5c07b;display:none;">
        &#9432; Gemini free tier: 15 req/min, 1M tokens/day.
        Set <code style="background:rgba(255,255,255,.08);padding:1px 4px;border-radius:3px;">GEMINI_API_KEY</code>
        in Settings or run <code style="background:rgba(255,255,255,.08);padding:1px 4px;border-radius:3px;">gemini auth login</code>.
      </div>
      <div id="rc-or-hint" style="margin-top:8px;font-size:12px;color:#e5c07b;display:none;">
        &#9432; OpenRouter: set <code style="background:rgba(255,255,255,.08);padding:1px 4px;border-radius:3px;">OPENROUTER_API_KEY</code>
        in Settings. Models marked &#10022; free have no usage cost.
        Agent loop uses tool use (read_file / write_file / bash).
      </div>

      <div id="rc-run-status" style="margin-top:10px;font-size:13px;color:var(--text-dim);display:none;"></div>
    </div>

    <!-- Artifact upload card (shown for binary asset types) -->
    <div class="card" id="rc-upload-card" style="display:none;">
      <div style="font-weight:600;margin-bottom:12px;">Upload Artifact</div>
      <div id="rc-artifact-list" style="margin-bottom:12px;min-height:28px;"></div>
      <div id="rc-drop-zone"
           style="border:2px dashed var(--border);border-radius:8px;padding:24px;text-align:center;
                  cursor:pointer;transition:border-color .2s,background .2s;"
           ondragover="event.preventDefault();this.style.borderColor='var(--accent)';this.style.background='rgba(0,212,170,.07)'"
           ondragleave="this.style.borderColor='var(--border)';this.style.background=''"
           ondrop="window.abbHandleDrop(event)">
        <div style="color:var(--text-dim);font-size:13px;">
          Drop APK / EXE / ZIP here, or
          <label style="color:var(--accent);cursor:pointer;text-decoration:underline;">
            browse
            <input type="file" id="rc-file-input" style="display:none;" />
          </label>
        </div>
        <div id="rc-upload-accept" style="font-size:11px;color:var(--text-dim);margin-top:4px;"></div>
      </div>
      <div id="rc-upload-progress" style="margin-top:10px;font-size:13px;color:var(--text-dim);display:none;"></div>
    </div>

    <!-- Step progress (steps are clickable when data is available) -->
    <div class="card" id="rc-stepper" style="padding-bottom:0;">
      <div id="stepper-steps" style="display:flex;gap:0;"></div>
    </div>

    <!-- Phase detail panel (shown when a step is clicked) -->
    <div class="card" id="rc-phase-detail" style="display:none;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <span style="font-weight:600;font-size:14px;" id="rc-detail-title"></span>
        <button class="btn btn-secondary" id="rc-detail-close" style="padding:3px 10px;font-size:12px;">&#10005; Close</button>
      </div>
      <div id="rc-detail-content" style="font-size:13px;"></div>
    </div>

    <!-- HITL approval panel (appears when pipeline pauses) -->
    <div class="card" id="rc-approval" style="display:none;">
      <div style="font-weight:600;margin-bottom:10px;font-size:15px;" id="rc-approval-title">Awaiting approval</div>
      <div id="rc-plan-list" style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px;"></div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-primary" id="rc-approve-btn">Approve &amp; proceed</button>
        <button class="btn btn-danger"  id="rc-reject-btn">Stop pipeline</button>
      </div>
    </div>

    <!-- Live log feed -->
    <div class="card">
      <div style="font-size:13px;color:var(--text-dim);margin-bottom:8px;">Live log</div>
      <div id="rc-log-lines"
           style="font-family:var(--font-mono);font-size:12px;height:280px;overflow-y:auto;
                  line-height:1.6;padding:4px 0;"></div>
    </div>
  `;

  loadTargetSelector();

  document.getElementById("rc-target-select").addEventListener("change", (e) => {
    setActiveTarget(e.target.value);
  });

  document.getElementById("rc-cli").addEventListener("change", updateModelOptions);
  document.getElementById("rc-start-btn").addEventListener("click", startRun);
  document.getElementById("rc-stop-btn").addEventListener("click",  stopRun);
  updateModelOptions(); // init model list

  document.getElementById("rc-asset-type").addEventListener("change", () => {
    updateUploadCard();
  });
  document.getElementById("rc-file-input").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) uploadArtifact(file);
    e.target.value = ""; // reset so same file can be re-selected
  });
  window.abbHandleDrop = (e) => {
    e.preventDefault();
    document.getElementById("rc-drop-zone").style.borderColor = "var(--border)";
    document.getElementById("rc-drop-zone").style.background  = "";
    const file = e.dataTransfer.files[0];
    if (file) uploadArtifact(file);
  };
  updateUploadCard(); // init

  document.getElementById("rc-reset-btn").addEventListener("click", resetProject);

  document.getElementById("rc-detail-close").addEventListener("click", () => {
    document.getElementById("rc-phase-detail").style.display = "none";
    activeDetailPhase = null;
    updateStepper(PHASE_KEY[currentPhaseIndex] || null); // re-render to clear active-detail highlight
  });

  // Init stepper in idle state
  updateStepper(null);
}

const MODELS = {
  claude: [
    { value: "",                         label: "default (opus-4-6)" },
    { value: "claude-opus-4-6",          label: "claude-opus-4-6" },
    { value: "claude-sonnet-4-6",        label: "claude-sonnet-4-6 (faster)" },
    { value: "claude-haiku-4-5-20251001",label: "claude-haiku-4-5 (cheapest)" },
  ],
  gemini: [
    { value: "gemini-2.0-flash",                  label: "gemini-2.0-flash ✦ free" },
    { value: "gemini-2.5-flash-preview-05-20",    label: "gemini-2.5-flash-preview" },
    { value: "gemini-1.5-flash",                  label: "gemini-1.5-flash ✦ free" },
  ],
  openrouter: [
    // ── Free tier ───────────────────────────────────────────────────────────
    { value: "deepseek/deepseek-r1:free",                  label: "DeepSeek R1 ✦ free" },
    { value: "deepseek/deepseek-chat-v3-0324:free",        label: "DeepSeek V3 ✦ free" },
    { value: "google/gemini-2.0-flash-exp:free",           label: "Gemini 2.0 Flash Exp ✦ free" },
    { value: "meta-llama/llama-3.3-70b-instruct:free",     label: "Llama 3.3 70B ✦ free" },
    { value: "mistralai/mistral-7b-instruct:free",         label: "Mistral 7B ✦ free" },
    { value: "qwen/qwen3-235b-a22b:free",                  label: "Qwen3 235B ✦ free" },
    // ── Paid (cheap) ────────────────────────────────────────────────────────
    { value: "anthropic/claude-3.5-haiku",                 label: "Claude 3.5 Haiku" },
    { value: "anthropic/claude-sonnet-4-5",                label: "Claude Sonnet 4.5" },
    { value: "openai/gpt-4o-mini",                         label: "GPT-4o mini" },
    { value: "openai/gpt-4.1-nano",                        label: "GPT-4.1 nano" },
    { value: "deepseek/deepseek-r1",                       label: "DeepSeek R1 (paid)" },
    { value: "google/gemini-2.5-pro-preview",              label: "Gemini 2.5 Pro" },
  ],
  codex: [
    { value: "", label: "default" },
  ],
};

function updateModelOptions() {
  const cli    = document.getElementById("rc-cli").value;
  const sel    = document.getElementById("rc-model");
  const models = MODELS[cli] || MODELS.claude;
  sel.innerHTML = models.map((m) => `<option value="${m.value}">${m.label}</option>`).join("");
  document.getElementById("rc-gemini-hint").style.display = cli === "gemini"      ? "block" : "none";
  document.getElementById("rc-or-hint").style.display     = cli === "openrouter"  ? "block" : "none";
}

let activeJobId = null;

async function startRun() {
  if (!activeTarget) { await showAlert("Select a target first."); return; }

  const cli       = document.getElementById("rc-cli").value;
  const model     = document.getElementById("rc-model").value;
  const assetType = document.getElementById("rc-asset-type").value;
  const mode      = document.getElementById("rc-mode").value;
  const hitl      = document.getElementById("rc-hitl").checked;
  const resume    = document.getElementById("rc-resume").checked;

  const startBtn  = document.getElementById("rc-start-btn");
  const stopBtn   = document.getElementById("rc-stop-btn");
  const statusEl  = document.getElementById("rc-run-status");

  startBtn.style.display = "none";
  stopBtn.style.display  = "inline-flex";
  statusEl.style.display = "block";
  statusEl.textContent   = "Starting pipeline…";

  try {
    const result = await apiFetch("/api/run/start", {
      method: "POST",
      body: {
        target:    activeTarget,
        cli:       cli    || undefined,
        model:     model  || undefined,
        mode,
        hitl:      hitl   || undefined,
        resume:    resume || undefined,
        skipIntel: true
      }
    });
    activeJobId = result.job_id;
    statusEl.textContent = `Running — job ${activeJobId}`;
    updateStepper("setup");
    subscribeJobLog(activeJobId);
    pollJobCompletion(activeJobId);
  } catch (err) {
    statusEl.textContent = "Start failed: " + err.message;
    startBtn.style.display = "inline-flex";
    stopBtn.style.display  = "none";
  }
}

async function stopRun() {
  if (!activeJobId) return;
  const ok = await showConfirm("Stop the current pipeline run?");
  if (!ok) return;
  await apiFetch(`/api/run/stop/${activeJobId}`, { method: "POST" }).catch(() => {});
  setIdleState("Stopped.");
}

async function pollJobCompletion(jobId) {
  while (true) {
    await new Promise((r) => setTimeout(r, 2000));
    try {
      const status = await apiFetch(`/api/run/status/${jobId}`);
      if (status.status === "done" || status.status === "error") {
        const msg = status.status === "done" ? "Run complete." : "Run ended with errors.";
        setIdleState(msg);
        return;
      }
    } catch { return; }
  }
}

function setIdleState(msg) {
  activeJobId = null;
  const startBtn = document.getElementById("rc-start-btn");
  const stopBtn  = document.getElementById("rc-stop-btn");
  const statusEl = document.getElementById("rc-run-status");
  if (startBtn) startBtn.style.display = "inline-flex";
  if (stopBtn)  stopBtn.style.display  = "none";
  if (statusEl) { statusEl.textContent = msg || ""; }
}

let jobSSE = null;

function subscribeJobLog(jobId) {
  if (jobSSE) { jobSSE.close(); jobSSE = null; }
  jobSSE = openSSE(`/api/stream/${jobId}`, (msg) => {
    if (msg.line) pushLogLine(msg.line); // raw — ansiToHtml handles it
  }, () => {});
}

async function resetProject() {
  if (!activeTarget) return;
  const ok = await showConfirm(
    `Reset "${activeTarget}"?\n\nDeletes:\n  • findings (confirmed + candidates)\n  • logs\n  • intelligence / DB\n  • scan manifest\n\nKeeps:\n  • src/ and src-*/ (source files)\n  • target.json and CLAUDE.md`
  );
  if (!ok) return;

  const btn = document.getElementById("rc-reset-btn");
  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Resetting…";

  try {
    await apiFetch(`/api/targets/${encodeURIComponent(activeTarget)}/reset`, { method: "POST" });
    // Clear stepper + log
    updateStepper(null);
    currentPhaseIndex = -1;
    document.getElementById("rc-log-lines").innerHTML = "";
    logBuffer.length = 0;
    document.getElementById("rc-phase-detail").style.display = "none";
    btn.textContent = "✓ Done";
    setTimeout(() => { btn.textContent = origText; btn.disabled = false; }, 2000);
  } catch (err) {
    btn.textContent = origText;
    btn.disabled = false;
    await showAlert("Reset failed: " + err.message);
  }
}

// ── Upload helpers ─────────────────────────────────────────────────────────────

const UPLOAD_ASSET_TYPES = new Set(["mobileapp", "executable", "browserext"]);
const UPLOAD_ACCEPT = {
  mobileapp:  ".apk,.apkx,.ipa,.zip",
  executable: ".exe,.elf,.bin,.out,.zip",
  browserext: ".zip,.crx,.xpi",
};

function updateUploadCard() {
  const assetType = document.getElementById("rc-asset-type").value;
  const card      = document.getElementById("rc-upload-card");
  if (!UPLOAD_ASSET_TYPES.has(assetType)) { card.style.display = "none"; return; }
  card.style.display = "block";
  const acceptEl = document.getElementById("rc-upload-accept");
  acceptEl.textContent = `Accepted: ${UPLOAD_ACCEPT[assetType] || "*"}`;
  document.getElementById("rc-file-input").accept = UPLOAD_ACCEPT[assetType] || "";
  if (activeTarget) refreshArtifactList(activeTarget, assetType);
}

async function refreshArtifactList(target, assetType) {
  const listEl = document.getElementById("rc-artifact-list");
  if (!listEl) return;
  try {
    const all = await apiFetch(`/api/targets/${target}/artifacts`);
    const relevant = (all || []).filter((a) => !assetType || a.assetType === assetType);
    if (relevant.length === 0) {
      listEl.innerHTML = `<span style="font-size:12px;color:var(--text-dim);">No artifacts uploaded yet.</span>`;
      return;
    }
    listEl.innerHTML = "";
    for (const a of relevant) {
      const row = document.createElement("div");
      row.style.cssText = "display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border-subtle);";
      row.innerHTML = `
        <span style="font-size:18px;">${a.assetType === "mobileapp" ? "📱" : a.assetType === "executable" ? "⚙️" : "🧩"}</span>
        <div style="flex:1;min-width:0;">
          <div style="font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(a.filename)}</div>
          <div style="font-size:11px;color:var(--text-dim);">${esc(a.dir)} · ${(a.bytes / 1024 / 1024).toFixed(1)} MB</div>
        </div>
        <span style="font-size:11px;color:var(--success);font-weight:600;">✓ ready</span>
        <button class="btn btn-danger" style="padding:2px 8px;font-size:11px;" title="Delete artifact">&#128465;</button>
      `;
      row.querySelector("button").addEventListener("click", async () => {
        const ok = await showConfirm(`Delete "${a.filename}"?`);
        if (!ok) return;
        try {
          await apiFetch(
            `/api/targets/${encodeURIComponent(target)}/artifacts/${encodeURIComponent(a.filename)}?assetType=${a.assetType}`,
            { method: "DELETE" }
          );
          row.remove();
          if (listEl.children.length === 0) {
            listEl.innerHTML = `<span style="font-size:12px;color:var(--text-dim);">No artifacts uploaded yet.</span>`;
          }
        } catch (err) {
          alert("Delete failed: " + err.message);
        }
      });
      listEl.appendChild(row);
    }
  } catch {
    listEl.innerHTML = "";
  }
}

async function uploadArtifact(file) {
  if (!activeTarget) { await showAlert("Select a target first."); return; }
  const assetType = document.getElementById("rc-asset-type").value;
  if (!UPLOAD_ASSET_TYPES.has(assetType)) return;

  const progressEl = document.getElementById("rc-upload-progress");
  progressEl.style.display = "block";
  progressEl.textContent   = `Uploading ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)…`;

  try {
    const url = `/api/targets/${activeTarget}/upload?assetType=${assetType}&filename=${encodeURIComponent(file.name)}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    progressEl.textContent = `✓ ${data.filename} uploaded (${(data.bytes / 1024 / 1024).toFixed(1)} MB) → ${data.dest}`;
    setTimeout(() => { progressEl.style.display = "none"; }, 4000);
    refreshArtifactList(activeTarget, assetType);
  } catch (err) {
    progressEl.textContent = "Upload failed: " + err.message;
  }
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
  const resetBtn = document.getElementById("rc-reset-btn");
  if (resetBtn) resetBtn.style.display = name ? "inline-flex" : "none";
  if (!name) return;
  localStorage.setItem("abb-active-target", name);
  checkSourceMissing(name);
  checkCheckpoint(name);
  subscribeSessionStream(name);
  const assetType = document.getElementById("rc-asset-type")?.value;
  if (assetType && UPLOAD_ASSET_TYPES.has(assetType)) refreshArtifactList(name, assetType);
}

async function checkCheckpoint(name) {
  const resumeBox  = document.getElementById("rc-resume");
  const resumeHint = document.getElementById("rc-resume-hint");
  try {
    const cp = await apiFetch(`/api/run/checkpoint/${name}`);
    if (cp.exists) {
      resumeBox.checked        = true;
      resumeHint.style.display = "inline";
      resumeHint.textContent   = `saved: ${cp.phase}${cp.asset ? " / " + cp.asset : ""}`;
    } else {
      resumeBox.checked        = false;
      resumeHint.style.display = "none";
    }
  } catch {
    resumeBox.checked        = false;
    resumeHint.style.display = "none";
  }
}

async function checkSourceMissing(name) {
  const warning = document.getElementById("rc-src-warning");
  try {
    const intel    = await apiFetch(`/api/intelligence/${name}`);
    const cfg      = intel?.config || {};
    const hasWhitebox = cfg.default_mode === "whitebox" || (cfg.allowed_modes || []).includes("whitebox");
    const repoData = await apiFetch(`/api/targets/${name}/repos`).catch(() => ({ repos: [] }));
    const hasSrc   = (repoData.repos && repoData.repos.length > 0);
    warning.style.display = (hasWhitebox && !hasSrc) ? "inline" : "none";
  } catch {
    warning.style.display = "none";
  }
}

function subscribeSessionStream(target) {
  apiFetch(`/api/session/${target}`).then(handleSessionUpdate).catch(() => {});
  sessionSSE = openSSE(
    `/api/session/${target}/stream`,
    (msg) => { if (msg.type === "session_update") handleSessionUpdate(msg.data); },
    () => {}
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
  currentPhaseIndex = phase === null  ? -1
                    : phase === "done" ? STEPS.length   // 6 — all steps done
                    : (PHASE_INDEX[phase] ?? 0);
  document.getElementById("stepper-steps").innerHTML = STEPS.map((label, i) => {
    const state = currentPhaseIndex < 0
      ? "pending"
      : i < currentPhaseIndex ? "done" : i === currentPhaseIndex ? "active" : "pending";
    const isDetail  = activeDetailPhase === PHASE_KEY[i];
    const clickable = state === "done" || state === "active";
    const color = state === "done"   ? "var(--success)"
                : state === "active" ? "var(--accent)"
                : "var(--text-dim)";
    const border = isDetail
      ? `border-bottom: 2px solid var(--accent); background:rgba(var(--accent-rgb,99,179,237),0.08);`
      : state === "active"
        ? `border-bottom: 2px solid ${color};`
        : `border-bottom: 1px solid var(--border);`;
    return `<div
      style="flex:1;text-align:center;padding:10px 4px;${border}font-size:13px;color:${color};
             ${clickable ? "cursor:pointer;user-select:none;" : ""}"
      ${clickable ? `onclick="abbShowPhaseDetail('${PHASE_KEY[i]}')"` : ""}
      title="${clickable ? "Click to inspect " + label : label}">
      ${state === "done" ? "&#10003; " : ""}${label}
    </div>`;
  }).join("");
}

// ── Phase detail panel ──────────────────────────────────────────────────────

window.abbShowPhaseDetail = async function(phase) {
  // Toggle off if already open
  if (activeDetailPhase === phase) {
    activeDetailPhase = null;
    document.getElementById("rc-phase-detail").style.display = "none";
    updateStepper(PHASE_KEY[currentPhaseIndex] || null);
    return;
  }
  activeDetailPhase = phase;
  updateStepper(PHASE_KEY[currentPhaseIndex] || null); // re-render to show highlight

  const detail  = document.getElementById("rc-phase-detail");
  const title   = document.getElementById("rc-detail-title");
  const content = document.getElementById("rc-detail-content");
  detail.style.display = "block";
  title.textContent    = STEPS[PHASE_INDEX[phase]] || phase;
  content.innerHTML    = `<div style="color:var(--text-dim);">Loading…</div>`;

  try {
    content.innerHTML = await renderPhase(phase);
  } catch (err) {
    content.innerHTML = `<span style="color:var(--danger);">Failed to load: ${esc(err.message)}</span>`;
  }
};

async function renderPhase(phase) {
  if (!activeTarget) return `<span style="color:var(--text-dim);">No target selected.</span>`;

  // ── Setup ──────────────────────────────────────────────────────────────
  if (phase === "setup") {
    const d   = await apiFetch(`/api/intelligence/${activeTarget}`);
    const cfg = d?.config || {};
    return infoGrid([
      ["Target",     cfg.target_name || activeTarget],
      ["Asset type", cfg.asset_type  || "—"],
      ["Mode",       cfg.default_mode || "—"],
      ["Program URL", cfg.program_url
        ? `<a href="${esc(cfg.program_url)}" target="_blank" style="color:var(--accent);">${esc(cfg.program_url)}</a>`
        : "—", true],
      ["H1 handle",  cfg.hackerone?.program_handle || "—"],
    ]);
  }

  // ── Assets ─────────────────────────────────────────────────────────────
  if (phase === "assets") {
    const d      = await apiFetch(`/api/intelligence/${activeTarget}`);
    const scopes = d?.local?.scopeSnapshot?.scopes || [];
    if (!scopes.length) return `<span style="color:var(--text-dim);">No scope data yet.</span>`;
    return renderScopeTable(scopes);
  }

  // ── Explorer: tech stack + attack surface + disclosed vulns ────────────
  if (phase === "explorer") {
    const [intel, recon] = await Promise.all([
      apiFetch(`/api/intelligence/${activeTarget}`),
      apiFetch(`/api/targets/${activeTarget}/recon`).catch(() => ({})),
    ]);

    const scopes     = intel?.local?.scopeSnapshot?.scopes || [];
    const langStats  = recon.lang_stats || {};
    const relStats   = recon.relevance_stats || {};
    const brief      = recon.research_brief;
    const as         = recon.attack_surface;

    // Tech stack bar chart
    const LANG_COLOR = {
      javascript:"#e5c07b", typescript:"#61afef", python:"#98c379",
      html:"#e06c75", css:"#56b6c2", json:"#c678dd", ruby:"#ff6b6b",
      java:"#e5c07b", kotlin:"#98c379", swift:"#e06c75", go:"#56b6c2",
      rust:"#e5c07b", cpp:"#c678dd", c:"#abb2bf", xml:"#88dde8", other:"#5c6370",
    };
    const sortedLangs = Object.entries(langStats).sort((a,b) => b[1]-a[1]);
    const maxCount    = sortedLangs[0]?.[1] || 1;
    const totalFiles  = recon.total_files || 0;

    let techHtml = "";
    if (sortedLangs.length) {
      const bars = sortedLangs.slice(0, 12).map(([lang, count]) => {
        const pct   = Math.max(2, Math.round(count / maxCount * 100));
        const color = LANG_COLOR[lang] || "#abb2bf";
        const pcOfTotal = totalFiles ? Math.round(count/totalFiles*100) : 0;
        return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
          <div style="width:80px;font-size:12px;color:var(--text-dim);text-align:right;flex-shrink:0;">${esc(lang)}</div>
          <div style="flex:1;background:var(--border);border-radius:3px;height:13px;">
            <div style="width:${pct}%;background:${color};height:13px;border-radius:3px;transition:width .3s;"></div>
          </div>
          <div style="width:50px;font-size:11px;color:var(--text-dim);">${count} <span style="opacity:.6;">(${pcOfTotal}%)</span></div>
        </div>`;
      }).join("");
      techHtml = `
        <div style="margin-bottom:20px;">
          <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:.06em;margin-bottom:10px;">
            TECH STACK &mdash; ${totalFiles} files scanned
          </div>
          ${bars}
        </div>`;
    }

    // Attack surface summary (populated after whitebox run)
    let asHtml = "";
    if (as) {
      const asSections = Object.entries(as)
        .filter(([k, v]) => Array.isArray(v) && v.length > 0
          && !["schema_version","generated_at","target"].includes(k));
      if (asSections.length) {
        const chips = asSections.map(([k, v]) =>
          `<span style="display:inline-flex;align-items:center;gap:5px;
            background:rgba(86,182,194,0.15);border:1px solid rgba(86,182,194,0.3);
            border-radius:4px;padding:3px 8px;font-size:12px;margin:3px;">
            <span style="font-weight:600;color:#56b6c2;">${v.length}</span>
            <span style="color:var(--text-dim);">${esc(k.replace(/_/g," "))}</span>
          </span>`
        ).join("");
        asHtml = `
          <div style="margin-bottom:20px;">
            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:.06em;margin-bottom:8px;">ATTACK SURFACE</div>
            <div style="display:flex;flex-wrap:wrap;">${chips}</div>
          </div>`;
      }
    }

    // Disclosed vulnerabilities (from H1 history)
    let disclosedHtml = "";
    const weaknesses = brief?.same_program_disclosed_top_weaknesses || [];
    if (weaknesses.length) {
      const SEV_COLOR_W = ["#e06c75","#e5c07b","#56b6c2","#98c379","#abb2bf"];
      const maxWCount = weaknesses[0]?.count || 1;
      const wBars = weaknesses.map(({ label, count }, i) => {
        const pct   = Math.max(2, Math.round(count / maxWCount * 100));
        const color = SEV_COLOR_W[i % SEV_COLOR_W.length];
        return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
          <div style="width:240px;font-size:12px;color:var(--text-dim);text-align:right;flex-shrink:0;">${esc(label)}</div>
          <div style="flex:1;background:var(--border);border-radius:3px;height:12px;">
            <div style="width:${pct}%;background:${color};height:12px;border-radius:3px;"></div>
          </div>
          <div style="width:24px;font-size:11px;color:var(--text-dim);">${count}</div>
        </div>`;
      }).join("");
      disclosedHtml = `
        <div style="margin-bottom:20px;">
          <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:.06em;margin-bottom:10px;">
            DISCLOSED VULNERABILITIES (same program, H1 history)
          </div>
          ${wBars}
        </div>`;
    }

    // Scope table
    const scopeHtml = scopes.length
      ? `<div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:.06em;margin-bottom:8px;">IN-SCOPE ASSETS</div>` + renderScopeTable(scopes)
      : "";

    return (techHtml || asHtml || disclosedHtml || scopeHtml)
      ? techHtml + asHtml + disclosedHtml + scopeHtml
      : `<span style="color:var(--text-dim);">Explorer data not yet available — run the pipeline first.</span>`;
  }

  // ── Researcher / Review: confirmed findings + input→sink flow ──────────
  if (phase === "researcher" || phase === "triage") {
    const [bundle, cData] = await Promise.all([
      apiFetch(`/api/targets/${activeTarget}/findings`).catch(() => ({ findings: [] })),
      apiFetch(`/api/targets/${activeTarget}/candidates`).catch(() => ({ candidates: [] })),
    ]);

    const findings   = bundle?.findings   || [];
    const candidates = cData?.candidates  || [];
    const withFlow   = candidates.filter((c) => c.source && c.sink);

    const SEV_COLOR = {
      critical:"#e06c75", high:"#e5c07b", medium:"#56b6c2", low:"#98c379", info:"#abb2bf",
    };

    // Confirmed findings summary
    let findingsHtml = "";
    if (findings.length) {
      const bySev = findings.reduce((acc, f) => {
        const s = (f.severity || "info").toLowerCase(); acc[s] = (acc[s]||0)+1; return acc;
      }, {});
      const summary = ["critical","high","medium","low","info"]
        .filter((s) => bySev[s])
        .map((s) => `<span style="color:${SEV_COLOR[s]};font-weight:600;">${bySev[s]} ${s}</span>`)
        .join(" &bull; ");
      const rows = findings.map((f) => {
        const sev   = (f.severity || "info").toLowerCase();
        const color = SEV_COLOR[sev] || "inherit";
        return `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:5px 8px 5px 0;font-family:var(--font-mono);font-size:11px;white-space:nowrap;">${esc(f.id||"—")}</td>
          <td style="padding:5px 8px;">${esc(f.title||"—")}</td>
          <td style="padding:5px 8px;color:${color};font-weight:600;white-space:nowrap;">${esc(sev)}</td>
          <td style="padding:5px 0;color:var(--text-dim);font-size:11px;">${esc(f.status||"—")}</td>
        </tr>`;
      }).join("");
      findingsHtml = `
        <div style="margin-bottom:20px;">
          <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:.06em;margin-bottom:8px;">
            CONFIRMED FINDINGS &mdash; ${summary}
          </div>
          <table style="width:100%;border-collapse:collapse;font-size:12px;">
            <thead><tr style="color:var(--text-dim);border-bottom:1px solid var(--border);">
              <th style="text-align:left;padding:4px 8px 4px 0;">ID</th>
              <th style="text-align:left;padding:4px 8px;">Title</th>
              <th style="text-align:left;padding:4px 8px;">Severity</th>
              <th style="text-align:left;padding:4px 0;">Status</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`;
    }

    // Input → Sink data flow cards
    let flowHtml = "";
    if (withFlow.length) {
      const cards = withFlow.slice(0, 25).map((c) => {
        const sev      = (c.severity || "info").toLowerCase();
        const sevColor = SEV_COLOR[sev] || "#abb2bf";
        const entry    = c.source?.entry_point || c.source?.file || "?";
        const sinkFn   = c.sink?.function || c.sink?.file || "?";
        const srcLoc   = c.source?.file ? `<div style="font-size:10px;color:var(--text-dim);margin-top:2px;">${esc(c.source.file)}${c.source.line ? ":"+c.source.line : ""}</div>` : "";
        const sinkLoc  = c.sink?.file   ? `<div style="font-size:10px;color:var(--text-dim);margin-top:2px;">${esc(c.sink.file)}${c.sink.line ? ":"+c.sink.line : ""}</div>` : "";
        const path     = (c.reachability_path || []).map((step, i) =>
          `<div style="font-size:11px;color:var(--text-dim);padding:2px 0 2px 10px;
             border-left:2px solid var(--border);margin-left:6px;
             ${i === 0 ? "margin-top:4px;" : ""}">${esc(step)}</div>`
        ).join("");
        return `
          <div style="margin-bottom:10px;padding:10px;background:rgba(255,255,255,0.02);
                      border:1px solid var(--border);border-radius:6px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
              <span style="color:${sevColor};font-size:11px;font-weight:700;text-transform:uppercase;
                           background:${sevColor}22;border-radius:3px;padding:1px 6px;">${esc(sev)}</span>
              <span style="font-size:12px;flex:1;min-width:0;">${esc(c.title||"—")}</span>
              <span style="font-size:11px;color:var(--text-dim);white-space:nowrap;">${esc(c.agent||"")} agent</span>
            </div>
            <div style="display:flex;align-items:stretch;gap:0;">
              <div style="flex:1;background:rgba(97,175,239,0.08);border:1px solid rgba(97,175,239,0.25);
                          border-radius:4px 0 0 4px;padding:7px 10px;">
                <div style="font-size:10px;color:#61afef;letter-spacing:.06em;margin-bottom:3px;">ENTRY POINT</div>
                <div style="font-family:var(--font-mono);font-size:11px;color:#84c3ff;word-break:break-all;">${esc(entry)}</div>
                ${srcLoc}
              </div>
              <div style="display:flex;align-items:center;padding:0 10px;font-size:20px;
                          color:var(--text-dim);background:rgba(255,255,255,0.02);flex-shrink:0;">&#8594;</div>
              <div style="flex:1;background:rgba(224,108,117,0.08);border:1px solid rgba(224,108,117,0.25);
                          border-radius:0 4px 4px 0;padding:7px 10px;">
                <div style="font-size:10px;color:#e06c75;letter-spacing:.06em;margin-bottom:3px;">SINK</div>
                <div style="font-family:var(--font-mono);font-size:11px;color:#ff7b7b;word-break:break-all;">${esc(sinkFn)}</div>
                ${sinkLoc}
              </div>
            </div>
            ${path}
          </div>`;
      }).join("");
      flowHtml = `
        <div>
          <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:.06em;margin-bottom:10px;">
            INPUT &#8594; SINK PATHS &mdash; ${withFlow.length} candidate(s)
          </div>
          ${cards}
          ${withFlow.length > 25 ? `<div style="color:var(--text-dim);font-size:12px;padding:8px 0;">… and ${withFlow.length-25} more</div>` : ""}
        </div>`;
    }

    if (!findingsHtml && !flowHtml) {
      return `<span style="color:var(--text-dim);">No findings or candidates yet.</span>`;
    }
    return findingsHtml + flowHtml;
  }

  // ── Submit ─────────────────────────────────────────────────────────────
  if (phase === "submit") {
    const bundle = await apiFetch(`/api/targets/${activeTarget}/findings`).catch(() => ({ findings: [] }));
    const ready  = (bundle?.findings || []).filter((f) => f.status === "confirmed" || f.status === "ready");
    if (!ready.length) return `<span style="color:var(--text-dim);">No submission-ready reports yet.</span>`;
    const SEV_COLOR = { critical:"#e06c75", high:"#e5c07b", medium:"#56b6c2", low:"#98c379", info:"#abb2bf" };
    const list = ready.map((f) => {
      const sev   = (f.severity||"info").toLowerCase();
      return `<div style="padding:8px 0;border-bottom:1px solid var(--border);display:flex;gap:12px;align-items:center;">
        <span style="font-family:var(--font-mono);font-size:11px;color:${SEV_COLOR[sev]||"inherit"};
                     min-width:60px;">${esc(f.id||"—")}</span>
        <span style="flex:1;font-size:13px;">${esc(f.title||"—")}</span>
        <span style="font-size:11px;color:${SEV_COLOR[sev]||"inherit"};font-weight:600;">${esc(sev)}</span>
      </div>`;
    }).join("");
    return `<div>${list}</div>
      <div style="margin-top:10px;color:var(--text-dim);font-size:12px;">${ready.length} report(s) ready for submission</div>`;
  }

  return `<span style="color:var(--text-dim);">No detail available for this phase.</span>`;
}

function renderScopeTable(scopes) {
  const STYPE_COLOR = { WILDCARD:"badge-blue", URL:"badge-green",
    GOOGLE_PLAY_APP_ID:"badge-blue", APPLE_STORE_APP_ID:"badge-blue", SOURCE_CODE:"badge-blue" };
  const rows = scopes.map((s) => {
    const badge    = STYPE_COLOR[s.asset_type] || "";
    const sev      = s.max_severity || "—";
    const sevColor = sev === "critical" ? "color:#e06c75;" : sev === "high" ? "color:#e5c07b;" : "";
    return `<tr style="border-bottom:1px solid var(--border);">
      <td style="padding:5px 8px 5px 0;"><span class="badge ${badge}" style="font-size:11px;">${esc(s.asset_type)}</span></td>
      <td style="padding:5px 8px;font-family:var(--font-mono);font-size:11px;word-break:break-all;">${esc(s.asset_identifier)}</td>
      <td style="padding:5px 8px;${sevColor}white-space:nowrap;">${esc(sev)}</td>
      <td style="padding:5px 0;">${s.eligible_for_submission ? "&#10003;" : "&#10007;"}</td>
    </tr>`;
  }).join("");
  return `
    <div style="overflow-x:auto;">
      <table style="width:100%;border-collapse:collapse;font-size:12px;">
        <thead><tr style="color:var(--text-dim);border-bottom:1px solid var(--border);">
          <th style="text-align:left;padding:4px 8px 4px 0;">Type</th>
          <th style="text-align:left;padding:4px 8px;">Identifier</th>
          <th style="text-align:left;padding:4px 8px;">Max severity</th>
          <th style="text-align:left;padding:4px 0;">Eligible</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div style="margin-top:6px;color:var(--text-dim);font-size:12px;">${scopes.length} asset(s) in scope</div>`;
}

function infoGrid(rows) {
  return `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px 24px;">` +
    rows.map(([label, value, raw]) => `
      <div>
        <div style="font-size:11px;color:var(--text-dim);margin-bottom:2px;">${esc(label)}</div>
        <div style="font-weight:500;">${raw ? value : esc(String(value))}</div>
      </div>`).join("") +
  `</div>`;
}

// ── Approval panel ──────────────────────────────────────────────────────────

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
  const checked     = [...document.querySelectorAll("#rc-plan-list input[type=checkbox]:checked")];
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

// ── Live log ────────────────────────────────────────────────────────────────

/** Called by metrics.js — accepts raw ANSI lines, renders with color. */
export function pushLogLine(line) {
  const el = document.getElementById("rc-log-lines");
  if (!el) return;
  logBuffer.push(line);
  if (logBuffer.length > 30) logBuffer.shift();
  el.innerHTML = logBuffer.map((l) => `<div style="white-space:pre-wrap;">${ansiToHtml(l)}</div>`).join("");
  el.scrollTop = el.scrollHeight;
}

// ── Utilities ───────────────────────────────────────────────────────────────

function esc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
