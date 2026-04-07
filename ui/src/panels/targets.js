import { apiFetch } from "../modules/api.js";
import { showAlert } from "../modules/modal.js";

export function initTargets(container) {
  container.innerHTML = `
    <div class="panel-title">Targets</div>

    <div class="card" id="create-target-card">
      <div style="font-weight:600;margin-bottom:14px;">Create New Target</div>
      <div style="display:flex;flex-direction:column;gap:12px;">
        <div>
          <label style="font-size:13px;color:var(--text-dim);display:block;margin-bottom:4px;">Program URL (H1 / bbscope)</label>
          <input type="url" id="ct-url" placeholder="https://hackerone.com/duckduckgo" />
        </div>
        <div>
          <label style="font-size:13px;color:var(--text-dim);display:block;margin-bottom:4px;">Target name</label>
          <input type="text" id="ct-name" placeholder="duckduckgo" />
        </div>
        <div id="ct-progress" style="display:none;font-size:13px;color:var(--text-dim);font-family:var(--font-mono);padding:8px;background:var(--bg-elevated);border-radius:var(--radius);"></div>
        <button class="btn btn-primary" id="ct-submit">Create target</button>
      </div>
    </div>

    <div class="card" id="repo-select-card" style="display:none;">
      <div style="font-weight:600;margin-bottom:6px;">GitHub Repos Found</div>
      <div style="font-size:13px;color:var(--text-dim);margin-bottom:14px;">Select repos to clone for whitebox analysis. AI-ranked by attack surface priority.</div>
      <div id="repo-list"></div>
      <div style="margin-top:14px;display:flex;gap:8px;">
        <button class="btn btn-primary" id="repo-clone-btn">Clone selected</button>
        <button class="btn btn-secondary" id="repo-skip-btn">Skip for now</button>
      </div>
    </div>

    <div class="panel-title" style="margin-top:24px;">Existing Targets</div>
    <div id="target-list-container">Loading&hellip;</div>
  `;

  setupCreateWizard();
  loadTargetList();
}

function setupCreateWizard() {
  const urlInput  = document.getElementById("ct-url");
  const nameInput = document.getElementById("ct-name");

  urlInput.addEventListener("input", () => {
    const val = urlInput.value.trim();
    if (!nameInput.value) {
      const match = val.match(/\/([a-z0-9_-]+)\/?$/i);
      if (match) nameInput.value = match[1].toLowerCase();
    }
  });

  document.getElementById("ct-submit").addEventListener("click", () => submitCreate());
}

async function submitCreate() {
  const url     = document.getElementById("ct-url").value.trim();
  const name    = document.getElementById("ct-name").value.trim();
  const progressEl = document.getElementById("ct-progress");

  if (!name) { await showAlert("Target name is required."); return; }

  progressEl.style.display = "block";
  progressEl.textContent = "Creating target…";

  let createResp;
  try {
    createResp = await apiFetch("/api/targets/create", {
      method: "POST",
      body: { name, program_url: url || undefined }
    });
  } catch (err) {
    progressEl.textContent = "Error: " + err.message;
    return;
  }

  const jobs = [
    { id: createResp.job_id,           label: "Scaffold" },
    { id: createResp.sync_job_id,      label: "Scope sync" },
    { id: createResp.intel_job_id,     label: "Intel sync" },
    { id: createResp.repo_scan_job_id, label: "Repo scan" }
  ].filter((j) => j.id);

  await pollJobs(jobs, progressEl);

  // Show repo selector if repo scan was triggered
  if (createResp.repo_scan_job_id) {
    await showRepoSelector(name);
  }

  progressEl.style.display = "none";
  document.getElementById("ct-name").value = "";
  document.getElementById("ct-url").value  = "";
  loadTargetList();
}

async function pollJobs(jobs, progressEl) {
  let allDone = false;
  while (!allDone) {
    await sleep(1500);
    const statuses = await Promise.all(
      jobs.map((j) => apiFetch(`/api/run/status/${j.id}`).catch(() => ({ status: "error" })))
    );
    const lines = jobs.map((j, i) => {
      const s    = statuses[i]?.status || "?";
      const icon = s === "done" ? "✓" : s === "error" ? "✗" : "⟳";
      return `${icon} ${j.label}`;
    });
    progressEl.textContent = lines.join("  ");
    allDone = statuses.every((s) => ["done", "error"].includes(s?.status));
  }
}

async function showRepoSelector(target) {
  const data  = await apiFetch(`/api/targets/${target}/repos`).catch(() => ({ repos: [] }));
  const repos = data.repos || [];
  if (repos.length === 0) return;

  const card = document.getElementById("repo-select-card");
  const list = document.getElementById("repo-list");
  card.style.display = "block";

  list.innerHTML = repos.map((r, i) => `
    <label style="display:flex;gap:10px;align-items:flex-start;padding:10px;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:8px;cursor:pointer;background:var(--bg-elevated);">
      <input type="checkbox" data-url="${escapeAttr(r.url)}" ${i < 3 ? "checked" : ""} style="margin-top:3px;width:auto;flex-shrink:0;"/>
      <div style="flex:1;min-width:0;">
        <div style="font-weight:600;font-size:14px;">${escapeHtml(r.repo)}</div>
        <div style="font-size:12px;color:var(--text-dim);margin-top:2px;">
          ${escapeHtml(r.language || "?")} &middot; ${r.size_kb}kb &middot; pushed ${new Date(r.pushed_at).toLocaleDateString()}
          ${r.topics.length ? `&middot; ${r.topics.slice(0, 3).map(escapeHtml).join(", ")}` : ""}
        </div>
        ${r.rank_rationale ? `<div style="font-size:12px;color:var(--accent);margin-top:3px;">${escapeHtml(r.rank_rationale)}</div>` : ""}
      </div>
      <a href="${escapeAttr(r.url)}" target="_blank" rel="noopener noreferrer"
         style="color:var(--accent);font-size:12px;flex-shrink:0;padding-top:2px;">&#8599;</a>
    </label>
  `).join("");

  await new Promise((resolve) => {
    document.getElementById("repo-clone-btn").onclick = async () => {
      const checked = [...list.querySelectorAll("input[type=checkbox]:checked")];
      const urls    = checked.map((cb) => cb.dataset.url);
      if (urls.length === 0) { await showAlert("Select at least one repo."); return; }
      try {
        await apiFetch(`/api/targets/${target}/repos/clone`, {
          method: "POST",
          body: { urls }
        });
      } catch { /* clone jobs spawn in background, errors are non-fatal here */ }
      card.style.display = "none";
      resolve();
    };
    document.getElementById("repo-skip-btn").onclick = () => {
      card.style.display = "none";
      resolve();
    };
  });
}

async function loadTargetList() {
  const container = document.getElementById("target-list-container");
  let targets;
  try {
    targets = await apiFetch("/api/targets");
  } catch {
    container.textContent = "Failed to load targets.";
    return;
  }
  if (!targets || targets.length === 0) {
    container.innerHTML = `<div style="color:var(--text-dim);font-size:14px;">No targets yet. Create one above.</div>`;
    return;
  }
  container.innerHTML = targets.map((t) => {
    const name = typeof t === "string" ? t : (t.name || t);
    const progUrl = t.program_url || "";
    return `
      <div class="card" style="display:flex;align-items:center;justify-content:space-between;">
        <div>
          <div style="font-weight:600;">${escapeHtml(name)}</div>
          ${progUrl ? `<div style="font-size:12px;color:var(--text-dim);margin-top:2px;">${escapeHtml(progUrl)}</div>` : ""}
        </div>
        <button class="btn btn-secondary" onclick="abbSelectTarget('${escapeAttr(name)}')">Select</button>
      </div>`;
  }).join("");
}

// ── Utilities ─────────────────────────────────────────────────────────────

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(s) {
  return String(s).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// Exposed for onclick attributes — prefixed to avoid global namespace collision
window.abbSelectTarget = async (name) => {
  localStorage.setItem("abb-active-target", name);
  await showAlert(`Target "${name}" selected. Switch to Run Control to start.`);
};
