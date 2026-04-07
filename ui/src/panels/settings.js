import { apiFetch } from "../modules/api.js";
import { showAlert } from "../modules/modal.js";

export function initSettings(container) {
  container.innerHTML = `
    <div class="panel-title">Settings</div>
    <div class="card">
      <div style="background:var(--bg-elevated);border:1px solid var(--warning);border-radius:var(--radius);padding:10px 14px;margin-bottom:18px;font-size:13px;color:var(--warning);">
        &#9888; Changes apply to the <strong>next run</strong>. Restart the server to apply changes to the UI itself.
      </div>
      <div id="settings-grid"></div>
    </div>
  `;
  loadSettings();
}

async function loadSettings() {
  const grid = document.getElementById("settings-grid");
  let settings;
  try {
    settings = await apiFetch("/api/settings");
  } catch {
    grid.textContent = "Failed to load settings.";
    return;
  }

  grid.innerHTML = Object.entries(settings).map(([key, val]) => `
    <div style="display:grid;grid-template-columns:240px 1fr auto;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);">
      <div>
        <div style="font-size:14px;font-family:var(--font-mono);">${escapeHtml(key)}</div>
        <span class="${val.set ? "badge badge-green" : "badge badge-red"}" style="font-size:11px;margin-top:3px;display:inline-block;">
          ${val.set ? "set" : "not set"}
        </span>
      </div>
      <input
        type="password"
        id="setting-${escapeAttr(key)}"
        value="${escapeAttr(val.masked || "")}"
        placeholder="Enter value&hellip;"
        style="font-family:var(--font-mono);"
        autocomplete="new-password"
      />
      <button class="btn btn-secondary"
              style="padding:6px 14px;font-size:13px;white-space:nowrap;"
              onclick="abbSaveSetting('${escapeAttr(key)}')">Save</button>
    </div>
  `).join("");
}

window.abbSaveSetting = async function(key) {
  const input = document.getElementById(`setting-${key}`);
  if (!input) return;
  const value = input.value.trim();
  if (!value) { await showAlert("Value cannot be empty."); return; }
  try {
    const result = await apiFetch("/api/settings", {
      method: "POST",
      body: { key, value }
    });
    input.value = result.masked || value;
    await showAlert(`${key} saved.`);
    loadSettings();
  } catch (err) {
    await showAlert("Save failed: " + err.message);
  }
};

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeAttr(s) {
  return String(s).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
