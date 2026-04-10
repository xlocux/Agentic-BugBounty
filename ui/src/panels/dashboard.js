import { apiFetch } from "../modules/api.js";
import { showConfirm } from "../modules/modal.js";

const SEV_COLOR = {
  critical: "#e06c75", high: "#e5c07b", medium: "#56b6c2", low: "#98c379", info: "#abb2bf",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

const LANG_COLOR = {
  javascript:"#e5c07b", typescript:"#61afef", python:"#98c379", html:"#e06c75",
  css:"#56b6c2", json:"#c678dd", ruby:"#ff6b6b", java:"#e5c07b", kotlin:"#98c379",
  swift:"#e06c75", go:"#56b6c2", rust:"#e5c07b", cpp:"#c678dd", c:"#abb2bf",
  xml:"#88dde8", other:"#5c6370",
};

// Asset type → pipeline asset key
const SCOPE_TYPE_TO_ASSET = {
  WILDCARD: "webapp", URL: "webapp", CIDR: "webapp",
  GOOGLE_PLAY_APP_ID: "mobileapp", APPLE_STORE_APP_ID: "mobileapp",
  SOURCE_CODE: "webapp", OTHER: "webapp",
};

let selectedTarget = null;

export function initDashboard(container) {
  container.innerHTML = `
    <div class="panel-title">Dashboard</div>
    <div id="dash-body"></div>
  `;
  loadDashboard(container.querySelector("#dash-body"));
}

async function loadDashboard(root) {
  root.innerHTML = `<div style="color:var(--text-dim);font-size:13px;padding:20px 0;">Loading…</div>`;
  try {
    const [targets, dbData] = await Promise.all([
      apiFetch("/api/targets"),
      apiFetch("/api/dashboard").catch(() => ({ summary: [], topVulns: [] })),
    ]);

    // Build per-target summary from DB
    const summaryByTarget = {};
    for (const row of (dbData.summary || [])) {
      if (!summaryByTarget[row.target]) summaryByTarget[row.target] = {};
      if (!summaryByTarget[row.target][row.status]) summaryByTarget[row.target][row.status] = {};
      summaryByTarget[row.target][row.status][row.severity] =
        (summaryByTarget[row.target][row.status][row.severity] || 0) + row.count;
    }

    const targetNames = (targets || []).map((t) => typeof t === "string" ? t : (t.name || t));

    root.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
        <div style="font-size:13px;color:var(--text-dim);">${targetNames.length} target(s)</div>
        <button class="btn btn-secondary" id="dash-sync-btn" style="padding:4px 14px;font-size:12px;">&#8635; Sync DB</button>
        <span id="dash-sync-status" style="font-size:12px;color:var(--text-dim);"></span>
      </div>
      <div id="dash-target-list" style="display:flex;flex-direction:column;gap:10px;"></div>
      <div id="dash-target-detail" style="margin-top:16px;"></div>
    `;

    document.getElementById("dash-sync-btn").addEventListener("click", () => syncDb(root));

    const listEl = document.getElementById("dash-target-list");
    for (const name of targetNames) {
      listEl.appendChild(buildTargetCard(name, summaryByTarget[name] || {}));
    }

    if (!targetNames.length) {
      listEl.innerHTML = `<div style="color:var(--text-dim);font-size:13px;">No targets yet — create one in the Targets panel.</div>`;
    }
  } catch (err) {
    root.innerHTML = `<div style="color:var(--danger);font-size:13px;">Error: ${esc(err.message)}</div>`;
  }
}

function buildTargetCard(name, summary) {
  const confirmed   = Object.values(summary.confirmed   || {}).reduce((a,b) => a+b, 0);
  const unconfirmed = Object.values(summary.unconfirmed || {}).reduce((a,b) => a+b, 0);
  const critical    = (summary.confirmed?.critical || 0) + (summary.unconfirmed?.critical || 0);
  const high        = (summary.confirmed?.high     || 0) + (summary.unconfirmed?.high     || 0);

  const sevDots = SEV_ORDER.map((s) => {
    const n = (summary.confirmed?.[s] || 0) + (summary.unconfirmed?.[s] || 0);
    if (!n) return "";
    return `<span style="color:${SEV_COLOR[s]};font-size:11px;font-weight:600;margin-right:6px;">${n} ${s}</span>`;
  }).join("");

  const div = document.createElement("div");
  div.className = "card";
  div.style.cssText = "cursor:pointer;transition:border-color .15s;margin:0;";
  div.dataset.target = name;
  div.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
      <div style="flex:1;min-width:0;cursor:pointer;" class="dash-card-body">
        <div style="font-size:15px;font-weight:700;color:var(--accent);margin-bottom:3px;">${esc(name)}</div>
        <div style="font-size:12px;color:var(--text-dim);">${sevDots || "<span style='opacity:.5;'>No findings synced — click Sync DB</span>"}</div>
      </div>
      <div style="display:flex;gap:16px;align-items:center;flex-shrink:0;">
        ${confirmed   ? `<div style="text-align:center;"><div style="font-size:18px;font-weight:700;color:#98c379;">${confirmed}</div><div style="font-size:10px;color:var(--text-dim);">confirmed</div></div>` : ""}
        ${unconfirmed ? `<div style="text-align:center;"><div style="font-size:18px;font-weight:700;color:#e5c07b;">${unconfirmed}</div><div style="font-size:10px;color:var(--text-dim);">candidates</div></div>` : ""}
        <span class="dash-card-arrow" style="font-size:18px;color:var(--text-dim);cursor:pointer;">&#8250;</span>
      </div>
      <div style="display:flex;gap:6px;align-items:center;flex-shrink:0;" onclick="event.stopPropagation()">
        <button class="btn btn-secondary dash-reset-btn" title="Reset findings, logs, intel (keeps src + config)"
                style="padding:3px 10px;font-size:11px;">&#8635; Reset</button>
        <button class="btn btn-danger dash-delete-btn" title="Delete entire target workspace"
                style="padding:3px 10px;font-size:11px;">&#128465; Delete</button>
      </div>
    </div>
  `;

  div.querySelector(".dash-card-body").addEventListener("click", toggleDetail);
  div.querySelector(".dash-card-arrow").addEventListener("click", toggleDetail);

  function toggleDetail() {
    if (selectedTarget === name) {
      selectedTarget = null;
      div.style.borderColor = "";
      document.getElementById("dash-target-detail").innerHTML = "";
    } else {
      document.querySelectorAll("#dash-target-list .card").forEach((c) => c.style.borderColor = "");
      div.style.borderColor = "var(--accent)";
      selectedTarget = name;
      loadTargetDetail(name);
    }
  }

  div.querySelector(".dash-reset-btn").addEventListener("click", async (e) => {
    e.stopPropagation();
    const ok = await showConfirm(
      `Reset "${name}"?\n\nThis deletes findings, logs, and intelligence.\nSource files and target.json are preserved.`
    );
    if (!ok) return;
    const statusEl = div.querySelector(".dash-reset-btn");
    statusEl.disabled = true;
    statusEl.textContent = "…";
    try {
      await apiFetch(`/api/targets/${encodeURIComponent(name)}/reset`, { method: "POST" });
      statusEl.textContent = "✓ Reset";
      if (selectedTarget === name) {
        selectedTarget = null;
        document.getElementById("dash-target-detail").innerHTML = "";
        div.style.borderColor = "";
      }
    } catch (err) {
      statusEl.textContent = "Reset";
      statusEl.disabled = false;
      alert("Reset failed: " + err.message);
    }
  });

  div.querySelector(".dash-delete-btn").addEventListener("click", async (e) => {
    e.stopPropagation();
    const ok = await showConfirm(
      `Delete "${name}" permanently?\n\nThis removes the entire target folder including source files. This cannot be undone.`
    );
    if (!ok) return;
    try {
      await apiFetch(`/api/targets/${encodeURIComponent(name)}`, { method: "DELETE" });
      div.remove();
      if (selectedTarget === name) {
        selectedTarget = null;
        document.getElementById("dash-target-detail").innerHTML = "";
      }
    } catch (err) {
      alert("Delete failed: " + err.message);
    }
  });

  return div;
}

async function loadTargetDetail(name) {
  const detailEl = document.getElementById("dash-target-detail");
  detailEl.innerHTML = `<div style="color:var(--text-dim);font-size:13px;padding:12px 0;">Loading ${esc(name)}…</div>`;

  try {
    const [intel, bundle, candidatesData, recon, session] = await Promise.all([
      apiFetch(`/api/intelligence/${name}`).catch(() => ({})),
      apiFetch(`/api/targets/${name}/findings`).catch(() => ({ findings: [] })),
      apiFetch(`/api/targets/${name}/candidates`).catch(() => ({ candidates: [] })),
      apiFetch(`/api/targets/${name}/recon`).catch(() => ({})),
      apiFetch(`/api/session/${name}`).catch(() => null),
    ]);

    const cfg        = intel?.config   || {};
    const scopes     = intel?.local?.scopeSnapshot?.scopes || [];
    const findings   = bundle?.findings   || [];
    const candidates = candidatesData?.candidates || [];
    const langStats  = recon.lang_stats || {};
    const totalFiles = recon.total_files || 0;

    // Determine which asset types have been scanned based on bundle meta + candidates
    const scannedAssetType = bundle?.meta?.asset_type || null;
    const hasSource = totalFiles > 0;

    detailEl.innerHTML = renderTargetDetail({
      name, cfg, scopes, findings, candidates, langStats, totalFiles,
      scannedAssetType, hasSource, session, recon,
    });

  } catch (err) {
    detailEl.innerHTML = `<div style="color:var(--danger);font-size:13px;">Failed: ${esc(err.message)}</div>`;
  }
}

function renderTargetDetail({ name, cfg, scopes, findings, candidates, langStats, totalFiles,
                               scannedAssetType, hasSource, session, recon }) {

  const allCandidates = [...findings, ...candidates];
  const bySev = allCandidates.reduce((acc, f) => {
    const s = (f.severity || "info").toLowerCase(); acc[s] = (acc[s]||0)+1; return acc;
  }, {});

  // ── Header ───────────────────────────────────────────────────────────────
  const phase     = session?.phase || null;
  const phaseText = phase ? `<span class="badge badge-blue" style="font-size:11px;">${esc(phase)}</span>` : "";
  const progUrl   = cfg.program_url
    ? `<a href="${esc(cfg.program_url)}" target="_blank" style="color:var(--accent);font-size:12px;">${esc(cfg.program_url)}</a>`
    : "";

  const headerHtml = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:20px;">
      <div>
        <div style="font-size:18px;font-weight:700;color:var(--accent);margin-bottom:4px;">${esc(name)}</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          ${phaseText}
          ${progUrl}
          ${cfg.asset_type ? `<span style="font-size:12px;color:var(--text-dim);">${esc(cfg.asset_type)}</span>` : ""}
          ${cfg.default_mode ? `<span style="font-size:12px;color:var(--text-dim);">${esc(cfg.default_mode)}</span>` : ""}
        </div>
      </div>
      <div style="display:flex;gap:16px;">
        ${SEV_ORDER.filter((s) => bySev[s]).map((s) =>
          `<div style="text-align:center;">
            <div style="font-size:20px;font-weight:700;color:${SEV_COLOR[s]};">${bySev[s]}</div>
            <div style="font-size:10px;color:var(--text-dim);">${s}</div>
          </div>`
        ).join("")}
      </div>
    </div>`;

  // ── Assets in scope ───────────────────────────────────────────────────────
  let assetsHtml = "";
  if (scopes.length) {
    const assetRows = scopes.map((s) => {
      const assetKey = SCOPE_TYPE_TO_ASSET[s.asset_type] || "webapp";
      const covered  = scannedAssetType && scannedAssetType === assetKey;
      const statusIcon = covered
        ? `<span style="color:#98c379;font-size:13px;" title="Scanned">&#10003; scanned</span>`
        : `<span style="color:var(--text-dim);font-size:12px;" title="Not yet scanned">&#9675; pending</span>`;
      const sev      = s.max_severity || "—";
      const sevColor = sev === "critical" ? SEV_COLOR.critical : sev === "high" ? SEV_COLOR.high : "inherit";

      // Candidate count for this asset (approximate by checking source file paths)
      const assetCandidates = candidates.filter((c) =>
        (c.source?.file || c.sink?.file || "").length > 0
      ).length;

      return `<tr style="border-bottom:1px solid var(--border);">
        <td style="padding:6px 10px 6px 0;">
          <span style="font-size:10px;background:rgba(97,175,239,.15);color:#61afef;border-radius:3px;padding:2px 6px;">${esc(s.asset_type)}</span>
        </td>
        <td style="padding:6px 10px;font-family:var(--font-mono);font-size:11px;word-break:break-all;">${esc(s.asset_identifier)}</td>
        <td style="padding:6px 10px;color:${sevColor};font-size:12px;white-space:nowrap;">${esc(sev)}</td>
        <td style="padding:6px 0;white-space:nowrap;font-size:12px;">${statusIcon}</td>
      </tr>`;
    }).join("");

    assetsHtml = section("ASSETS IN SCOPE", `
      <table style="width:100%;border-collapse:collapse;">
        <thead><tr style="color:var(--text-dim);border-bottom:1px solid var(--border);font-size:11px;">
          <th style="text-align:left;padding:4px 10px 4px 0;">Type</th>
          <th style="text-align:left;padding:4px 10px;">Identifier</th>
          <th style="text-align:left;padding:4px 10px;">Max severity</th>
          <th style="text-align:left;padding:4px 0;">Coverage</th>
        </tr></thead>
        <tbody>${assetRows}</tbody>
      </table>
    `);
  }

  // ── Tech stack (mandatory) ────────────────────────────────────────────────
  let techHtml = "";
  const sortedLangs = Object.entries(langStats).sort((a, b) => b[1] - a[1]);
  const maxCount = sortedLangs[0]?.[1] || 1;

  if (sortedLangs.length) {
    const bars = sortedLangs.slice(0, 14).map(([lang, count]) => {
      const pct   = Math.max(2, Math.round(count / maxCount * 100));
      const color = LANG_COLOR[lang] || "#abb2bf";
      const pcTot = totalFiles ? Math.round(count / totalFiles * 100) : 0;
      return `<div style="display:flex;align-items:center;gap:10px;margin-bottom:5px;">
        <div style="width:80px;font-size:12px;color:var(--text-dim);text-align:right;flex-shrink:0;">${esc(lang)}</div>
        <div style="flex:1;background:var(--border);border-radius:3px;height:13px;">
          <div style="width:${pct}%;background:${color};height:13px;border-radius:3px;"></div>
        </div>
        <div style="width:60px;font-size:11px;color:var(--text-dim);">${count} <span style="opacity:.6;">(${pcTot}%)</span></div>
      </div>`;
    }).join("");
    techHtml = section(`TECH STACK — ${totalFiles} files analysed`, bars);
  } else {
    techHtml = section("TECH STACK", `<span style="color:var(--text-dim);font-size:12px;">No source code scanned yet — run a whitebox pipeline.</span>`);
  }

  // ── Attack surface ────────────────────────────────────────────────────────
  let attackHtml = "";
  const as = recon.attack_surface;
  if (as) {
    const populated = Object.entries(as)
      .filter(([k, v]) => Array.isArray(v) && v.length > 0
        && !["schema_version","generated_at","target"].includes(k));
    if (populated.length) {
      const chips = populated.map(([k, v]) =>
        `<div style="display:flex;align-items:center;justify-content:space-between;padding:5px 0;
             border-bottom:1px solid var(--border);font-size:12px;">
           <span style="color:var(--text-dim);">${esc(k.replace(/_/g," "))}</span>
           <span style="font-weight:600;color:#56b6c2;">${v.length}</span>
         </div>`
      ).join("");
      attackHtml = section("ATTACK SURFACE", chips);
    }
  }

  // ── Findings & Candidates ─────────────────────────────────────────────────
  let findingsHtml = "";
  if (findings.length || candidates.length) {
    // confirmed
    let confirmedTable = "";
    if (findings.length) {
      const rows = findings.map((f) => {
        const sev = (f.severity||"info").toLowerCase();
        return `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:5px 8px 5px 0;font-family:var(--font-mono);font-size:10px;color:var(--text-dim);">${esc(f.id||"—")}</td>
          <td style="padding:5px 8px;">${esc(f.title||"—")}</td>
          <td style="padding:5px 0;color:${SEV_COLOR[sev]||"inherit"};font-weight:600;white-space:nowrap;">${esc(sev)}</td>
        </tr>`;
      }).join("");
      confirmedTable = `
        <div style="font-size:11px;color:var(--text-dim);letter-spacing:.06em;margin-bottom:6px;margin-top:12px;">CONFIRMED (${findings.length})</div>
        <table style="width:100%;border-collapse:collapse;font-size:12px;">
          <tbody>${rows}</tbody>
        </table>`;
    }

    // candidates with source→sink
    let candidatesSection = "";
    const withFlow = candidates.filter((c) => c.source && c.sink);
    if (withFlow.length) {
      const cards = withFlow.slice(0, 15).map((c) => {
        const sev     = (c.severity||"info").toLowerCase();
        const sevCol  = SEV_COLOR[sev] || "#abb2bf";
        const entry   = c.source?.entry_point || c.source?.file || "?";
        const sinkFn  = c.sink?.function || c.sink?.file || "?";
        const srcLoc  = c.source?.file ? `${c.source.file}${c.source.line ? ":"+c.source.line : ""}` : null;
        const sinkLoc = c.sink?.file   ? `${c.sink.file}${c.sink.line   ? ":"+c.sink.line   : ""}` : null;
        return `<div style="margin-bottom:8px;padding:8px;background:rgba(255,255,255,.02);
                     border:1px solid var(--border);border-left:3px solid ${sevCol};border-radius:4px;">
          <div style="font-size:11px;font-weight:600;margin-bottom:6px;">${esc(c.title||"—")}
            <span style="color:${sevCol};margin-left:6px;">${esc(sev)}</span>
          </div>
          <div style="display:flex;align-items:stretch;gap:0;font-size:11px;">
            <div style="flex:1;background:rgba(97,175,239,.06);border:1px solid rgba(97,175,239,.2);
                        border-radius:3px 0 0 3px;padding:5px 8px;">
              <div style="color:#61afef;font-size:10px;margin-bottom:2px;">ENTRY</div>
              <div style="font-family:var(--font-mono);color:#84c3ff;">${esc(entry)}</div>
              ${srcLoc ? `<div style="color:var(--text-dim);font-size:10px;margin-top:1px;">${esc(srcLoc)}</div>` : ""}
            </div>
            <div style="display:flex;align-items:center;padding:0 8px;color:var(--text-dim);">&#8594;</div>
            <div style="flex:1;background:rgba(224,108,117,.06);border:1px solid rgba(224,108,117,.2);
                        border-radius:0 3px 3px 0;padding:5px 8px;">
              <div style="color:#e06c75;font-size:10px;margin-bottom:2px;">SINK</div>
              <div style="font-family:var(--font-mono);color:#ff7b7b;">${esc(sinkFn)}</div>
              ${sinkLoc ? `<div style="color:var(--text-dim);font-size:10px;margin-top:1px;">${esc(sinkLoc)}</div>` : ""}
            </div>
          </div>
        </div>`;
      }).join("");
      candidatesSection = `
        <div style="font-size:11px;color:var(--text-dim);letter-spacing:.06em;margin-bottom:6px;margin-top:12px;">
          CANDIDATES — INPUT &#8594; SINK (${withFlow.length})
        </div>
        ${cards}
        ${withFlow.length > 15 ? `<div style="color:var(--text-dim);font-size:12px;">…and ${withFlow.length-15} more</div>` : ""}`;
    }

    findingsHtml = section("FINDINGS", confirmedTable + candidatesSection);
  }

  // ── Disclosed vulnerability history ──────────────────────────────────────
  let disclosedHtml = "";
  const weaknesses = recon.research_brief?.same_program_disclosed_top_weaknesses || [];
  if (weaknesses.length) {
    const maxW = weaknesses[0]?.count || 1;
    const bars = weaknesses.map(({ label, count }, i) => {
      const pct   = Math.max(2, Math.round(count / maxW * 100));
      const color = ["#e06c75","#e5c07b","#56b6c2","#98c379","#c678dd"][i % 5];
      return `<div style="display:flex;align-items:center;gap:10px;margin-bottom:5px;">
        <div style="width:220px;font-size:11px;color:var(--text-dim);text-align:right;flex-shrink:0;">${esc(label)}</div>
        <div style="flex:1;background:var(--border);border-radius:3px;height:12px;">
          <div style="width:${pct}%;background:${color};height:12px;border-radius:3px;"></div>
        </div>
        <div style="width:20px;font-size:11px;color:var(--text-dim);">${count}</div>
      </div>`;
    }).join("");
    disclosedHtml = section("H1 DISCLOSED HISTORY (same program)", bars);
  }

  return `<div style="display:flex;flex-direction:column;gap:12px;">
    <div class="card" style="margin:0;">
      ${headerHtml}
      ${assetsHtml}
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div class="card" style="margin:0;">${techHtml}${attackHtml}</div>
      <div class="card" style="margin:0;">${disclosedHtml || findingsHtml}</div>
    </div>
    ${(disclosedHtml && findingsHtml) ? `<div class="card" style="margin:0;">${findingsHtml}</div>` : ""}
  </div>`;
}

// ── Sync ──────────────────────────────────────────────────────────────────────

async function syncDb(root) {
  const btn    = document.getElementById("dash-sync-btn");
  const status = document.getElementById("dash-sync-status");
  if (!btn) return;
  btn.disabled = true;
  status.textContent = "Syncing…";
  try {
    const res = await apiFetch("/api/dashboard/sync", { method: "POST", body: {} });
    const ok  = (res.results || []).filter((r) => r.ok);
    status.textContent = `Synced ${ok.length} target(s) at ${new Date().toLocaleTimeString()}`;
    // Reload the dashboard cards to reflect updated counts
    loadDashboard(root);
  } catch (err) {
    status.textContent = "Sync failed: " + err.message;
    btn.disabled = false;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function section(title, contentHtml) {
  return `<div style="margin-bottom:16px;">
    <div style="font-size:11px;font-weight:600;color:var(--text-dim);letter-spacing:.06em;margin-bottom:10px;">${esc(title)}</div>
    ${contentHtml}
  </div>`;
}

function esc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
