# UI Refactor Design — Agentic BugBounty
**Date:** 2026-04-05
**Status:** Approved for implementation

---

## 1. Goals

The current UI was added on top of a CLI pipeline. The result is a job monitor that tails log files and parses text strings to infer state. This spec redesigns the UI as the primary interface for the entire bug bounty workflow, with the CLI pipeline as the execution backend.

**Primary driver:** UX — the UI guides the user through the full workflow (target setup → scope selection → plan approval → execution → findings review → submit) without requiring terminal interaction.

**Non-goals:** Rewriting the agents (researcher, triager, chain-coordinator). They remain Claude Code CLI subprocesses and are not touched.

---

## 2. Architecture Overview

### 2.1 Session File + Checkpoint Protocol

The pipeline communicates with the UI through a structured `session.json` file per target. This reuses the existing checkpoint system with a formal schema.

**Mechanism:**
1. Pipeline writes `session.json` with `status: "awaiting_*"` and pauses (500ms polling loop)
2. UI server watches `session.json` via `fs.watch`, pushes SSE event to browser
3. User approves/modifies in UI → UI writes response to `session.json`
4. Pipeline detects status change, reads approved options, resumes

This is activated only when `--hitl` flag is passed to `run-pipeline.js`. Without it, the pipeline runs exactly as today (zero regression).

### 2.2 Frontend Stack

**Vite + vanilla JS** (no framework). The existing Node server serves only the API. In development, Vite proxies API calls to the Node server. In production, `npm run build` outputs `ui/dist/` which the Node server serves as static files.

```
ui/                         ← new Vite project root
  src/
    main.js                 ← entry point
    modules/
      window-manager.js     ← drag, resize, min/max/close, dock
      theme.js              ← light/dark toggle, CSS variables
      modal.js              ← replaces all browser alert/confirm/prompt
    panels/
      run-control.js        ← wizard stepper + approval UI
      metrics.js            ← live counters + log feed
      tech-stack.js         ← asset × tech matrix with 0-day filter
      data-flow.js          ← input→sink animated graph (SVG)
      intelligence.js       ← scope, history, skills tabs
      findings.js           ← confirmed findings review
      settings.js           ← env vars, API keys
      targets.js            ← target list + create flow
    style/
      base.css              ← CSS variables, reset
      theme-dark.css        ← dark theme (default)
      theme-light.css       ← light theme
      scrollbars.css        ← theme-aware scrollbar styles
      window-manager.css    ← floater, dock, topbar
  index.html
  vite.config.js
```

---

## 3. Session Contract

**File location:** `targets/{name}/session.json`

**Schema:** `schemas/session.schema.json` (AJV validated on every write)

### 3.1 Pipeline writes

```jsonc
// Phase: asset selection
{
  "schema_version": "1.0",
  "status": "awaiting_assets",
  "phase": "setup",
  "asset_type": "browserext",
  "available_assets": [
    { "id": "ext-main", "label": "Extension main process", "mandatory": true },
    { "id": "content-scripts", "label": "Content scripts", "mandatory": false }
  ]
}

// Phase: plan approval (before researcher)
{
  "schema_version": "1.0",
  "status": "awaiting_approval",
  "phase": "researcher",
  "asset_type": "browserext",
  "context": "Found 3 content scripts, 2 background workers, 1 popup",
  "plan": [
    { "id": "postmessage",     "label": "postMessage vulnerabilities",   "mandatory": true,  "reason": null },
    { "id": "dom_xss",         "label": "DOM XSS",                       "mandatory": true,  "reason": null },
    { "id": "content_script",  "label": "Content script injection",      "mandatory": false, "reason": "requires user interaction" },
    { "id": "supply_chain",    "label": "Supply chain",                  "mandatory": false, "reason": "no npm deps found" }
  ]
}

// Phase: findings review (before triage)
{
  "schema_version": "1.0",
  "status": "awaiting_approval",
  "phase": "triage",
  "findings": [ /* array of confirmed findings from report_bundle */ ]
}

// Runtime progress (UI reads for live monitor)
{
  "schema_version": "1.0",
  "status": "running",
  "phase": "researcher",
  "current_op": "postmessage",
  "completed_ops": ["dom_xss"],
  "findings_so_far": 2
}
```

### 3.2 UI writes (response)

```jsonc
// Asset selection response
{ "status": "assets_selected", "selected_assets": ["ext-main"] }

// Plan approval response
{ "status": "approved", "approved_ops": ["postmessage", "dom_xss", "content_script"] }

// Skip at runtime
{ "status": "skip_requested", "skip_op": "content_script" }
```

### 3.3 Domain map by asset_type

The `buildPlanForAssetType(assetType, surfaceMap)` function in `session.js` generates the plan based on:

| asset_type   | domains / operations |
|--------------|---------------------|
| `webapp`     | AUTH, INJECT, CLIENT, ACCESS, MEDIA, INFRA |
| `browserext` | postmessage, dom_xss, content_script, supply_chain, permissions |
| `mobileapp`  | deep_links, intent, storage, network, crypto |
| `executable` | memory_corruption, binary_analysis, input_validation, priv_esc |

Mandatory ops per type are defined in a config map. Optional ops are filtered by surface map evidence (e.g. MEDIA only suggested if file upload endpoints found).

---

## 4. Pipeline Changes

Minimal surgical changes to `run-pipeline.js` — all gated behind `isHitlMode(args)`.

### 4.1 New module: `scripts/lib/session.js`

```js
writeCheckpoint(sessionPath, payload)   // writes + validates session.json
waitForApproval(sessionPath, timeoutMs) // polls every 500ms, resolves with UI response; default timeout 30min
buildPlanForAssetType(assetType, surfaceMap) // returns { plan, context }
isHitlMode(args)                        // true if --hitl in args
```

### 4.2 Three insertion points in `run-pipeline.js`

1. **Before pipeline start** — asset selection checkpoint
2. **After explorer, before researcher** — researcher plan approval
3. **After researcher, before triage** — findings review approval

~50 lines added total. All wrapped in `if (isHitlMode(args)) { ... }`.

### 4.3 New API endpoints in `serve-intel-ui.js`

```
GET  /api/session/:target          → current session.json state
POST /api/session/:target/respond  → write UI response to session.json
```

The server uses `fs.watch` on `session.json` to push SSE events to connected browser clients when the pipeline writes a new checkpoint.

---

## 5. UI Architecture

### 5.1 Window Manager

Every panel is a floating window. Capabilities:
- **Drag:** grab title bar, move freely within viewport
- **Resize:** drag handle at bottom-right corner
- **Minimize (−):** collapses to title bar only, persists in dock
- **Maximize (+):** fills viewport (minus topbar + dock), toggle to restore
- **Close (×):** hides window, dock button turns highlighted to indicate closed state
- **Restore:** click dock button to reopen at last position/size
- **Focus:** click any window to bring to front (z-index management)
- **Responsive fallback:** on viewport < 768px, windows stack vertically as normal block elements (no drag/resize)

Window state (position, size, open/closed, minimized) is persisted to `localStorage` keyed by panel id.

### 5.2 Wizard Flow (Run Control panel)

The Run Control panel is always available and shows:
1. **Stepper** — 6 steps: Setup → Assets → Explorer → Researcher → Review → Submit. Current step highlighted with pulse animation.
2. **Approval panel** — appears when `session.json` has `status: "awaiting_*"`. Shows plan with REQUIRED/optional badges and checkboxes. Mandatory ops have disabled checkboxes.
3. **Live feed** — log lines from SSE stream, last 5 lines visible.

### 5.3 Graphs

**Data Flow (input → sink):**
- SVG-based, nodes positioned in columns: Inputs → Transforms → Sinks
- Animated dashed paths between nodes (CSS `stroke-dashoffset` animation)
- Node colors: blue = input, purple = transform, green = sanitized, red = critical sink, amber = potential sink
- Critical nodes pulse with glow animation
- Click node → opens modal with source file path and line number
- Data source: `surface_map.json` (explorer output), enriched by researcher findings

**Tech Stack (asset × technology matrix):**
- Table: rows = domains/assets, columns = detected technologies
- Cells with detected version glow; vulnerable cells (CVE match) pulse red
- CVE filter bar: type a technology name → highlights all matching cells across assets
- Data source: `hybrid-recon.js` fingerprinting output, stored in `intelligence/tech_stack.json`. This file does not exist yet — `hybrid-recon.js` must be extended to write it as part of this implementation.

### 5.4 Settings Panel

Reads/writes `.env` file in project root via new API endpoint.

```
GET  /api/settings        → masked key/value pairs ({ key, masked_value, is_set })
POST /api/settings        → write one key/value to .env (server validates key whitelist)
```

Keys shown:
- `H1_API_TOKEN`, `H1_API_USERNAME` — HackerOne API
- `OPENROUTER_API_KEY` — LLM fallback
- `BBSCOPE_API_KEY` — bbscope.com
- `NOTIFY_WEBHOOK_URL` — optional webhook

Display: masked value (`••••••••`), status indicator (✓ set / ⚠ partial / ✕ missing), edit inline.

### 5.5 Theme System

CSS custom properties on `:root`. Two themes: `dark` (default) and `light`. Toggle button in topbar. Preference persisted to `localStorage`.

Theme-aware scrollbars via `::-webkit-scrollbar` + `scrollbar-color` (Firefox). Scrollbar styles defined in `scrollbar.css`, inherit CSS variables from active theme.

### 5.6 Modals

`modal.js` exports `showAlert(msg)`, `showConfirm(msg)` → Promise<bool>, `showPrompt(msg, defaultVal)` → Promise<string|null>. All browser `alert`/`confirm`/`prompt` calls replaced with these throughout the codebase. Modals are theme-aware floating panels (not windows — they have an overlay backdrop and cannot be moved).

---

## 6. Files Changed / Added

### New files
```
ui/                               ← Vite project (all new)
scripts/lib/session.js
schemas/session.schema.json
tests/session.test.js
```

### Modified files
```
scripts/run-pipeline.js           ← +~50 lines (3 HITL checkpoints)
scripts/serve-intel-ui.js         ← +2 session endpoints, +settings endpoint, serve ui/dist/
package.json                      ← +ui:dev script (vite dev), update ui:start to serve dist
```

### Deleted / replaced
```
docs/intel-ui.html                ← replaced by ui/dist/index.html (built output)
docs/intel-ui.css                 ← replaced by ui/src/style/
```

---

## 7. Out of Scope

- Rewriting researcher / triager / chain-coordinator agents
- WebSocket (SSE is sufficient for this use case)
- Multi-user / auth (single-user local tool)
- Mobile native app
- Migrating from SQLite to a different DB
- CI/CD pipeline changes
