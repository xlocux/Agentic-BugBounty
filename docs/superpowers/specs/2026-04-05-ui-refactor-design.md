# UI Refactor Design — Agentic BugBounty
**Date:** 2026-04-05
**Status:** Approved for implementation — split into 2 milestones

---

## 1. Goals

The current UI was added on top of a CLI pipeline. The result is a job monitor that tails log files and parses text strings to infer state. This spec redesigns the UI as the primary interface for the entire bug bounty workflow, with the CLI pipeline as the execution backend.

**Primary driver:** UX — the UI guides the user through the full workflow (target setup → scope selection → plan approval → execution → findings review → submit) without requiring terminal interaction.

**Non-goals:** Rewriting the agents (researcher, triager, chain-coordinator). They remain Claude Code CLI subprocesses and are not touched.

---

## 2. Architecture Overview

### 2.1 Session Contract — Two-File Protocol

Pipeline and UI never write the same file simultaneously. Two dedicated files per target eliminate race conditions and ambiguous acks:

| File | Writer | Reader | Purpose |
|------|--------|--------|---------|
| `targets/{name}/session.json` | pipeline only | UI server | State, plan, progress |
| `targets/{name}/session-response.json` | UI server only | pipeline | Approval, selections, skip |

**Mechanism:**
1. Pipeline writes `session.json` with `status: "awaiting_*"` + `request_id` + `written_at`, then enters polling loop on `session-response.json`
2. UI server detects change (see §2.2), reads `session.json`, pushes SSE event to browser
3. User approves in UI → server writes `session-response.json` with matching `request_id`
4. Pipeline reads response, verifies `request_id` matches, resumes

`request_id` is a monotonically incrementing integer per run. Pipeline rejects any response whose `request_id` doesn't match the current checkpoint — stale acks are ignored.

### 2.2 Change Detection — fs.watch + Polling Fallback

`fs.watch` is used as a low-latency trigger only, not as a source of truth. The UI server also polls `session.json` every 2 seconds via `mtime` comparison. On each poll, if `mtime` has advanced, the file is re-read and the SSE event is emitted. This means:

- Normal case: fs.watch fires within ~100ms, instant UI update
- Degraded case (fs.watch miss, NFS, WSL): polling catches the change within 2s
- Source of truth: always the file content + mtime, never the watch event itself

### 2.3 Frontend Stack

**Vite + vanilla JS** (no framework). In development, `npm run ui:dev` starts Vite dev server with proxy to the Node API. In production, `npm run ui:build` outputs `ui/dist/` which the Node server serves as static files.

```
ui/
  src/
    main.js
    modules/
      window-manager.js     ← drag, resize, min/max/close, dock, localStorage persist
      theme.js              ← light/dark toggle, CSS custom properties
      modal.js              ← showAlert / showConfirm / showPrompt (no browser dialogs)
      api.js                ← fetch wrapper + SSE client
    panels/
      run-control.js        ← wizard stepper + plan approval
      metrics.js            ← live counters + log feed
      tech-stack.js         ← asset × tech matrix + CVE filter
      data-flow.js          ← input→sink animated SVG graph
      intelligence.js       ← scope, history, skills tabs + target selector
      findings.js           ← confirmed findings review + pre-triage editing
      settings.js           ← env vars, API keys editor
      targets.js            ← target list + create wizard
    style/
      base.css              ← CSS custom properties, reset
      theme-dark.css        ← dark theme variables (default)
      theme-light.css       ← light theme variables
      scrollbars.css        ← theme-aware ::-webkit-scrollbar + scrollbar-color
      window-manager.css    ← floater, dock, topbar
  index.html
  vite.config.js            ← proxy /api → Node server, build → ui/dist/
```

---

## 3. Session Contract Schema

**Schema:** `schemas/session.schema.json` (AJV validated on every write by both writer)

### 3.1 session.json (pipeline → UI)

```jsonc
// Checkpoint: asset selection
{
  "schema_version": "1.0",
  "request_id": 1,
  "written_at": "2026-04-05T10:00:00.000Z",
  "written_by": "pipeline",
  "status": "awaiting_assets",
  "phase": "setup",
  "asset_type": "browserext",
  "available_assets": [
    { "id": "ext-main",        "label": "Extension main process", "mandatory": true },
    { "id": "content-scripts", "label": "Content scripts",        "mandatory": false }
  ]
}

// Checkpoint: researcher plan approval
{
  "schema_version": "1.0",
  "request_id": 2,
  "written_at": "2026-04-05T10:05:00.000Z",
  "written_by": "pipeline",
  "status": "awaiting_approval",
  "phase": "researcher",
  "asset_type": "browserext",
  "context": "Found 3 content scripts, 2 background workers, 1 popup",
  "plan": [
    { "id": "postmessage",    "label": "postMessage vulnerabilities",  "mandatory": true,  "reason": null },
    { "id": "dom_xss",        "label": "DOM XSS",                      "mandatory": true,  "reason": null },
    { "id": "content_script", "label": "Content script injection",     "mandatory": false, "reason": "requires user interaction" },
    { "id": "supply_chain",   "label": "Supply chain",                 "mandatory": false, "reason": "no npm deps found" }
  ]
}

// Checkpoint: findings review (before triage)
{
  "schema_version": "1.0",
  "request_id": 3,
  "written_at": "2026-04-05T10:30:00.000Z",
  "written_by": "pipeline",
  "status": "awaiting_approval",
  "phase": "triage",
  "findings": [ /* confirmed findings array from report_bundle.findings */ ]
}

// Runtime progress (polled by UI every 2s for live monitor)
{
  "schema_version": "1.0",
  "request_id": 2,
  "written_at": "2026-04-05T10:10:00.000Z",
  "written_by": "pipeline",
  "status": "running",
  "phase": "researcher",
  "current_op": "postmessage",
  "completed_ops": ["dom_xss"],
  "findings_so_far": 2
}
```

### 3.2 session-response.json (UI → pipeline)

```jsonc
// Asset selection
{
  "schema_version": "1.0",
  "request_id": 1,
  "written_at": "2026-04-05T10:01:00.000Z",
  "written_by": "ui",
  "status": "assets_selected",
  "selected_assets": ["ext-main"]
}

// Plan approval
{
  "schema_version": "1.0",
  "request_id": 2,
  "written_at": "2026-04-05T10:06:00.000Z",
  "written_by": "ui",
  "status": "approved",
  "approved_ops": ["postmessage", "dom_xss", "content_script"]
}

// Skip at runtime
{
  "schema_version": "1.0",
  "request_id": 2,
  "written_at": "2026-04-05T10:12:00.000Z",
  "written_by": "ui",
  "status": "skip_requested",
  "skip_op": "content_script"
}
```

### 3.3 Domain map by asset_type

`buildPlanForAssetType(assetType, surfaceMap)` in `session.js` generates the plan. Mandatory ops are fixed per type; optional ops are filtered by surface map evidence.

| asset_type   | mandatory | optional (surface-gated) |
|--------------|-----------|--------------------------|
| `webapp`     | AUTH, INJECT | CLIENT, ACCESS, MEDIA (if uploads), INFRA |
| `browserext` | postmessage, dom_xss | content_script, supply_chain, permissions |
| `mobileapp`  | deep_links, intent | storage, network, crypto |
| `executable` | memory_corruption, binary_analysis | input_validation, priv_esc |

---

## 4. Pipeline Changes

### 4.1 New module: `scripts/lib/session.js`

```js
writeState(sessionPath, payload)           // writes + AJV-validates session.json
writeResponse(responsePath, payload)       // writes + AJV-validates session-response.json
waitForResponse(responsePath, requestId, timeoutMs=1800000)
                                           // polls every 500ms; rejects stale request_id; default 30min timeout
buildPlanForAssetType(assetType, surfaceMap) // returns { plan, context }
isHitlMode(args)                           // true if args.hitl === true
```

### 4.2 Changes to run-pipeline.js

The file already has `--hitl` flag parsing (line 84) and three `checkpoint1/2/3` calls from `lib/hitl.js` (line 47, 1423). The new implementation **replaces** the existing `hitl.js` checkpoint calls with `session.js` calls — it does not add on top of them.

The existing `hitl.js` checkpoints use `readline` (interactive terminal). The new session checkpoints write files and poll. The two modes are mutually exclusive: `--hitl` now means file-based session protocol; the old `readline` path is retired.

Realistic estimate: **~150–200 lines** of net change in `run-pipeline.js` (replacing hitl.js calls, adding asset selection loop, adapting the existing domain filtering logic to use approved_ops).

Three logical insertion points:
1. **Asset selection** — before `allAssets` loop starts (~line 1896 area)
2. **Researcher plan approval** — replaces `checkpoint1_postExplorer` call (~line 1423)
3. **Findings review** — replaces `checkpoint2_postResearcher` / `checkpoint3_preTriage` calls (~line 1620/1680)

### 4.3 New API endpoints in serve-intel-ui.js

```
GET  /api/session/:target           → current session.json (pipeline state)
POST /api/session/:target/respond   → write session-response.json (UI approval)
GET  /api/settings                  → masked .env key/value pairs
POST /api/settings                  → write single key to .env (whitelist validated)
```

**SSE streams — two distinct channels, not unified:**

| Stream | Endpoint | Events | Consumer |
|--------|----------|--------|----------|
| Job log stream | `GET /api/stream/:job_id` | `{ type, line, offset, ts }` — existing | Terminal panel, Metrics log feed |
| Session stream | `GET /api/session/:target/stream` | `{ type: "session_update", data }` — new | Run Control approval panel |

They are kept separate deliberately: the job stream is per-job-id and carries raw log lines; the session stream is per-target and carries structured state. The UI subscribes to both independently. `api.js` in the frontend wraps both with the same SSE client helper.

Session stream change detection: server watches `session.json` (fs.watch + 2s polling fallback on `mtime`) and pushes `{ type: "session_update", data: <session.json content> }` to all active session stream connections for that target.

---

## 5. UI Architecture

### 5.1 Window Manager

Every panel is a floating window. State persisted to `localStorage` (position, size, open/closed/minimized).

- **Drag:** title bar grab
- **Resize:** bottom-right handle
- **Minimize (−):** collapses to title bar, docked
- **Maximize (+):** fills viewport minus topbar+dock; toggle restores
- **Close (×):** hides; dock button highlighted
- **Restore:** click dock button
- **Focus:** click to front (z-index stack)
- **Responsive:** viewport < 768px → windows become stacked block elements, no drag/resize

### 5.2 Wizard Flow (Run Control panel)

1. **Stepper** — 6 steps: Setup → Assets → Explorer → Researcher → Review → Submit
2. **Approval panel** — shown when `session.json.status === "awaiting_*"`. REQUIRED badges on mandatory ops (checkbox disabled), optional ops user-selectable
3. **Live feed** — last 5 log lines from SSE stream

### 5.3 Graphs

**Data Flow (input → sink):**
- SVG nodes in columns: Inputs → Transforms → Sinks
- Animated `stroke-dashoffset` paths, color-coded by safety (blue/purple/green/amber/red)
- Glow + pulse on critical sinks
- Click node → modal with file:line
- Data source: `surface_map.json` enriched by researcher findings

**Tech Stack matrix:**
- Rows = assets, columns = detected technologies
- Vulnerable cells pulse red; CVE filter highlights affected assets
- Data source: `intelligence/tech_stack.json` — **new file** that `hybrid-recon.js` must be extended to write

### 5.4 Settings Panel

`.env` editor. **Changes take effect only for future jobs** (environment is loaded at process startup — running pipeline processes are not affected). A server restart is required for changes to propagate to the Node server itself.

Keys managed:
- `H1_API_TOKEN`, `H1_API_USERNAME`
- `OPENROUTER_API_KEY` + `OPENROUTER_API_KEY_1` through `OPENROUTER_API_KEY_5` (rotation pool)
- `BBSCOPE_API_KEY`
- `NOTIFY_WEBHOOK_URL`

Display: masked value, status badge, inline edit. Explicit banner: "Changes apply to the next run. Restart the server to apply to the UI itself."

### 5.5 Source Fetching

When creating a target, the user can optionally provide a GitHub URL for the source code. Two paths:

Many H1 programs have 5–20 GitHub repos in scope. The user needs help deciding which ones to analyze first. The flow has two sub-phases:

#### Phase A — Repo Discovery & AI Ranking

After scope sync completes, the system scans the in-scope assets for GitHub URLs (from `h1_scope_snapshot.json` and the program policy page). For each discovered public GitHub repo it fetches lightweight metadata via the GitHub API (no auth required for public repos):

```
GET https://api.github.com/repos/{owner}/{repo}
→ language, size, stargazers_count, pushed_at, topics, description
GET https://api.github.com/repos/{owner}/{repo}/contents (root listing)
→ detect package.json, pom.xml, go.mod, requirements.txt, etc.
```

This metadata is stored in `intelligence/github_repos.json`. Then a lightweight LLM call (optional, skipped if no API key) ranks the repos by attack surface priority using:
- Recency (`pushed_at`) — recently active repos are higher priority
- Language/stack — web-facing stacks (Node, PHP, Python/Django, Java/Spring) ranked higher
- Size — very small repos (< 50 files) deprioritized
- Topics — keywords like `api`, `auth`, `payments` boost ranking
- In-scope asset match — repos whose name matches an in-scope domain ranked higher

The result is a ranked list with a short rationale per repo.

#### Phase B — User Selection

The create wizard shows the ranked repo list as a checklist (AI suggestion pre-selected, user can override). For each repo: name, language, last push date, size, AI rationale, and a link to GitHub.

User selects one or more repos → system spawns one `git clone` job per selected repo into `targets/<name>/src/<repo-name>/`. Each clone job is tracked independently.

#### Path B — No repos found / manual source

If no GitHub repos are found in scope, or the user skips selection, Run Control shows `⚠ Source missing` before whitebox runs. Blackbox mode is unaffected.

**Private repos:** user clones manually into `./src` — out of scope for auto-fetch.

**target.json additions:**
```jsonc
{
  "github_repos": [
    {
      "url": "https://github.com/duckduckgo/zeroclickinfo-goodies",
      "source_path": "./src/zeroclickinfo-goodies",
      "cloned_at": "2026-04-05T10:05:00.000Z"
    }
  ]
}
```

**New API endpoints:**
```
GET  /api/targets/:target/repos          → github_repos.json (ranked list)
POST /api/targets/:target/repos/clone    → spawn clone jobs for selected repos
     body: { urls: ["https://github.com/..."] }
     response: { clone_jobs: [{ url, job_id }] }
```

**New script:** `scripts/scan-github-repos.js` — fetches metadata + writes `github_repos.json`. Called as a job from `/api/targets/create` after intel sync, or on-demand from the UI.

**`/api/targets/create` response extended:**
```jsonc
{ "job_id": "...", "sync_job_id": "...", "intel_job_id": "...", "repo_scan_job_id": "..." }
// clone_job_id is NOT in the create response — cloning is triggered separately
// after the user reviews the repo list
```

### 5.6 Theme System

CSS custom properties on `:root`. Dark (default) and light. Toggle in topbar. `localStorage` persisted. Scrollbars via `::-webkit-scrollbar` + `scrollbar-color` inheriting theme variables.

### 5.6 Modals

`modal.js`: `showAlert(msg)`, `showConfirm(msg) → Promise<bool>`, `showPrompt(msg, default) → Promise<string|null>`. Theme-aware, backdrop overlay, not draggable. Zero browser `alert/confirm/prompt` calls anywhere in the codebase.

---

## 6. Files Changed / Added

### New
```
ui/                               ← Vite project
scripts/lib/session.js
schemas/session.schema.json
tests/session.test.js
```

### Modified
```
scripts/new-target.js             ← accept --github-url, store in target.json
scripts/run-pipeline.js           ← ~150–200 lines (replace hitl.js calls, add session protocol)
scripts/lib/hitl.js               ← retired: the `require('./lib/hitl')` import is removed from run-pipeline.js as part of M1. The file may be kept on disk temporarily for reference but must not be imported anywhere by end of M1. Delete in M2 cleanup.
scripts/serve-intel-ui.js         ← session + settings endpoints; serve ui/dist/
package.json                      ← ui:dev (vite), ui:build (vite build), update ui:start
```

### Deleted / replaced
```
docs/intel-ui.html → ui/dist/index.html (built)
docs/intel-ui.css  → ui/src/style/
```

---

## 7. Milestones

### M1 — Functional workflow (de-risk first)

Deliverables:
- `session.js` + `session.schema.json` + `session-response.schema.json`
- `GET/POST /api/session/:target` + `GET /api/session/:target/stream` (SSE)
- Pipeline HITL replacement (remove `hitl.js` import, add three session checkpoints)
- Vite scaffold with two functional panels: Run Control (stepper + approval) and Metrics (live feed)
- `targets.js` panel: target create/list flow migrated to Vite, extended with GitHub auto-clone. Create wizard fields: program URL (H1/bbscope), target name (auto-filled), GitHub URL (optional). Four jobs spawned on create: scaffold + scope sync + intel sync + git clone (if GitHub URL provided). Progress shown inline with per-job status indicators.
- Run Control panel shows `⚠ Source missing` warning for whitebox runs when `./src` is empty and no `github_url` is set.

**M1 does not include:** private repo auth, drag-and-drop source upload.

At the end of M1: target creation, asset selection, plan approval, execution monitoring, and findings review all work from the browser. Terminal is optional.

### M2 — Visual layer
Window manager, animated graphs (Data Flow + Tech Stack), Settings editor, light theme, full panel set. M2 is additive — M1 remains stable throughout.

---

## 8. Out of Scope

- Rewriting researcher / triager / chain-coordinator agents
- WebSocket (SSE sufficient)
- Multi-user / auth
- Mobile native app
- SQLite migration
- CI/CD changes
