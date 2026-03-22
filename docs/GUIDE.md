# Agentic BugBounty — Complete Guide

---

> **Design philosophy**: this framework is built around **whitebox analysis** — clone the source, point the agent at it, get deep findings with file:line precision and working PoCs. Blackbox mode is supported for targets where source is unavailable, but whitebox is the primary mode and delivers significantly higher signal quality.

---

## Table of Contents

1. [How it works](#how-it-works)
2. [Analysis modes](#analysis-modes)
3. [Target workspace](#target-workspace)
4. [Running the pipeline](#running-the-pipeline)
5. [Live agent output](#live-agent-output)
6. [PoC artifacts and summary](#poc-artifacts-and-summary)
7. [Interactive finding review](#interactive-finding-review)
8. [Session resume (Claude Pro usage limits)](#session-resume-claude-pro-usage-limits)
9. [Intelligence sources](#intelligence-sources)
10. [bbscope](#bbscope)
11. [HackerOne intelligence](#hackerone-intelligence)
    - [Global disclosed dataset](#global-disclosed-dataset)
    - [Calibration dataset](#calibration-dataset)
12. [Intel UI](#intel-ui)
13. [Direct agent invocation](#direct-agent-invocation)
14. [JSON contracts](#json-contracts)
15. [Validation](#validation)
16. [Package scripts reference](#package-scripts-reference)
17. [Environment variables](#environment-variables)

---

## How it works

The pipeline runs two agents in sequence.

```mermaid
flowchart TD
    SRC["Source code (whitebox)\nor target URL (blackbox)"]
    R["Researcher"]
    B["report_bundle.json"]
    T["Triager"]
    NMI{"NEEDS MORE INFO?"}
    TR["triage_result.json"]
    H1["H1-ready reports"]

    SRC --> R
    R --> B
    B --> T
    T --> NMI
    NMI -- "yes (max 2 rounds)" --> R
    NMI -- no --> TR
    TR --> H1
```

**One command runs both agents.** `node scripts/run-pipeline.js` launches the Researcher, waits for it to finish, then automatically launches the Triager. You do not need to run them separately unless you want manual control.

**Researcher** operates in either whitebox (source available) or blackbox mode. It loads a structured threat model for the asset type, consumes a pre-built intelligence brief, runs grep patterns, reads source files, and produces a `report_bundle.json` with confirmed findings — each with a full PoC, CVSS score, and reproduction steps. If the target has multiple assets (e.g. a Chrome extension + a backend API), the Researcher runs a separate pass per asset, appending findings to the same bundle. The pipeline pauses between passes so you can review before continuing.

**Triager** runs six checks on every finding: scope, completeness, validity, CVSS reassessment, novelty (duplicate detection against HackerOne history), and submission decision. Findings that need clarification get flagged as `NEEDS_MORE_INFO`, which triggers a second Researcher pass. This loops up to `--max-nmi-rounds` times (default 2).

**Deterministic fallback**: if the Triager agent fails to write `triage_result.json`, the pipeline runs a local Node.js triage pass with the same six checks and H1 universal rules.

---

## Analysis modes

| | Whitebox | Blackbox |
|---|---|---|
| Source required | Yes — clone or copy | No |
| Finding precision | File:line exact | Endpoint / behavior |
| PoC quality | Code-level, self-contained | HTTP/script-based |
| Coverage | Full codebase | Exposed surface only |
| Recommended | **Yes** | When source unavailable |

Set in `target.json`:

```json
{
  "default_mode": "whitebox",
  "allowed_modes": ["whitebox", "blackbox"]
}
```

Or override at runtime:

```bash
node scripts/run-pipeline.js --target acme --mode whitebox
node scripts/run-pipeline.js --target acme --mode blackbox
```

---

## Target workspace

### Create automatically (recommended)

Pass `--target <name>` to the pipeline. If the workspace does not exist, the setup wizard runs:

```bash
node scripts/run-pipeline.js --target acme --cli claude
```

```
Target 'acme' not found. Starting setup wizard...

HackerOne program URL (Enter to skip): https://hackerone.com/acme
HackerOne program handle (Enter to skip): acme

Workspace created: targets/acme

Place your source files in:
  targets/acme/src

  • clone a repo:  git clone <url> "targets/acme/src/<repo-name>"
  • copy a folder: xcopy /E /I <src> "targets/acme/src\<name>"

Press Enter when the source is ready...

────────────────────────────────────────────────────────────
Assets detected: 2
────────────────────────────────────────────────────────────

[1/2] ./src/acme-extension
  Detected as : Chrome Extension (name: "Acme", v1.4.2, MV3)
  Type options: webapp | chromeext | mobileapp | executable
  Confirm type [Enter = chromeext] or type to override:
  Analysis mode [Enter = whitebox] or blackbox:
  → chromeext | whitebox

[2/2] ./src/acme-api
  Detected as : Web App (Node.js)
  Type options: webapp | chromeext | mobileapp | executable
  Confirm type [Enter = webapp] or type to override:
  Analysis mode [Enter = whitebox] or blackbox:
  → webapp | whitebox

────────────────────────────────────────────────────────────
Workspace ready: targets/acme
Assets configured: chromeext (./src/acme-extension), webapp (./src/acme-api)
────────────────────────────────────────────────────────────
```

The wizard:
1. Creates the workspace and shows where to place sources
2. Waits for you to clone/copy the repos
3. Scans every subdirectory in `src/` — detects asset type from marker files (`manifest.json` + `manifest_version`, `AndroidManifest.xml`, `build.gradle`, `next.config.js`, `go.mod`, PE/ELF magic bytes, etc.) and reads framework/version info where available
4. Shows each asset with its detected type and lets you confirm or override
5. Writes `target.json` with all assets — primary + `additional_assets`
6. Starts the pipeline

Multiple assets get separate Researcher passes. The pipeline pauses between passes so you can review findings before continuing.

### Create manually

```bash
node scripts/new-target.js <name>
# place source in targets/<name>/src/
node scripts/setup-target.js <name> --detect
```

### Workspace layout

```
targets/<name>/
├── target.json                          machine config
├── CLAUDE.md                            target notes for agents
├── run.sh / run.cmd                     convenience wrappers
├── src/                                 target source code
├── findings/
│   ├── confirmed/report_bundle.json     confirmed findings
│   ├── unconfirmed/candidates.json      unconfirmed candidates
│   ├── triage_result.json               triager verdicts
│   └── h1_submission_ready/*.md         HackerOne-ready reports
├── poc/
│   ├── EXT-001_slug.html                extracted PoC files
│   └── summary.md                       vulnerability summary
├── logs/
│   └── pipeline-*.log
└── intelligence/
    ├── agentic-bugbounty.db
    ├── h1_scope_snapshot.json
    ├── h1_vulnerability_history.json
    ├── h1_skill_suggestions.json
    ├── target_profile.json
    └── research_brief.json
```

### target.json

Minimal working config:

```json
{
  "schema_version": "1.0",
  "target_name": "Acme Corp",
  "asset_type": "webapp",
  "default_mode": "whitebox",
  "allowed_modes": ["whitebox", "blackbox"],
  "program_url": "https://hackerone.com/acme",
  "source_path": "./src",
  "findings_dir": "./findings",
  "h1_reports_dir": "./findings/h1_submission_ready",
  "logs_dir": "./logs",
  "intelligence_dir": "./intelligence",
  "hackerone": {
    "program_handle": "acme",
    "sync_enabled": true
  },
  "scope": {
    "in_scope": ["*.acme.com"],
    "out_of_scope": ["Self-XSS", "DoS"]
  },
  "rules": [
    "Never modify files in ./src",
    "Never test against production",
    "Confirm every finding dynamically before reporting"
  ]
}
```

Multi-asset config:

```json
{
  "asset_type": "chromeext",
  "source_path": "./src/acme-extension",
  "additional_assets": [
    { "asset_type": "webapp", "source_path": "./src/acme-backend" }
  ]
}
```

**Asset types:** `webapp` `mobileapp` `chromeext` `executable`

**Report ID prefixes:** `WEB-NNN` `MOB-NNN` `EXT-NNN` `EXE-NNN`

---

## Running the pipeline

```bash
node scripts/run-pipeline.js --target <name> --cli claude
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--target <name>` | — | Target name under `targets/` |
| `--cli claude\|codex` | `claude` | Agent backend |
| `--model <id>` | model default | Override model |
| `--asset <type>` | from target.json | Override asset type |
| `--mode whitebox\|blackbox` | from target.json | Override analysis mode |
| `--interactive` | off | Manual finding review before triage |
| `--max-nmi-rounds <n>` | 2 | Max NEEDS_MORE_INFO feedback loops |

**Environment overrides:**

```bash
AGENTIC_CLI=claude
AGENTIC_MODEL=claude-opus-4-6
```

**Per-target wrappers** (generated automatically):

```bash
# Linux / macOS
./targets/<name>/run.sh --cli claude

# Windows
targets\<name>\run.cmd --cli claude
```

---

## Live agent output

The pipeline streams every tool call as it happens:

```
[2026-03-20T20:08:07Z] → Starting researcher[chromeext] agent
  [  12s] Bash       grep -r "postMessage" src/ --include="*.js"
  [  18s] Read       src/background/messaging.js
  [  34s] Grep       eval( src/
  [ 774s] Write      targets/acme/findings/confirmed/report_bundle.json

  [done] 774s | 87 tool call(s) | $1.2340 | in: 45.2k | out: 8.1k | cache_read: 182.3k | cache_create: 12.4k

[2026-03-20T20:21:22Z] ← researcher[chromeext] agent done in 774s
```

When the agent is reasoning between tool calls, a heartbeat fires every 15 seconds:

```
  ⏱  45s | 12 tool call(s)...
```

After the Researcher completes, the pipeline prints the next command:

```
────────────────────────────────────────────────────────────────────────
Researcher done — 3 finding(s) confirmed.

To run the triager now:
  /triager --asset chromeext

Or run the full pipeline (researcher + triager) in one shot:
  node scripts/run-pipeline.js --target acme --cli claude
────────────────────────────────────────────────────────────────────────
```

Token usage and cost are logged to `logs/pipeline-*.log` at the end of each agent phase.

---

## PoC artifacts and summary

After the Researcher phase, the pipeline automatically writes:

```
targets/<name>/poc/
  EXT-001_javascript_code_injection_via_url_path.html
  EXT-002_csp_bypass_via_inline_script.js
  summary.md
```

`summary.md` contains:
- target metadata table
- analysis stats
- findings overview table (all findings at a glance)
- full detail section per finding: CVSS, CWE, component, steps, impact, remediation, observed result

**Run standalone:**

```bash
node scripts/render-poc-artifacts.js findings/confirmed/report_bundle.json --poc-dir targets/<name>/poc
```

Or:

```bash
npm run poc:render
```

---

## Interactive finding review

Add `--interactive` to pause after the Researcher and review each finding before triage:

```bash
node scripts/run-pipeline.js --target acme --cli claude --interactive
```

```
────────────────────────────────────────────────────────────────────────
MANUAL REVIEW — 3 finding(s) to validate before triage
────────────────────────────────────────────────────────────────────────

▶ [EXT-001] Content script postMessage handler lacks origin validation
   Severity  : High
   Component : background/messaging.js:47
   Summary   : Any frame can dispatch messages to the background page...
   PoC type  : js_console
   [y] approve  [n] reject  [v] view full PoC →
```

`[v]` expands the full PoC and step list in-place. `[n]` removes the finding from the bundle before the Triager sees it.

---

## Session resume (Claude Pro usage limits)

Claude Pro sessions have a rolling usage cap. If the cap hits mid-run, the pipeline detects it automatically, saves a checkpoint, and tells you exactly what to run when the session resets.

### How it works

1. `spawnClaude` streams JSON events from the agent
2. On `SessionLimitError` detected in the stream:
   - saves `targets/<name>/logs/checkpoint.json`
   - prints the exact resume command
   - exits cleanly
3. When the session resets, run with `--resume`:
   - if phase was **researcher**: skips completed assets, injects resume hint into prompt
   - if phase was **triage**: skips researcher loop, re-runs triage on existing bundle
4. On clean completion, checkpoint is deleted

### What gets saved

The checkpoint lives at `targets/<name>/logs/checkpoint.json`:

```json
{
  "phase": "researcher",
  "assetIndex": 0,
  "asset": "chromeext",
  "totalAssets": 1,
  "findingsCount": 3,
  "savedAt": "2026-03-21T22:00:00.000Z"
}
```

Everything written to `findings/confirmed/report_bundle.json` before the limit hit is preserved — the researcher picks up from where it stopped and is instructed not to re-analyse already-confirmed findings.

### When a limit hits

```
════════════════════════════════════════════════════════════════════════
SESSION LIMIT REACHED

Claude Pro usage cap hit during the researcher phase.
Checkpoint saved — no work lost.
  Checkpoint : targets/acme/logs/checkpoint.json

When your session resets, resume with:

  node scripts/run-pipeline.js --target acme --cli claude --resume

The pipeline will pick up exactly where it stopped.
════════════════════════════════════════════════════════════════════════
```

### Resuming

```bash
node scripts/run-pipeline.js --target acme --cli claude --resume
```

On resume the pipeline:

1. Loads `checkpoint.json` and prints what it found
2. If phase was `researcher`: skips assets already completed, injects a resume hint into the agent prompt (`N findings already confirmed, continue from where you left off`)
3. If phase was `triage`: skips the researcher loop entirely, re-runs triage on the existing bundle
4. On clean completion, deletes the checkpoint

### Notes

- `--resume` with no checkpoint is a no-op — the pipeline starts fresh
- Intelligence syncs (bbscope, HackerOne) are skipped on resume (already current)
- If you want to force a full re-run despite a checkpoint, delete `targets/<name>/logs/checkpoint.json` and run without `--resume`

---

## Intelligence sources

### Intelligence flow

```mermaid
flowchart TD
    BBSCOPE["bbscope.com\n(no auth)"]
    H1API["HackerOne API\n(credentials)"]
    GDB["Global DB\ndata/global-intelligence/"]
    LDB["Target DB\ntargets/name/intelligence/"]
    BRIEF["research_brief.json"]
    R["Researcher"]

    BBSCOPE -- "bbscope:sync" --> LDB
    H1API -- "h1:bootstrap / h1:disclosed" --> GDB
    H1API -- "h1:sync" --> LDB
    GDB --> BRIEF
    LDB --> BRIEF
    BRIEF --> R
```

---

## bbscope

[bbscope.com](https://bbscope.com) aggregates scope data from HackerOne, Bugcrowd, Intigriti, and YesWeHack — no API credentials required.

Use it to populate scope for any program, regardless of platform.

### Check connectivity

```bash
npm run bbscope:doctor
```

### Sync scope for a target

```bash
node scripts/sync-bbscope-intel.js --target <name>
# or
npm run bbscope:sync
```

Auto-detects platform from `program_url` in `target.json`. Override with `--platform`:

```bash
node scripts/sync-bbscope-intel.js --target <name> --platform bc   # Bugcrowd
node scripts/sync-bbscope-intel.js --target <name> --platform h1   # HackerOne
node scripts/sync-bbscope-intel.js --target <name> --platform it   # Intigriti
node scripts/sync-bbscope-intel.js --target <name> --platform ywh  # YesWeHack
```

Or specify the program handle directly:

```bash
node scripts/sync-bbscope-intel.js --target <name> --platform bc --handle my-program
```

Writes to `targets/<name>/intelligence/`:
- `bbscope_scope_snapshot.json`
- `agentic-bugbounty.db` (shared with H1 sync — scopes tagged `source: bbscope_<platform>`)

---

## HackerOne intelligence

### Setup

```bash
export H1_API_USERNAME="your_api_username"
export H1_API_TOKEN="your_api_token"
```

Check connectivity:

```bash
npm run h1:doctor
```

### Target-local sync

Fetches structured scope, accessible history, and derived skill suggestions for the target:

```bash
node scripts/sync-hackerone-intel.js --target <name>
# or
npm run h1:sync
```

Writes to `targets/<name>/intelligence/`.

Auto-runs at pipeline start when `hackerone.sync_enabled: true` in `target.json` and credentials are present.

### Global disclosed dataset

Builds a cross-program dataset from publicly disclosed HackerOne reports:

```bash
npm run h1:disclosed         # incremental sync
npm run h1:bootstrap         # full history backfill
```

Full history with a date window:

```bash
node scripts/sync-hackerone-disclosed.js --full-history --start-date 2025-01-01 --end-date 2026-01-01 --window-days 31
```

Writes to `data/global-intelligence/`.

### Calibration dataset

After syncing disclosed reports, build a queryable calibration index with severity distributions and real disclosure examples:

```bash
npm run calibration:sync
```

This classifies all 12,000+ disclosed reports by `(asset_type, vuln_class)` and aggregates:
- Severity distributions (critical/high/medium/low counts)
- Typical CWE and weakness per class
- Top programs by disclosure volume
- Real `hacktivity_summary` excerpts stored as behavior examples

Query the data:

```bash
# Severity distribution for all chromeext vuln classes
node scripts/query-calibration.js --asset chromeext

# Specific class, JSON output (for agent piping)
node scripts/query-calibration.js --asset webapp --vuln xss --json

# Real H1 report summaries — how researchers described the vuln and what triage validated
node scripts/query-calibration.js --asset webapp --vuln xss --behaviors --limit 5

# All asset types
node scripts/query-calibration.js --all
```

The **Researcher** queries this before touching the target (Phase 0) to bias module loading toward historically rewarded vuln classes and read real disclosure examples.

The **Triager** queries this at Check 4.5 to cross-check the researcher's severity claim against historical H1 triage outcomes for the same `(asset_type, vuln_class)` combination.

### Research brief

Build the intelligence brief the Researcher reads before touching the target:

```bash
node scripts/build-research-brief.js --target <name>
# or
npm run research:brief
```

Get prioritized research focus suggestions:

```bash
node scripts/recommend-research-focus.js --target <name>
# or
npm run research:focus
```

---

## Intel UI

```bash
node scripts/serve-intel-ui.js --target <name> --port 31337 --open
# or
npm run ui:intel
```

Open `http://127.0.0.1:31337`.

Includes: target config, structured scope, local history, skill suggestions, global DB navigator with search/filters/pagination, file browser.

---

## Direct agent invocation

The agents are Claude Code slash commands. You can invoke them directly inside a Claude Code session:

```
/researcher --asset chromeext --mode whitebox ./src
/triager --asset chromeext
```

Optional flags for the Researcher:

```
/researcher --asset webapp --mode whitebox ./src --vuln cors,graphql --bypass xss_filter_evasion
```

`--vuln` loads specialized vulnerability modules (e.g. `cors`, `graphql`, `prototype_pollution`, `oauth`, `ssrf`).
`--bypass` loads filter evasion modules (e.g. `xss_filter_evasion`, `sqli_filter_evasion`, `waf_evasion`).

Bypass modules also auto-load on trigger conditions — HTTP 403 loads `waf_evasion`, blocked XSS payload loads `xss_filter_evasion + encoding`.

### Compose prompts manually (Codex)

```bash
node scripts/compose-agent-prompt.js researcher --asset chromeext --mode whitebox --target <name>
node scripts/compose-agent-prompt.js triager --asset chromeext --target <name>
```

---

## JSON contracts

### report_bundle.json (Researcher output)

```
meta.schema_version      "2.0"
meta.asset_type          webapp | mobileapp | chromeext | executable
findings[]
  report_id              WEB-001 / MOB-001 / EXT-001 / EXE-001
  finding_title
  severity_claimed       Critical | High | Medium | Low | Informative
  cvss_vector_claimed    CVSS:3.1/...
  cvss_score_claimed     0.0–10.0
  cwe_claimed            CWE-NNN: name
  vulnerability_class
  affected_component     file:line or endpoint
  summary
  steps_to_reproduce[]   ≥3 steps for confirmed findings
  poc_code               full self-contained PoC
  poc_type               html | curl | python | js_console | burp_request | gdb | other
  observed_result
  impact_claimed
  remediation_suggested
  vulnerable_code_snippet
    file                 relative path to vulnerable file
    line_start           start line (integer)
    line_end             end line (integer)
    snippet              verbatim source lines — copied exactly from the file
    annotation           one sentence: which line is the root cause and why
  attack_flow_diagram    Mermaid sequenceDiagram or flowchart LR showing attacker→sink chain
  researcher_notes
  confirmation_status    confirmed | unconfirmed
```

### triage_result.json (Triager output)

```
results[]
  report_id
  triage_verdict         TRIAGED | NOT_APPLICABLE | NEEDS_MORE_INFO | DUPLICATE | INFORMATIVE
  ready_to_submit        true | false
  analyst_severity
  analyst_cvss_score
  analyst_cvss_vector
  cwe_confirmed
  triage_summary
  nmi_questions[]        populated when verdict = NEEDS_MORE_INFO
  duplicate_of           populated when verdict = DUPLICATE
  checks{}
    scope_pass
    complete_pass
    valid_pass
    cvss_pass
    novelty_pass
```

### Triage decision flow

```mermaid
flowchart TD
    F["Finding"]
    S{"Scope\ncheck"}
    C{"Complete\ncheck"}
    V{"Valid\nPoC?"}
    CV{"CVSS\ncheck"}
    N{"Novelty\ncheck"}
    OK["✅ TRIAGED\nready_to_submit: true"]
    NA["❌ NOT_APPLICABLE"]
    NMI["🔁 NEEDS_MORE_INFO"]
    DUP["🔁 DUPLICATE"]

    F --> S
    S -- fail --> NA
    S -- pass --> C
    C -- fail --> NMI
    C -- pass --> V
    V -- fail --> NA
    V -- pass --> CV
    CV --> N
    N -- duplicate --> DUP
    N -- novel --> OK
```

### H1 universal auto-reject rules

Findings are automatically marked `NOT_APPLICABLE` if they are:
- Self-XSS without an external attack vector
- DoS / rate limiting
- Theoretical without a working PoC
- Missing security headers without demonstrated exploitability

---

## Validation

```bash
node scripts/validate-bundle.js findings/confirmed/report_bundle.json
node scripts/validate-triage-result.js findings/triage_result.json findings/confirmed/report_bundle.json
node scripts/validate-target-config.js targets/<name>/target.json
npm test
```

All validation runs automatically during the pipeline. Failures abort the run.

---

## Package scripts reference

| Command | Description |
|---------|-------------|
| `npm test` | Run contract regression tests (18 tests) |
| `npm run pipeline` | Run pipeline for the default target |
| `npm run poc:render` | Extract PoC files + summary.md from bundle |
| `npm run reports:render` | Render H1-ready markdown from bundle + triage |
| `npm run h1:doctor` | Check H1 API credentials |
| `npm run h1:sync` | Sync target-local intel from H1 |
| `npm run h1:disclosed` | Incremental sync of global disclosed reports |
| `npm run h1:bootstrap` | Full history backfill of global disclosed reports |
| `npm run calibration:sync` | Classify disclosed reports into calibration patterns + behavior examples |
| `npm run calibration:query` | Query the calibration dataset (human table output) |
| `npm run target:new` | Create a new target workspace scaffold |
| `npm run target:setup` | Detect and configure assets in existing workspace |
| `npm run target:profile` | Build target profile JSON |
| `npm run research:brief` | Build researcher intel brief |
| `npm run research:focus` | Get prioritized research focus suggestions |
| `npm run ui:intel` | Serve local intel UI on port 31337 |
| `npm run validate:bundle` | Validate report_bundle.json against schema |
| `npm run validate:triage` | Validate triage_result.json against schema |
| `npm run validate:target` | Validate target.json against schema |

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `H1_API_USERNAME` or `HACKERONE_API_USERNAME` | HackerOne API username |
| `H1_API_TOKEN` or `HACKERONE_API_TOKEN` | HackerOne API token |
| `AGENTIC_CLI` | Default CLI backend (`claude` or `codex`) |
| `AGENTIC_MODEL` | Default model override |
