# Agentic BugBounty

Experimental AI-driven research framework for bug bounty work.

Two agents. One pipeline. No amnesia.

- **Researcher** — hunts the target, validates candidates, writes evidence
- **Triager** — challenges every finding, checks scope and plausibility, decides what survives

A single pipeline command runs **both agents in sequence** — researcher first, then triager automatically. No second command needed.

Each target gets persistent intelligence (local SQLite + HackerOne sync). Each run starts from where the last one left off.

→ [Blog post](https://www.locu.uk/gui.html#/blog/2026/2026-03-agentic-bugbounty)
→ [Full documentation](docs/GUIDE.md)

---

## Requirements

- Node.js 24+
- Claude Code CLI (`claude`)

---

## Quickstart

```bash
git clone https://github.com/xlocux/Agentic-BugBounty.git
cd Agentic-BugBounty
npm test
```

### Run against a target

```bash
node scripts/run-pipeline.js --target <name> --cli claude
```

This runs the **full pipeline**: Researcher → (optional manual review) → Triager → H1-ready reports.

If `<name>` does not exist yet, the pipeline runs a setup wizard — asks for the program details, creates the workspace, waits for you to place the source files, auto-detects every asset in `src/` with type and framework info, asks you to confirm or correct each one, then starts.

### Run with manual finding review

```bash
node scripts/run-pipeline.js --target <name> --cli claude --interactive
```

After the Researcher finishes, the pipeline pauses and walks you through each finding before handing off to the Triager.

### Session resume (Claude Pro)

If a Claude Pro usage cap hits mid-run, the pipeline saves a checkpoint and prints the exact command to resume:

```bash
node scripts/run-pipeline.js --target <name> --cli claude --resume
```

The pipeline picks up from the exact phase and asset index where it stopped. No work lost.

---

## What you get after a run

```
targets/<name>/
  findings/
    confirmed/report_bundle.json     — confirmed findings (JSON contract)
    triage_result.json               — triager verdicts
    h1_submission_ready/*.md         — HackerOne-ready reports
  poc/
    <ID>_<slug>.<ext>                — extracted PoC files per finding
    summary.md                       — vulnerability summary in Markdown
  intelligence/
    research_brief.json              — pre-run intel brief
    h1_scope_snapshot.json           — in-scope assets
    h1_vulnerability_history.json    — target history
```

---

## HackerOne credentials (optional)

Only needed for scope/history sync. Set either:

```bash
export H1_API_USERNAME="..."
export H1_API_TOKEN="..."
```

Verify with:

```bash
npm run h1:doctor
```

---

## Full documentation

All commands, config options, schemas, and architecture details:

→ **[docs/GUIDE.md](docs/GUIDE.md)**
