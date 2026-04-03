# Agentic BugBounty

Experimental AI-driven security research framework for bug bounty work.

Seven stages. Six specialist domains. One pipeline.

- **Stage 0** — deterministic file triage (relevance scoring, language detection)
- **Stage 1** — surface mapping (LLM-driven entry point and sink extraction)
- **Stage 1.5** — git intelligence (commit mining, author mapping, secret scan)
- **Stage 2** — six specialist researcher agents: AUTH · INJECT · CLIENT · ACCESS · MEDIA · INFRA
- **Stage 2.5** — chain coordinator (primitive chaining across domain findings)
- **Explorer** — parallel surface mapper (dep analysis, JS endpoint extraction, HTTP fingerprinting)
- **Triager** — challenges every finding, checks scope and plausibility, decides what survives

→ [Full documentation](docs/GUIDE.md) · [Blog post](https://www.locu.uk/gui.html#/blog/2026/2026-03-agentic-bugbounty)

---

## Requirements

- Node.js 24+
- Claude Code CLI (`claude`)
- OpenRouter API key(s) — optional, enables Explorer and CVE analysis

---

## Setup

```bash
git clone https://github.com/xlocux/Agentic-BugBounty.git
cd Agentic-BugBounty
cp .env.example .env        # fill in credentials
npm test                    # contract tests — should all pass
```

---

## Common commands

### Start a new target

```bash
node scripts/run-pipeline.js --target <name> --cli claude
```

First run launches a setup wizard — creates workspace, detects assets, starts the pipeline.

### Interactive mode (Phase 0 onboarding + HITL review)

```bash
node scripts/run-pipeline.js --target <name> --cli claude --interactive
```

Phase 0 runs a structured Q&A session (scope, focus, CVE context, credentials) before the pipeline starts. Add `--hitl` to enable manual review checkpoints after Explorer and after each Researcher pass.

### Human-in-the-loop checkpoints

```bash
node scripts/run-pipeline.js --target <name> --cli claude --hitl
```

Pauses at three points: after Explorer surface map, after each Researcher domain, before Triage.

### Resume after a session limit or Ctrl+C

```bash
node scripts/run-pipeline.js --target <name> --cli claude --resume
```

Both Claude Pro session limits and manual `Ctrl+C` interruptions save a checkpoint. The pipeline resumes from the interrupted phase — confirmed findings already in `report_bundle.json` are never lost.

### Re-run triage only (existing bundle)

```bash
/triager --asset <type>
```

### Render reports from existing bundle

```bash
npm run reports:render
npm run poc:render
```

### Reset a target (wipe findings, keep source)

```bash
node scripts/reset-target.js --target <name>
```

### Export training dataset

```bash
npm run dataset:export          # append all sessions to dataset/
npm run dataset:export:new      # fresh export (overwrites)
npm run dataset:stats           # show type A/B/C counts
```

---

## Intelligence setup (optional but recommended)

```bash
# Sync scope from bbscope.com (no credentials — HackerOne, Bugcrowd, Intigriti, YesWeHack)
node scripts/sync-bbscope-intel.js --target <name>

# H1 credentials → sync scope + history for target
npm run h1:doctor
npm run h1:sync

# Bootstrap global disclosed dataset (12k+ reports, run once)
npm run h1:bootstrap
npm run calibration:sync

# CVE intel for a specific target
node scripts/sync-cve-intel.js --target <name>

# Extract hacker skill patterns from disclosed reports (needs LLM backend)
npm run calibration:extract-skills
```

### OpenRouter keys (free tier — enables Explorer, CVE analysis)

```bash
# In .env:
OPENROUTER_API_KEY=your_key
OPENROUTER_API_KEY_1=key1     # up to 5 keys — auto-rotated on 401/429/busy
OPENROUTER_API_KEY_2=key2
```

Models and fallback order configured in `config/openrouter.json`.
The framework skips unavailable models (HTTP 404) immediately and rotates to the next one.

---

## What you get after a run

```
targets/<name>/
  findings/
    confirmed/report_bundle.json   confirmed findings (JSON)
    unconfirmed/candidates.json    unconfirmed candidates
    candidates_pool_AUTH.json      per-domain candidate shards
    triage_result.json             triager verdicts
    h1_submission_ready/*.md       HackerOne-ready reports
  poc/
    EXT-001_slug.html              extracted PoC per finding
    summary.md                     full vulnerability summary
  logs/
    pipeline-*.log                 run log with token usage
    agents/                        per-domain status files
dataset/
  surface_extraction.jsonl         Type A training examples
  candidate_triage.jsonl           Type B training examples
  chain_hypothesis.jsonl           Type C training examples
```

---

→ **[docs/GUIDE.md](docs/GUIDE.md)** — all commands, config, schemas, architecture
