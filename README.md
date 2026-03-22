# Agentic BugBounty

Experimental AI-driven security research framework for bug bounty work.

Two agents. One pipeline. No amnesia.

- **Researcher** — hunts the target, validates candidates, writes evidence
- **Triager** — challenges every finding, checks scope and plausibility, decides what survives
- **Dual Researcher** — a second AI model cross-checks the first pass for anything missed

→ [Full documentation](docs/GUIDE.md) · [Blog post](https://www.locu.uk/gui.html#/blog/2026/2026-03-agentic-bugbounty)

---

## Requirements

- Node.js 24+
- Claude Code CLI (`claude`)
- OpenRouter API key(s) — optional, enables dual researcher + CVE LLM analysis

---

## Setup

```bash
git clone https://github.com/xlocux/Agentic-BugBounty.git
cd Agentic-BugBounty
cp .env.example .env        # fill in credentials
npm test                    # 18 contract tests — should all pass
```

---

## Common commands

### Start a new target

```bash
node scripts/run-pipeline.js --target <name> --cli claude
```

First run launches a setup wizard — creates workspace, detects assets, starts the pipeline.

### Resume after a Claude Pro session limit

```bash
node scripts/run-pipeline.js --target <name> --cli claude --resume
```

### Manual finding review before triage

```bash
node scripts/run-pipeline.js --target <name> --cli claude --interactive
```

### Re-run triage only (existing bundle)

```bash
/triager --asset <type>
```

### Reset a target (wipe findings, keep source)

```bash
node scripts/reset-target.js --target <name>
```

### Render reports from existing bundle

```bash
npm run reports:render
npm run poc:render
```

---

## Intelligence setup (optional but recommended)

```bash
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

### OpenRouter keys (free tier — enables dual researcher + CVE analysis)

```bash
# In .env:
OPENROUTER_API_KEY=your_key
OPENROUTER_API_KEY_1=key1     # up to 5 keys — auto-rotated on 401/429
OPENROUTER_API_KEY_2=key2
```

Models and fallback order configured in `config/openrouter.json`.

---

## What you get after a run

```
targets/<name>/
  findings/
    confirmed/report_bundle.json   confirmed findings (JSON)
    triage_result.json             triager verdicts
    h1_submission_ready/*.md       HackerOne-ready reports
  poc/
    EXT-001_slug.html              extracted PoC per finding
    summary.md                     full vulnerability summary
```

---

→ **[docs/GUIDE.md](docs/GUIDE.md)** — all commands, config, schemas, architecture
