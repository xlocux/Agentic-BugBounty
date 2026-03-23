# Bug Bounty Agent Framework
# Workspace-level instructions — Claude Code reads this automatically on startup

## Overview
This framework provides modular AI agents for security research across four asset types.
All agents share a universal JSON contract (`REPORT_BUNDLE`) enabling cross-tool pipelines.

## Invocation

### Researcher agent
```
/researcher --asset [webapp|mobileapp|browserext|executable] --mode [whitebox|blackbox] [path_or_url]
```
If `--asset` or `--mode` are omitted, the agent will ask interactively before starting.

### Triager agent
```
/triager --asset [webapp|mobileapp|browserext|executable]
```
Reads `findings/confirmed/report_bundle.json` automatically.

### Examples
```
/researcher --asset webapp --mode whitebox ./src
/researcher --asset browserext --mode whitebox ./extension
/researcher --asset mobileapp --mode blackbox com.example.app
/researcher --asset executable --mode whitebox ./bin/target
/triager --asset webapp
```

## Output paths

When invoked via the pipeline (`run-pipeline.js`), absolute paths are injected into the prompt — use those.
When invoked directly via slash command, use paths relative to the current working directory:

| File | Description |
|---|---|
| `findings/confirmed/report_bundle.json` | Researcher output — confirmed findings |
| `findings/unconfirmed/candidates.json` | Researcher output — unconfirmed candidates |
| `findings/triage_result.json` | Triager output — verdicts + summaries |
| `findings/h1_submission_ready/[ID].md` | Final reports ready for HackerOne |
| `logs/pipeline-*.log` | Runtime validation + orchestration logs |

## Runtime validation
- `node scripts/validate-bundle.js findings/confirmed/report_bundle.json`
- `node scripts/validate-triage-result.js findings/triage_result.json findings/confirmed/report_bundle.json`
- `node scripts/validate-target-config.js targets/<name>/target.json`
- `node --test --test-isolation=none tests/contracts.test.js`

## Asset report ID prefix
| Asset | Prefix | Example |
|---|---|---|
| webapp | WEB | WEB-001 |
| mobileapp | MOB | MOB-001 |
| browserext | EXT | EXT-001 |
| executable | EXE | EXE-001 |

## Global rules
- Never modify source files in the target directory
- Never test against production environments
- Confirm every finding dynamically before including in `REPORT_BUNDLE`
- Self-XSS, DoS, and theoretical findings without PoC are always out of scope
- Keep `target.json` aligned with the target-specific `CLAUDE.md` notes

## Recommended model
`claude-opus-4-5` for both agents (complex multi-step reasoning required)
