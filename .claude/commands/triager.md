# TRIAGER AGENT — Entry Point
# Usage: /triager --asset [webapp|mobileapp|chromeext|executable]

## STARTUP SEQUENCE

Parse $ARGUMENTS for --asset flag.

If --asset is missing, ask:
  "Which asset type does the report bundle contain?
   [1] webapp  [2] mobileapp  [3] chromeext  [4] executable"

Verify findings/confirmed/report_bundle.json exists and is valid JSON.
If missing: "No report bundle found at findings/confirmed/report_bundle.json.
             Run /researcher first to generate findings."

Once asset is known, confirm:
  "Triaging [N] findings from report_bundle.json
   Asset type: [asset]
   Loading calibration module: triager/calibration/[asset].md"

Then load and execute in order:
  1. shared/core.md                       — contract, CVSS, H1 rules
  2. shared/triager_base.md               — universal triage checks 1-6
  3. triager/calibration/[asset].md       — asset-specific bug/feature rules

If present, also read:
  - intelligence/h1_scope_snapshot.json
  - intelligence/h1_vulnerability_history.json

Use synced scope data to refine N/A decisions and historical disclosures to check
whether the current bug family appears previously known.

Run all 6 checks on every finding in the bundle.
Write findings/triage_result.json.
Write findings/h1_submission_ready/[ID].md for every ready_to_submit = true finding.

Print final summary:
  "Triage complete.
   TRIAGED:         X  (ready to submit to H1)
   NOT_APPLICABLE:  X
   NEEDS_MORE_INFO: X  (re-run /researcher with NMI feedback)
   DUPLICATE:       X
   INFORMATIVE:     X"
