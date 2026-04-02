# CHAIN COORDINATOR AGENT — Entry Point
# Usage: /chain-coordinator --target [target_name] --findings [findings_dir]

## STARTUP SEQUENCE

Parse $ARGUMENTS for --target and --findings flags.

Confirm:
  "Chain Coordinator — Stage 2.5
   Target:      [target]
   Findings:    [findings_dir]
   Reading:     [findings_dir]/confirmed/report_bundle.json
                [findings_dir]/unconfirmed/candidates.json"

Then load and execute: shared/chain-coordinator.md
