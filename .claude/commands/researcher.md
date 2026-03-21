# RESEARCHER AGENT — Entry Point
# Usage: /researcher --asset [webapp|mobileapp|chromeext|executable] --mode [whitebox|blackbox] [path_or_url]

## STARTUP SEQUENCE

Parse $ARGUMENTS for --asset and --mode flags.

If --asset is missing, ask:
  "Which asset type are you analyzing?
   [1] webapp      (PHP, Node, Python, Java, JSP, Ruby — any web application)
   [2] mobileapp   (Android APK or iOS IPA)
   [3] chromeext   (Chrome, Firefox, or Edge browser extension)
   [4] executable  (ELF, PE, Mach-O binary)"

If --mode is missing, ask:
  "What type of analysis?
   [1] whitebox  (you have the source code)
   [2] blackbox  (live target only, no source)"

Once both are known, confirm:
  "Starting [mode] analysis on [asset] target: [path_or_url]
   Report prefix will be: [PREFIX]-NNN
   Output: findings/confirmed/report_bundle.json"

Then load and execute in order:
  1. shared/core.md              — contract, CVSS, H1 rules
  2. shared/researcher_[mode].md — base methodology for chosen mode
  3. asset/[asset]/module.md     — asset-specific threat model and grep patterns

If present, also read:
  - intelligence/h1_scope_snapshot.json
  - intelligence/h1_vulnerability_history.json
  - intelligence/h1_skill_suggestions.json

Use those files to prioritize historically relevant vuln classes, avoid out-of-scope
surfaces, and decide which focused modules to load first.

Execute all phases defined in the loaded modules.
Produce REPORT_BUNDLE at findings/confirmed/report_bundle.json.
Produce unconfirmed candidates at findings/unconfirmed/candidates.json.

## OPTIONAL --vuln FLAG

If --vuln [module] is specified, load the corresponding focused module
in addition to the standard asset module:

| --vuln value | Module loaded |
|---|---|
| graphql | asset/webapp/vuln/graphql.md |
| pp | asset/webapp/vuln/prototype_pollution.md |
| postmessage | asset/[asset]/vuln/postmessage.md |
| wcp | asset/webapp/vuln/web_cache_poisoning.md |
| smuggling | asset/webapp/vuln/http_smuggling.md |
| cors | asset/webapp/vuln/cors.md |
| supplychain | shared/vuln/supply_chain.md |

Example: /researcher --asset webapp --mode whitebox --vuln graphql ./src

## OPTIONAL --bypass FLAG

When a payload is being blocked, load bypass modules to extend the attack:

| --bypass value | Module loaded |
|---|---|
| `encoding` | shared/bypass/encoding.md |
| `xss` | shared/bypass/xss_filter_evasion.md |
| `sqli` | shared/bypass/sqli_filter_evasion.md |
| `ssrf` | shared/bypass/ssrf_filter_evasion.md |
| `auth` | shared/bypass/auth_bypass.md |
| `waf` | shared/bypass/waf_evasion.md |
| `all` | all bypass modules |

Example:
  /researcher --asset webapp --mode blackbox --bypass xss,waf https://target.com
  /researcher --asset webapp --mode whitebox --bypass sqli ./src

AUTO-LOAD TRIGGERS:
- If dynamic confirmation fails with HTTP 403/406 → auto-load waf_evasion.md
- If XSS candidate found but payload blocked → auto-load xss_filter_evasion.md + encoding.md
- If SQLi candidate found but payload blocked → auto-load sqli_filter_evasion.md + encoding.md
- If SSRF candidate found but blocked → auto-load ssrf_filter_evasion.md
- If auth endpoint found → auto-load auth_bypass.md
