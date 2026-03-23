# RESEARCHER AGENT — Entry Point
# Usage: /researcher --asset [webapp|mobileapp|browserext|executable] --mode [whitebox|blackbox] [path_or_url]

## STARTUP SEQUENCE

Parse $ARGUMENTS for --asset and --mode flags.

If --asset is missing, ask:
  "Which asset type are you analyzing?
   [1] webapp      (PHP, Node, Python, Java, JSP, Ruby — any web application)
   [2] mobileapp   (Android APK or iOS IPA)
   [3] browserext   (Browser extension — Chrome, Firefox, or Edge — MV2/MV3)
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
| bac | asset/webapp/vuln/broken_access_control.md |
| domxss | asset/webapp/vuln/dom_xss.md |
| email | asset/webapp/vuln/email_injection.md |
| jwt | asset/webapp/vuln/jwt.md |
| nextjs | asset/webapp/vuln/nextjs_ssrf.md |
| firebase | shared/vuln/firebase.md |
| pdf | asset/webapp/vuln/pdf_ssrf.md |
| latex | asset/webapp/vuln/latex_injection.md |
| xslt | asset/webapp/vuln/xslt_injection.md |
| ssi | asset/webapp/vuln/ssi_injection.md |
| domclob | asset/webapp/vuln/dom_clobbering.md |
| orm | asset/webapp/vuln/orm_leak.md |
| juggling | asset/webapp/vuln/type_juggling.md |
| hpp | asset/webapp/vuln/hpp.md |
| csv | asset/webapp/vuln/csv_injection.md |
| zipslip | asset/webapp/vuln/zip_slip.md |
| xsleak | asset/webapp/vuln/xs_leak.md |
| dnsrebind | asset/webapp/vuln/dns_rebinding.md |

Example: /researcher --asset webapp --mode whitebox --vuln graphql ./src
Example: /researcher --asset webapp --mode whitebox --vuln bac ./src
Example: /researcher --asset webapp --mode whitebox --vuln domxss ./src
Example: /researcher --asset webapp --mode blackbox --vuln email https://target.com
Example: /researcher --asset webapp --mode blackbox --vuln jwt https://target.com
Example: /researcher --asset webapp --mode blackbox --vuln nextjs https://target.com
Example: /researcher --asset webapp --mode blackbox --vuln pdf https://target.com

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
