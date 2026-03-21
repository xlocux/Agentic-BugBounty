# TRIAGER CALIBRATION — Prototype Pollution
# Appended to triager/calibration/webapp.md when target uses Node.js/JS

## VALIDITY RULES

### Server-side PP → RCE
VALID if:
  - Gadget chain PoC demonstrates code execution (file write, DNS callback, sleep)
  - Known gadget exists in dependency tree (EJS, Pug, Handlebars, etc.)
PARTIAL VALID (High, not Critical):
  - Pollution confirmed (polluted property visible in response)
  - Known RCE gadget engine in dependencies
  - But full RCE not demonstrated (partial PoC acceptable for Critical severity class)
NOT VALID:
  - Pollution confirmed but no gadget chain exists in dependency tree
  → Downgrade to Medium (auth bypass still possible, RCE not demonstrated)
Severity: Critical (with gadget), High (pollution confirmed, gadget plausible)

### Server-side PP → Auth bypass
VALID if:
  - PoC injects isAdmin/role/authorized into Object.prototype
  - Demonstrates accessing a privileged endpoint that was previously blocked
Severity: High

### Client-side PP → XSS
VALID if:
  - DOM gadget exists (innerHTML/document.write fed by polluted property)
  - alert(document.domain) executes in victim page context
NOT VALID:
  - Pollution confirmed in console but no DOM sink reachable
  → Informative
Severity: High (if no user interaction), Medium (if click required)

### DoS via PP
VALID if:
  - Pollution crashes the Node.js process or causes infinite loop
  - Reproducible and affects all users (not sandboxed)
Most programs exclude DoS — check rules first
Severity: Medium if in scope

## OVERCLAIM PATTERNS TO CATCH

"Prototype pollution leads to RCE" without demonstrated gadget chain:
  → Downgrade from Critical to Medium until gadget confirmed

"affects all users" for client-side PP:
  → Only affects users who visit the specific page/trigger
  → Scope the actual affected user population

lodash version X is vulnerable:
  → Informative unless an actual exploitation path shown
  → Known vulnerable library without working PoC = out of scope per most programs
