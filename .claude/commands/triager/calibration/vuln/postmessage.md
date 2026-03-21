# TRIAGER CALIBRATION — postMessage
# Appended to webapp or chromeext calibration module

## VALIDITY RULES

### Missing origin check → sensitive action (webapp)
VALID if:
  - PoC HTML page demonstrates triggering a sensitive action cross-origin
  - Action has real security impact: state change, data access, auth bypass
NOT VALID:
  - "Handler doesn't validate origin" without a reachable dangerous handler
  - Listener processes only non-sensitive UI messages
Severity: High (state-changing action), Medium (info disclosure)

### postMessage → XSS via DOM sink
Apply standard XSS calibration:
  - Must demonstrate alert(document.domain) in victim page context
Severity: High (no interaction), Medium (click required)

### Sensitive data with wildcard origin (webapp)
VALID if:
  - postMessage(sensitiveData, "*") confirmed
  - sensitiveData contains: auth tokens, session info, PII, CSRF tokens
NOT VALID:
  - Non-sensitive data sent with wildcard
  - Data already public or non-exploitable
Severity: High (auth token), Medium (non-auth sensitive)

### Extension privilege escalation via postMessage (chromeext)
VALID if:
  - PoC demonstrates privileged chrome API call triggered from attacker page
  - Specific API call shown: tabs.create, cookies.get, scripting.executeScript
NOT VALID:
  - "Background handler doesn't check sender" without a reachable privileged action
Severity: Critical (full API access with <all_urls>+cookies), High (limited APIs)

## ORIGIN BYPASS ASSESSMENT
If researcher claims origin check bypass:
  - Verify the specific bypass pattern is applicable
  - Test: does the supposed bypass actually pass the check in the code?
  - startsWith/includes bypasses: High if confirmed
  - null origin bypass: Medium (requires iframe setup by attacker)
