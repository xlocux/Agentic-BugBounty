# TRIAGER CALIBRATION — SSTI / CSTI

SSTI VALID if:
- Math evaluation confirmed (7*7=49 in response)
- RCE demonstrated (id command output returned OR DNS callback)
- Partial PoC (math eval + known engine with RCE gadget) acceptable for Critical

CSTI VALID if:
- alert(document.domain) executes via template expression
- Must be in victim page context (not attacker-hosted page)

SEVERITY:
  SSTI + RCE = Critical
  SSTI + math eval + known engine gadget = High (escalate to Critical with RCE PoC)
  CSTI + XSS = High (same as stored XSS criteria)
