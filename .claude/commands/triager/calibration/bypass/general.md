# TRIAGER CALIBRATION — Bypass Techniques
# Applied when a report includes a filter/WAF bypass as part of the PoC

## CORE PRINCIPLE

A bypass technique is NOT a standalone finding.
It is only relevant as part of a finding that demonstrates real impact.

"WAF can be bypassed" alone = NOT_APPLICABLE
"WAF bypassed → SQLi dumps users table" = HIGH/CRITICAL (severity from the underlying vuln)

---

## VALIDITY RULES

### Encoding bypass (URL, HTML, JS)
VALID if:
  - Bypass allows a previously-blocked payload to execute
  - The underlying vulnerability is confirmed with the bypass applied
  - PoC includes both the bypass technique AND the resulting impact
NOT VALID:
  - Encoding trick demonstrated in isolation without a reachable sink
  - "Double URL encoding bypasses the WAF" without showing what becomes possible

### WAF bypass
VALID if:
  - Specific payload reaches the application and triggers the vulnerability
  - HTTP-level manipulation (chunking, parameter pollution) demonstrated working
NOT VALID:
  - WAF bypass demonstrated only to reach a non-sensitive endpoint
  - Timing difference observed but no payload delivery confirmed
SEVERITY: the WAF bypass does not add severity — severity comes from the underlying vuln
  Example: WAF bypass → Reflected XSS with no sensitive context = Low (same as without WAF)
  Example: WAF bypass → SQLi on auth endpoint = Critical (same as without WAF)

### CSP bypass (for XSS reports)
VALID if:
  - Alert(document.domain) fires despite CSP being present
  - Bypass method is clearly documented (JSONP on whitelisted domain, etc.)
  - Bypass is reproducible in current app state (JSONP endpoint still exists)
NOT VALID:
  - CSP header missing entirely (not a bypass — just misconfiguration, report as XSS)
  - Bypass requires a whitelisted domain that no longer serves the JSONP endpoint

### JWT attack
VALID if:
  - Token accepted by server after modification
  - Impact demonstrated: access to resource previously blocked
  - For alg:none: server must accept the token, not just that the lib is vulnerable
NOT VALID:
  - JWT library version is outdated (known vuln library without working PoC = out of scope)
  - Token rejected after modification (server correctly validates)
  - Token decoded client-side only (no server-side validation = informative)

### OAuth bypass
VALID if:
  - redirect_uri bypass allows token/code to be sent to attacker
  - PoC demonstrates token captured at attacker URL
  - Missing state allows CSRF on OAuth flow (show account linking to attacker account)
NOT VALID:
  - redirect_uri validation exists but is strict (correct behavior)
  - State is missing but no sensitive OAuth action exists

### Auth bypass via mass assignment
VALID if:
  - Role/permission field accepted and reflected in subsequent responses
  - Privilege escalation demonstrated (admin endpoint accessed, admin action performed)
NOT VALID:
  - Field accepted but has no effect on authorization logic
  - Requires knowing internal field names without any evidence they are bindable

---

## SEVERITY IMPACT OF BYPASSES

Bypasses affect EXPLOITABILITY (AC in CVSS), not IMPACT (C/I/A).

A WAF bypass typically:
  - Lowers Attack Complexity from H to L (if WAF was the only barrier)
  - Does NOT change Confidentiality/Integrity/Availability scores

Example CVSS adjustment:
  Without WAF bypass: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N = 7.4 (High)
  With WAF bypass:    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1 (Critical)
  → The bypass justifies the Critical rating by making exploitation practical

---

## OVERCLAIM PATTERNS

"This bypass defeats all security controls" → focus only on demonstrated impact

"WAF bypass = Critical by itself" → severity from vuln, not bypass technique

"Encoding bypass shows the WAF is ineffective" → Informative without underlying vuln

"CSP bypass via third-party JSONP" → only valid if the JSONP endpoint is currently live
  Verify the endpoint before reporting
