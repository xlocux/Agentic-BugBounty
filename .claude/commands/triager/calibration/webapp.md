# TRIAGER CALIBRATION — WebApp
# Asset-specific bug vs feature rules for Check 3

## VALIDITY RULES BY VULNERABILITY CLASS

### SQL Injection
VALID if:
  - PoC demonstrates data extraction (UNION SELECT) or time-based blind (SLEEP/WAITFOR)
  - Error-based injection returns DB schema or data
NOT VALID if:
  - Only shows a DB error without extracting data (may be Informative)
  - Requires authenticated admin access AND admin can already access data directly

Severity calibration:
  Unauthenticated + data extraction = High/Critical
  Authenticated (low-priv) + data extraction = High
  Authenticated (admin only) = Medium (admin already has DB access)

### XSS
Stored XSS VALID if:
  - Payload persists and executes for OTHER users (not just self)
  - Execution happens in application context (not sandbox/preview)
Reflected XSS VALID if:
  - Requires only a crafted URL (no self-injection)
  - Executes in victim browser context
NOT VALID:
  - Self-XSS (victim must inject their own payload)
  - XSS in admin panel only accessible to admins (unless admin→user escalation shown)
  - XSS in sandbox/isolated preview iframe

CSP bypass requirement:
  If target has CSP, researcher must demonstrate bypass for XSS to be valid.

### CSRF
VALID if:
  - State-changing action (password change, email change, fund transfer)
  - No nonce or nonce not validated server-side
  - PoC HTML form demonstrates the action from cross-origin
NOT VALID:
  - Action requires knowing current user credentials (natural CSRF protection)
  - SameSite=Strict cookie present (blocks CSRF from cross-site)
  - JSON-only endpoint without CORS allowing cross-origin reads
Informative:
  - CSRF on low-impact action (theme change, notification preference)

### SSRF
VALID if:
  - Internal service response returned to attacker
  - Cloud metadata endpoint reachable (169.254.169.254)
  - Internal port scan possible
NOT VALID (per DDG and most programs):
  - Blind SSRF to external attacker server only (no internal access shown)
  - SSRF to localhost returns only generic response without data
Severity:
  Cloud metadata (AWS/GCP/Azure) = Critical (credential exfiltration)
  Internal service access = High
  Blind external SSRF = Low/Informative

### IDOR
VALID if:
  - Attacker accesses/modifies another user's data
  - Horizontal: same privilege level, different user
  - Vertical: lower privilege accesses higher privilege data
NOT VALID:
  - Sequential ID guessing where all data is already public
  - UUIDs that are exposed in normal app flow (not a security boundary)
Severity:
  PII / financial data access = High/Critical
  Non-sensitive data access = Medium
  Read-only public data = Low/Informative

### Deserialization
VALID always if user-controlled data reaches unserialize() / readObject()
Even without full RCE PoC, if gadget chain exists in dependencies → High
CVSS: treat as potential RCE until proven otherwise

### JWT Vulnerabilities
VALID:
  - alg:none accepted (no signature verification)
  - RS256→HS256 confusion (sign with public key)
  - Weak secret crackable (show cracked token)
NOT VALID:
  - Expired token rejected correctly (expected behavior)
  - Token not rotated after logout without shown session abuse

### Open Redirect
VALID only with demonstrated phishing scenario:
  - Redirect from trusted domain to attacker domain
  - Combined with OAuth flow to steal tokens
NOT VALID alone without phishing context:
  - "The URL redirects to external site" without impact demonstration
Severity: Low-Medium (requires social engineering)

## SEVERITY CALIBRATION — WebApp

| Finding | Unauth | Low-priv auth | Admin only |
|---|---|---|---|
| SQLi + data dump | Critical | High | Medium |
| Stored XSS | High | Medium | Low |
| SSRF + metadata | Critical | Critical | High |
| IDOR PII | High | High | N/A |
| CSRF state-change | Medium | Medium | Low |
| Deserialization | Critical | High | Medium |
| Path Traversal RCE | Critical | High | Medium |
