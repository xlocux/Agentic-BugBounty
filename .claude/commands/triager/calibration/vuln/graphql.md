# TRIAGER CALIBRATION — GraphQL
# Appended to triager/calibration/webapp.md when target uses GraphQL

## VALIDITY RULES

### Introspection enabled in production
VALID if: production endpoint returns full schema via __schema query
NOT VALID: staging/dev endpoints — must be production
Severity: LOW (information disclosure only — does not enable exploitation alone)
Note: escalate to MEDIUM if schema reveals sensitive internal API design

### Batch query brute force
VALID if: PoC demonstrates bypassing per-IP/per-user rate limiting on auth endpoints
Must show: N attempts in one request succeed where N individual requests would be blocked
Severity: MEDIUM (rate limit bypass for credential stuffing)

### Nested query DoS
VALID ONLY if:
  - Target has no depth/complexity limiting configured
  - PoC demonstrates meaningful server degradation (>5s response or timeout)
  - Server does not recover without restart (persistent DoS)
NOT VALID: transient slowdown, staging only
Note: Most programs explicitly exclude DoS — check program rules first
Severity: LOW-MEDIUM if in scope at all

### IDOR via GraphQL ID
Apply same rules as standard IDOR:
  - Must demonstrate access to another user's private data
  - Sequential ID guessing on public data = Informative

### Authorization bypass (field-level)
VALID if: low-privilege user accesses fields restricted to higher privilege role
Must show: the field contains sensitive data AND access is not intended
Severity: MEDIUM-HIGH depending on data sensitivity

### Injection via arguments
Apply standard injection calibration (SQLi, SSRF, etc.) based on the sink reached
GraphQL is just a delivery mechanism — the underlying injection class drives severity

### Introspection-assisted enumeration
NOT a standalone finding — it is recon for other findings
Include as researcher_notes in the report for the actual vulnerability found
