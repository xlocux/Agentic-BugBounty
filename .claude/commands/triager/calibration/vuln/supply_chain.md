# TRIAGER CALIBRATION — Supply Chain
# Appended to any asset calibration module when supply chain findings are present

## VALIDITY RULES

### Dependency Confusion
VALID if:
  - Private package name found that does NOT exist on public registry
  - Researcher demonstrates package can be registered and would be fetched
  - DNS callback proof provided (package's postinstall executed in victim env)
CRITICAL: do NOT accept without DNS callback or equivalent proof
  - "The package name is available" alone = NOT VALID (Informative at best)
  - Researcher must actually register a benign PoC package and prove execution
Severity:
  CI/CD environment code execution = Critical
  Developer machine code execution = High
  Package available but no exec path demonstrated = Low/Informative

### Typosquatting
VALID only if:
  - Malicious package already exists on public registry with the typo name
  - High probability of developer typo (common package, one character off)
NOT VALID:
  - Just noting that a similar name could be registered
Severity: Medium (requires developer to make typo)

### CI/CD Pipeline Injection
VALID if:
  - PoC PR/branch demonstrates user-controlled data reaches a shell command
  - Secrets are accessible in the injection context
Severity: Critical (if secrets exfiltrated), High (if arbitrary code in CI)

### Subdomain Takeover
VALID if:
  - Researcher claims the subdomain and serves content (demonstrates control)
  - Impact: cookie theft via shared eTLD, OAuth redirect abuse, phishing
NOT VALID:
  - CNAME target exists and serves valid content
  - Subdomain has no sensitive use (no auth, no cookies, no OAuth)
Severity:
  OAuth redirect_uri or CSP trusted = High
  Cookie on same eTLD+1 = High
  Basic content injection = Medium
  Unused subdomain = Low

### Secrets in Repository
VALID if:
  - Secret is functional (API call succeeds with it)
  - Found in public repository OR accessible via git history
  - Not already rotated
NOT VALID:
  - Example/placeholder values (REPLACE_WITH_YOUR_KEY)
  - Already rotated secrets (verify they are invalid)
Severity: depends on what the secret grants access to
