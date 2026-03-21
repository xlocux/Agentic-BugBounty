# TRIAGER CALIBRATION — Chrome Extension
# Asset-specific bug vs feature rules for Check 3

## VALIDITY RULES BY VULNERABILITY CLASS

### Universal XSS (uXSS)
VALID if:
  - alert(document.domain) shows the VICTIM domain (e.g., bank.com)
  - Triggered by visiting an attacker-controlled page (no victim interaction beyond visit)
  - Content script injects attacker data into victim page DOM
NOT VALID:
  - alert() shows chrome-extension:// origin → not uXSS, self-contained
  - Victim must type/paste the payload themselves (self-XSS)
  - Requires victim to have a specific non-default extension setting
Severity: Critical if no user interaction, High if one click required

### Privilege Escalation via Message Passing
VALID if:
  - Web page sends postMessage → content script forwards → background triggers chrome API
  - Specific demonstrated outcome: new tab opened to attacker URL, cookies read,
    scripting.executeScript called on target origin
NOT VALID:
  - "Handler doesn't check origin" without demonstrated privileged action
  - Informative: missing origin check with no reachable dangerous handler
Severity: High if privileged API triggered, Medium if limited outcome

### Sensitive Data Leakage
VALID if:
  - Data sent exceeds what the program's privacy policy discloses
  - Full URLs + identifiers sent to third-party domains
  - Auth tokens or cookie values transmitted externally
NOT VALID:
  - Anonymized queries sent to program's own servers (disclosed in privacy policy)
  - Aggregate statistics without user identifiers
Check: always read program privacy policy before ruling on data leakage

### Remote Config Integrity
VALID if:
  - Tracker list/config fetched without hash pinning
  - MITM PoC shows tampered config accepted and acted upon
  - Tampered config causes security-relevant behavior change
NOT VALID:
  - Config fetch uses HTTPS (MITM requires CA compromise — too high bar)
  - Tampered config only causes privacy degradation (product bug, not security)

### CSP Weakening
VALID if:
  - Extension removes/modifies CSP headers
  - PoC shows: page had strict CSP → extension removed it → attacker script executes
  - Must demonstrate actual script execution enabled by the weakening
NOT VALID:
  - "Extension removes CSP header" without showing exploitation
  - Informative: extension modifies CSP in way that doesn't enable new attacks

### Privacy Bypass (tracker not blocked)
ALWAYS Informative/Product Bug:
  - Never a security vulnerability
  - Report separately to program as product feedback, not H1 security report

## SEVERITY CALIBRATION — Chrome Extension

| Finding | No interaction | One click | Special config |
|---|---|---|---|
| uXSS any origin | Critical | High | Medium |
| uXSS specific origin | High | Medium | Low |
| Privilege escalation to chrome API | High | Medium | Low |
| Data leak to third party | High | Medium | Low |
| CSP weakening with PoC | High | Medium | Informative |
| Remote config no integrity | Medium | Low | Informative |
| Extension fingerprinting | Informative | Informative | Informative |
