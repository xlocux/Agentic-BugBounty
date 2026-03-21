# TRIAGER CALIBRATION — Misc Vuln Classes

## Open Redirect
VALID only with demonstrated phishing scenario OR OAuth token theft chain
"Redirects to external URL" alone = Informative

## Clickjacking
VALID only if: sensitive action on frameable page + no X-Frame-Options/CSP
NOT VALID: informational pages, pages requiring keyboard input
SEVERITY: Low unless demonstrated account impact chain

## ReDoS
VALID if: >2s response time for crafted input vs <100ms for normal input
SEVERITY: Node.js (blocks event loop) = High; Multi-threaded = Medium

## WebSocket CSWSH
VALID if: attacker page successfully receives target user's private data via hijacked WS
"No Origin check" alone = Informative (must show data leakage)

## NoSQL Injection
Auth bypass = High/Critical (same as SQLi auth bypass)
Data extraction = High
Blind NoSQL = Medium (confirm with regex extraction or DNS callback)

## LDAP Injection
Auth bypass = High
Data enumeration = Medium

## XXE
File read (/etc/passwd) = High
SSRF to cloud metadata = Critical
Blind (DNS only) = Medium (escalate with OOB file exfil)
DoS (billion laughs) = Low/Medium if DoS in scope

## CSS Injection
Token exfiltration via attribute selector = High (if CSRF token or session data)
UI redressing only = Low/Informative

## Mass Assignment
Role escalation to admin = Critical
Additional data field access = Medium
Field present but no privilege change = Informative

## Cloud Misconfiguration
Public S3 with PII = Critical
Public S3 write = High
Public S3 read (non-sensitive) = Medium
Exposed actuator/debug endpoint = Medium/High depending on data exposed
