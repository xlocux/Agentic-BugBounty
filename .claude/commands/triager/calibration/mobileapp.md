# TRIAGER CALIBRATION — MobileApp
# Asset-specific bug vs feature rules for Check 3

## VALIDITY RULES BY VULNERABILITY CLASS

### Hardcoded Secrets
VALID if:
  - API key/secret extracted from binary is functional (test it)
  - Grants access to backend services or third-party accounts
NOT VALID:
  - Key is clearly a placeholder/example value
  - Key is scoped to a sandbox/test environment only
  - Key already revoked or expired
Severity: High/Critical if key grants production access

### Insecure Data Storage
VALID if:
  - Sensitive data (passwords, tokens, PII) stored in plaintext
  - SharedPreferences / UserDefaults contains auth tokens
  - SQLite DB contains unencrypted sensitive data
  - Requires rooted device to access (note this — reduces severity)
NOT VALID:
  - Non-sensitive data stored in cleartext (app preferences, UI settings)
  - Data encrypted with system-level encryption (Android Keystore / iOS Keychain)
Severity:
  Token/password in plaintext on unrooted path = High
  Requires root to access = Medium

### Certificate Pinning Bypass
NOT a standalone vulnerability:
  - Pinning bypass is a TECHNIQUE used to find other vulnerabilities
  - "Certificate pinning can be bypassed" alone = Informative
  - Only report if bypass enables interception of sensitive data
    and that data constitutes a separate finding (credential exposure, etc.)

### Exported Activity / Deep Link Abuse
VALID if:
  - Exported Activity accepts Intent extras that trigger sensitive actions
    (file deletion, auth bypass, data access without login)
  - Deep link accepts parameters that cause sensitive behavior
  - PoC shows malicious app triggering the exported component
NOT VALID:
  - Exported Activity only displays non-sensitive UI
  - Deep link only navigates to a screen (no data manipulation)

### WebView XSS
VALID if:
  - Attacker can load attacker-controlled URL in WebView
  - JavaScript bridge (addJavascriptInterface) accessible from WebView
  - JavaScript can call native methods via bridge
NOT VALID:
  - WebView loads only hardcoded internal resources
  - JavaScript disabled in WebView

### Insecure Logging
VALID if:
  - Auth tokens, passwords, PII appear in logcat
  - Requires only adb access (no root) to extract
NOT VALID:
  - Generic non-sensitive debug messages
  - Log entries only visible on rooted device AND app is debug build

## SEVERITY CALIBRATION — MobileApp

| Finding | No root required | Root required |
|---|---|---|
| Hardcoded prod API key | Critical | Critical |
| Auth token in SharedPrefs | High | Medium |
| Exported Activity → auth bypass | High | N/A |
| WebView + JS bridge | High | Medium |
| Token in logcat | Medium | Low |
| Certificate pinning bypass alone | Informative | Informative |
