# TRIAGER CALIBRATION — Chrome Extension
# Asset-specific bug vs feature rules for Check 3
# Also extends Check 2.4 with extension-specific PoC validation

---

## CHROME EXTENSION MESSAGING MODEL — Read before triaging any finding

Extensions have three distinct message channels. A PoC that uses the wrong
channel will NEVER trigger the handler. Verify which channel is used before
accepting or rejecting.

```
CHANNEL 1: window.postMessage / window.addEventListener('message')
  Scope:    Same window object (web page ↔ content script)
  Who can send: Any web page in the same tab
  Who receives: Content script listeners using window.addEventListener('message')
  NOT received by: background script listeners

CHANNEL 2: chrome.runtime.sendMessage / chrome.runtime.onMessage
  Scope:    Extension pages, content scripts → background service worker
  Who can send: ONLY extension content scripts or extension pages
                A plain web page CANNOT directly call chrome.runtime.sendMessage
  Who receives: Background script registered with chrome.runtime.onMessage.addListener()
  Guard: sender.url / sender.tab — check if handler validates these

CHANNEL 3: chrome.runtime.onMessageExternal / onConnectExternal
  Scope:    Other extensions → this extension
  Who can send: Other Chrome extensions (if in externally_connectable)
  Who receives: Background script with onMessageExternal listener

CUSTOM EVENT BUS (e.g., thrush-future pattern)
  Uses: window.addEventListener + CustomEvent / dispatchEvent
  Scope: Same window — web page can trigger IF content script listens
  Check: does content script relay to background? Via which channel?
```

**PoC validation for message-based findings:**
Before accepting: read the actual message handler registration in the source.
Confirm:
  1. Which channel registers the handler (postMessage listener vs onMessage)?
  2. Does PoC use the correct channel to reach that handler?
  3. Do message field names in PoC match the handler's switch/if cases?
  4. Is there an intermediate relay (content script bridges postMessage → sendMessage)?
     If so, trace the relay code — is it present? Does it validate origin first?

---

## VALIDITY RULES BY VULNERABILITY CLASS

### 1. Universal XSS (uXSS) — CWE-79

VALID if:
  - alert(document.domain) shows the VICTIM DOMAIN (e.g., bank.com, not chrome-extension://)
  - Content script injects attacker-controlled data into victim page DOM via innerHTML,
    outerHTML, insertAdjacentHTML, document.write, or jQuery .html()
  - Attack can be triggered by: visiting attacker page, URL fragment, postMessage to
    content script, or page title/meta data the extension reads

PoC mechanism must show:
  - The exact DOM sink (innerHTML assignment, etc.) with file:line
  - The exact source: where attacker data enters (URL param, postMessage, page title)
  - alert(document.domain) showing victim origin

NOT VALID:
  - alert() shows chrome-extension:// origin → self-XSS in extension UI, not uXSS
  - Victim must type/paste the payload themselves → self-XSS, universally out of scope
  - Requires victim to have a specific non-default extension setting
  - XSS in extension's own popup/options page without demonstrable web page impact

Severity:
  - Triggered by visiting any attacker-controlled page: Critical
  - Triggered by clicking one attacker link: High
  - Requires specific non-default config: Medium

---

### 2. Privilege Escalation via Message Passing — CWE-269

VALID if:
  - A web page triggers a privileged chrome API through the extension
  - The complete attack chain is demonstrated:
      web page → postMessage → content script (no origin check) →
      chrome.runtime.sendMessage → background handler → chrome API call

  Qualifying privileged outcomes:
    - chrome.tabs.create / tabs.update with attacker URL (tab hijacking)
    - chrome.scripting.executeScript / tabs.executeScript on target origin
    - chrome.cookies.getAll / cookies.remove
    - chrome.history.search / history.deleteAll
    - chrome.storage.sync.set poisoning config
    - chrome.declarativeNetRequest rule injection

  PoC mechanism validation (CRITICAL):
    Step A: Confirm the content script has a window.addEventListener('message') listener
            AND that it does NOT check event.origin before processing
    Step B: Confirm the content script forwards to background via chrome.runtime.sendMessage
    Step C: Confirm the background handler executes the claimed chrome API
    Step D: Confirm PoC uses window.postMessage (not chrome.runtime.sendMessage)
            because only content scripts can sendMessage to background — web pages cannot

NOT VALID:
  - "Handler doesn't check origin" without demonstrated privileged API call
  - PoC sends chrome.runtime.sendMessage from a web page context → impossible,
    only works from extension content scripts / pages
  - Informative: missing origin check with no relay to background or no dangerous handler

Severity:
  - tabs / scripting / cookies / history APIs triggered: High
  - chrome.storage poisoning only: Medium
  - Limited to opening new tab to attacker URL: Medium (upgrade if phishing chain shown)

---

### 3. Open Redirect / Tab Hijacking — CWE-601

VALID if:
  - chrome.tabs.create or chrome.tabs.update is called with attacker-controlled URL
  - The complete channel leading to that call is traced:
      → Which message type triggers the openTab handler?
      → Does the message originate from a web page (via relay) or extension page only?
  - If extension-page-only trigger: requires XSS in extension page first (chain finding)
  - If web-page-triggerable: standalone Medium

PoC mechanism validation:
  - Confirm the PoC uses the correct channel (see Messaging Model above)
  - Confirm the URL is passed through without validation (no hostname check)
  - Confirm there is no guard requiring user action within the extension UI
  - If the handler is reached only via chrome.runtime messages (not postMessage relay),
    the PoC must come from a content script or extension page — verify the PoC accounts for this

NOT VALID:
  - PoC sends window.postMessage({type:'openTab',...}) but handler is on
    chrome.runtime.onMessage with no content-script relay → channels don't connect
  - Redirect goes to an Okta-controlled domain (not attacker-controlled)
  - Requires physical access to browser / victim to be logged in to the extension

Severity: Medium (open redirect only), upgrade to High if phishing chain demonstrated

---

### 4. Extension Storage Tampering — CWE-915

VALID if:
  - Attacker can write to chrome.storage.sync or chrome.storage.local via message passing
  - Written value changes security-relevant extension behavior:
      → Disables security features
      → Injects attacker-controlled URLs into trusted lists
      → Overrides authentication state
  - Chain demonstrated: web page → content script relay → background storage write

PoC mechanism validation:
  - Same channel validation as Privilege Escalation (§2)
  - Show what the poisoned storage key controls — read the code that consumes it

NOT VALID:
  - Storage write only changes UI preferences (theme, display options) — product bug
  - Requires existing extension-page XSS to trigger

Severity: Medium (if enables secondary attack), Low (if cosmetic only → Informative)

---

### 5. Sensitive Data Leakage — CWE-200

VALID if:
  - Data sent to external domains exceeds the program's privacy policy disclosure
  - Full URLs + user identifiers sent to third-party domains
  - Auth tokens, cookie values, or session identifiers transmitted externally
  - postMessage sends from extension to page include sensitive data with wildcard origin '*'

Check always:
  - Read program privacy policy before ruling on any data leakage claim
  - "Extension sends browsing data to its own servers" is often disclosed — not valid

PoC mechanism validation:
  - For postMessage leakage: confirm extension sends to window (not page sends to extension)
  - Intercept script must be injected into extension content script context (not page)
  - Show the exact postMessage call with file:line and the data field containing sensitive value

NOT VALID:
  - Anonymized queries to program's own servers disclosed in privacy policy
  - Aggregate statistics without user identifiers
  - Data visible only in extension DevTools (local, not transmitted)

Severity: High (auth tokens / PII sent to third party), Medium (non-sensitive URLs)

---

### 6. CSP Weakening — CWE-693

VALID if:
  - Extension removes or weakens Content-Security-Policy headers on victim pages
  - PoC demonstrates the full chain:
      1. Target page has strict CSP blocking inline scripts
      2. Extension removes/modifies the CSP header
      3. Attacker script executes on target page that would have been blocked

PoC mechanism validation:
  - Show the webRequest / declarativeNetRequest rule that modifies CSP
  - Show the page's original CSP vs the modified version
  - Show script execution that was only possible after the modification
  - HTTPS CSP modification requires MITM — only valid if extension actively strips headers,
    not just if an MITM could interfere

NOT VALID:
  - "Extension removes CSP header" without demonstrating script execution
  - Extension adds a less-strict CSP than nothing (page had none) — no degradation
  - Informative: extension modifies CSP in a way that doesn't enable new attack classes

Severity: High (enables script execution on any origin), Medium (enables only on specific origin)

---

### 7. Remote Config Integrity — CWE-494

VALID if:
  - Extension fetches a tracker list, rule set, or config from a remote URL
  - Fetch uses HTTP (not HTTPS), or uses HTTPS without subresource integrity / hash pinning
  - MITM PoC shows tampered config accepted and causes security-relevant behavior:
      → Malicious URLs added to allowlist
      → Tracking protection rules disabled
      → Remote code injection via config

NOT VALID:
  - Config fetch uses HTTPS only (MITM requires CA compromise — too high bar for H1)
  - Tampered config only causes privacy degradation (tracker not blocked) — product bug
  - No MITM PoC provided — theoretical only

Severity: Medium (if security-relevant behavior change), Low (privacy degradation only)

---

### 8. web_accessible_resources Abuse — CWE-200

VALID if:
  - Extension exposes resources with "matches": ["<all_urls>"]
  - A web page can load those resources and extract security-sensitive information:
      → Extension version allowing targeted known-vulnerable-version attacks
      → Exposed APIs callable from resource context
  - PoC shows concrete abusable outcome beyond fingerprinting

NOT VALID (Informative):
  - Extension detectable by websites via resource loading — expected browser behavior
  - Version leak alone without demonstrating a follow-on attack
  - Resource loads but contains no sensitive data

Severity: Informative (fingerprinting), Low–Medium (if enables targeted follow-on attack)

---

### 9. Content Script Injection into Sensitive Pages — CWE-79 variant

VALID if:
  - Extension's content_scripts.matches includes sensitive origins (bank, SSO, payment)
    where the content script is not expected/disclosed
  - Content script reads sensitive page data (passwords, tokens, form values) and:
      → Transmits externally, OR
      → Exposes to the hosting page via postMessage

Check manifest.json content_scripts[].matches
Compare against program's privacy policy disclosures

NOT VALID:
  - Extension is explicitly designed for that origin (okta extension on *.okta.com — expected)
  - Content script is passive (only receives messages, doesn't read DOM)

---

### 10. Native Messaging Abuse — CWE-78

VALID if:
  - Extension uses nativeMessaging permission
  - A web page can trigger the native messaging connection via message relay
  - Native host executes OS commands or accesses local files with attacker data

PoC must show: command injected into native message that executes on OS

NOT VALID: theoretical without PoC reaching nativeMessaging.sendMessage

Severity: Critical if OS command execution, High if arbitrary file read

---

## SEVERITY CALIBRATION — Chrome Extension

| Finding | No interaction | One click | Special config |
|---|---|---|---|
| uXSS any origin | Critical | High | Medium |
| uXSS specific origin | High | Medium | Low |
| Privilege escalation → chrome API (tabs/scripting/cookies) | High | Medium | Low |
| Privilege escalation → storage only | Medium | Low | Informative |
| Open redirect / tab hijacking (web-page-triggerable) | Medium | Low | Informative |
| Open redirect (extension-page-only) | Low | Low | Informative |
| Data leak to third party (auth tokens) | High | Medium | Low |
| Data leak to third party (non-sensitive URLs) | Medium | Low | Informative |
| CSP weakening with script execution PoC | High | Medium | Informative |
| CSP weakening without exploitation | Informative | Informative | Informative |
| Storage tampering (security-relevant) | Medium | Low | Informative |
| Remote config no integrity (HTTP) | Medium | Low | Informative |
| Remote config HTTPS only | Informative | Informative | Informative |
| Content script on sensitive page (undisclosed) | High | Medium | Low |
| Native messaging OS command injection | Critical | High | Medium |
| Extension fingerprinting / version leak | Informative | Informative | Informative |
| Privacy bypass (tracker not blocked) | Informative | Informative | Informative |

---

## ALWAYS INFORMATIVE / PRODUCT BUG (never security report)

- Extension fails to block a tracker
- Extension detectable by website (web_accessible_resources fingerprint without follow-on)
- Missing security headers on extension popup page (chrome-extension:// CSP)
- Self-XSS in extension popup (victim must paste payload)
- Extension setting defaults that reduce privacy (but are disclosed)
