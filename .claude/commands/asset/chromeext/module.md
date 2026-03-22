# ASSET MODULE — Chrome Extension
# Covers: Chrome, Firefox, Edge extensions (MV2 and MV3)
# Report ID prefix: EXT

## THREAT MODEL

A Chrome extension operates across multiple trust boundaries.
A malicious web page (attacker-controlled) can potentially:
  - Inject data into content scripts via DOM, postMessage, or page events
  - Escalate to privileged background APIs via message passing
  - Abuse web_accessible_resources to fingerprint or interact with the extension
  - Exploit remote config fetches via MITM or compromised CDN

Components and trust levels:
  manifest.json              → declares all permissions and boundaries
  background service worker  → privileged, full Chrome API access (MV3)
  background page            → privileged, full Chrome API access (MV2)
  content scripts            → injected into web pages, semi-trusted bridge
  popup / options pages      → extension origin, trusted
  web_accessible_resources   → files exposed to ALL web pages

## VULNERABILITY CLASSES (priority order)

1.  Universal XSS (uXSS)               CWE-79   — content script injects attacker HTML into any page
2.  Privilege Escalation via Messages  CWE-269  — web page triggers chrome privileged API
3.  Sensitive Data Leakage             CWE-200  — browsing data sent beyond privacy policy
4.  Remote Config Integrity            CWE-494  — tracker list fetched without hash verification
5.  CSP Weakening                      CWE-693  — extension strips page CSP enabling attacks
6.  web_accessible_resources Abuse     CWE-200  — extension detection / fingerprinting
7.  Open Redirect / Tab Hijacking      CWE-601  — chrome.tabs.update with attacker URL
8.  Extension Storage Tampering        CWE-915  — chrome.storage poisoned via message chain

## WHITEBOX STATIC ANALYSIS

### Step 1 — Parse manifest.json
```bash
cat manifest.json | python3 -m json.tool
```
Check:
  - manifest_version: 2 or 3?
  - permissions: flag <all_urls>, tabs, cookies, scripting, nativeMessaging, history
  - content_security_policy: flag unsafe-inline, unsafe-eval, external script-src
  - content_scripts[].matches: which pages are injected?
  - web_accessible_resources[].matches: "matches": ["<all_urls>"] is dangerous
  - externally_connectable: which external origins can send runtime.sendMessage?
  - background: service_worker (MV3) vs scripts (MV2)

### Step 2 — Source grep patterns
```bash
# uXSS / DOM sinks
grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML\|document\.write" --include="*.js"
grep -rn "\.html(\|jQuery.*html\b" --include="*.js"

# Message handling — origin validation
grep -rn "addEventListener.*message\|onmessage\b" --include="*.js"
grep -rn "runtime\.onMessage\|runtime\.sendMessage\|onMessageExternal" --include="*.js"
grep -rn "\.origin\b" --include="*.js"
# Flag any message handler that does NOT check event.origin or sender.url

# Dynamic code execution
grep -rn "eval(\|new Function(\|setTimeout.*['\"]" --include="*.js"
grep -rn "scripting\.executeScript\|tabs\.executeScript" --include="*.js"

# External fetches — remote config
grep -rn "fetch(\|XMLHttpRequest\|\.get(" --include="*.js"
# List ALL remote URLs fetched — check for integrity verification

# Sensitive data
grep -rn "chrome\.cookies\|document\.cookie" --include="*.js"
grep -rn "chrome\.history\|chrome\.tabs\b" --include="*.js"
grep -rn "password\|token\|api.key\|secret" --include="*.js" -i

# Navigation / tab control
grep -rn "chrome\.tabs\.update\|chrome\.tabs\.create\|chrome\.windows\.create" --include="*.js"
grep -rn "window\.location\|location\.href" --include="*.js"

# Storage
grep -rn "chrome\.storage\|localStorage\|sessionStorage" --include="*.js"
```

## DYNAMIC TESTING

### Setup
```bash
# Load unpacked extension
# Chrome → chrome://extensions → Developer mode ON → Load unpacked → select extension dir

# Debug background service worker
# Chrome → chrome://extensions → click "service worker" link → DevTools opens

# Debug content scripts
# Open any page → DevTools → Sources → Content scripts tab
```

### uXSS test template
```html
<!-- save as poc_uxss.html, serve locally, visit with extension active -->
<!DOCTYPE html>
<html>
<body>
<script>
// Attempt 1: URL fragment injection
// If extension reads location.hash and inserts into DOM:
// visit: poc_uxss.html#<img src=x onerror="alert(document.domain)">

// Attempt 2: postMessage to content script
window.postMessage({
  type: 'ddg:update',  // replace with actual message type from grep
  payload: '<img src=x onerror="alert(document.domain)">'
}, '*');

// Attempt 3: page title / meta injection
document.title = '<img src=x onerror="alert(document.domain)">';
</script>
</body>
</html>
```

### Message escalation test template
```html
<!DOCTYPE html>
<html>
<body>
<script>
// Try to trigger privileged API via content script message bridge
window.postMessage({
  type: 'REPLACE_WITH_REAL_TYPE',
  action: 'openTab',
  url: 'https://attacker.com'
}, '*');

// Monitor: does a new tab open? Does a cookie get sent to attacker.com?
</script>
</body>
</html>
```

### Remote config MITM test
```bash
# Run mitmproxy
mitmproxy --mode transparent --ssl-insecure

# Intercept the extension's config/blocklist fetch
# Return tampered JSON
# Observe: does extension accept it? Can you inject a malicious rule?
```

## KEY DISTINCTIONS — Bug vs Feature

Privacy bypass (extension fails to block a tracker):
  → Product bug, NOT a security vulnerability. Do not report.

Extension detectable by websites:
  → Expected browser behavior. INFORMATIVE unless leads to real exploit.

Self-XSS in extension popup (user must type payload):
  → Out of scope.

uXSS confirmation requirement:
  → alert(document.domain) must show the VICTIM DOMAIN, not extension origin.
  → alert(1) in chrome-extension:// context = NOT a valid uXSS.

---

## MANDATORY EVIDENCE CAPTURE — For every confirmed finding

Before writing a finding to REPORT_BUNDLE, you MUST collect:

### 1. Vulnerable Code Snippet
Read the exact lines from the source file.
Populate vulnerable_code_snippet with:
  - file: relative path from extension root
  - line_start / line_end: the exact line numbers
  - snippet: verbatim copy of the lines (no paraphrasing)
  - annotation: which specific line is the root cause and why

Example:
```json
{
  "file": "shared/bg/start-background-script.js",
  "line_start": 1,
  "line_end": 1,
  "snippet": "case\"openTab\":return p.openTab(r.url);",
  "annotation": "Line passes r.url directly to openTab() without any URL validation"
}
```

### 2. Attack Flow Diagram
For every finding, write a Mermaid diagram in attack_flow_diagram.
Choose the diagram type that best fits the vulnerability:

**For message-passing vulns** (postMessage, runtime.onMessage):
```
sequenceDiagram
    participant A as Attacker Page
    participant CS as Content Script
    participant BG as Background Script
    participant API as Chrome API
    A->>CS: window.postMessage({type:'openTab', url:'evil.com'})
    Note over CS: No event.origin check
    CS->>BG: chrome.runtime.sendMessage({type:'openTab', url:'evil.com'})
    Note over BG: No URL validation
    BG->>API: chrome.tabs.create({url:'evil.com'})
    API-->>A: New tab opens to attacker URL
```

**For uXSS vulns** (DOM injection):
```
flowchart LR
    A[Attacker controls\nURL fragment / postMessage] --> B[Content Script reads\nattacker data]
    B --> C[innerHTML assignment\non victim page]
    C --> D[Script executes in\nvictim origin context]
    D --> E[alert document.domain\nshows victim.com]
```

**For data leakage vulns**:
```
sequenceDiagram
    participant P as Victim Page
    participant CS as Content Script
    participant BG as Background Script
    participant EXT as External Server
    P->>CS: Page loads, content script active
    CS->>BG: Sends browsing data
    BG->>EXT: POST https://tracker.com/collect\n{url: full_url, userId: id}
```

### 3. PoC Channel Verification (REQUIRED before confirming)
For ANY message-based finding, explicitly trace the channel:
  □ What listener is registered in the code? (postMessage vs onMessage vs CustomEvent)
  □ Does the PoC trigger the correct channel?
  □ Do field names in PoC match the switch/case in the handler?
  □ Is there a relay from content script to background? Read the relay code.
  □ Does any origin/sender check guard the handler?

If you cannot confirm all 5 points: mark as unconfirmed, explain in reason_not_confirmed.

---

## ADDITIONAL VULN MODULES

| Vector | Module path |
|---|---|
| postMessage / runtime.onMessage | asset/chromeext/vuln/postmessage.md |
| npm supply chain (extension build) | shared/vuln/supply_chain.md |

Auto-load triggers:
- If addEventListener message OR runtime.onMessage found → load postmessage.md
- If package.json present in extension root → load supply_chain.md
