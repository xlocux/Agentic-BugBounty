# VULN MODULE — Open Redirect
# Asset: webapp
# CWE-601 | Report prefix: WEB-REDIR

## THREAT MODEL

Open redirects allow attackers to craft URLs on trusted domains that redirect
users to attacker-controlled sites. Used for:
- Phishing (trusted domain → fake login page)
- OAuth token theft (redirect_uri abuse)
- SSRF chain (server follows redirect to internal IP)
- Bypassing referrer-based access controls

## WHITEBOX PATTERNS

```bash
grep -rn "redirect(\|header.*Location\|Redirect(\|redirect_to" \
  --include="*.php" --include="*.py" --include="*.rb" --include="*.java"

grep -rn "next=\|return_to=\|redirect=\|url=\|goto=\|dest=\|destination=" \
  --include="*.php" --include="*.py" --include="*.js"

# Check for URL validation (or lack thereof)
grep -rn "parse_url\|urlparse\|URI\.parse\|URL\.parse" \
  --include="*.php" --include="*.py" --include="*.rb" --include="*.js" -A5
```

## TESTING

```bash
# Common parameter names for redirect destinations:
PARAMS="next return_to redirect redirect_uri url goto dest destination back callback"

for param in $PARAMS; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/login?$param=https://attacker.com")
  location=$(curl -sI "https://target.com/login?$param=https://attacker.com" | \
    grep -i "location:" | tr -d '\r')
  if echo "$location" | grep -q "attacker.com"; then
    echo "REDIRECT FOUND: ?$param= → $location"
  fi
done
```

## BYPASS TECHNIQUES

```bash
# When simple https://attacker.com is blocked:
//attacker.com                    # protocol-relative
/\attacker.com                    # backslash (IE/Edge interpret as /)
https:attacker.com                # missing //
https://target.com@attacker.com   # credentials confusion
https://attacker.com#target.com   # fragment
https://attacker.com%2Ftarget.com # encoded /
https://attacker.com?target.com   # parameter confusion
https://attacker.com/.target.com  # dot after hostname

# Unicode / IDN homograph
https://аttacker.com              # Cyrillic а

# Null byte
https://attacker.com%00.target.com

# CRLF in redirect (HTTP response splitting)
/redirect?url=https://attacker.com%0d%0aSet-Cookie:%20malicious=1
```

## SEVERITY NOTE

Standalone open redirect = Low/Medium
Open redirect + OAuth = High (token theft)
Open redirect + SSRF chain = Critical
Open redirect used in active phishing campaign = Medium/High
