# ASSET MODULE — WebApp
# Covers: PHP, Node.js, Python (Django/Flask), Java (Spring/JSP), Ruby on Rails,
#         Go, .NET, GraphQL APIs, REST APIs, SOAP services
# Report ID prefix: WEB

## THREAT MODEL

Web applications accept untrusted input over HTTP and process it server-side.
The primary attack surface is the HTTP boundary: parameters, headers, cookies,
file uploads, and request bodies that flow into dangerous server-side operations.

Authentication and authorization boundaries are equally critical:
who can call what, and whether those checks are enforced server-side.

## VULNERABILITY CLASSES (priority order)

1.  SQL Injection (SQLi)              CWE-89   — DB query construction
2.  Stored XSS                        CWE-79   — persistent HTML injection
3.  Reflected XSS                     CWE-79   — non-persistent HTML injection
4.  Remote Code Execution (RCE)       CWE-94   — OS command / eval injection
5.  Server-Side Request Forgery       CWE-918  — internal network access
6.  Insecure Deserialization          CWE-502  — object injection
7.  XML External Entity (XXE)         CWE-611  — XML parser abuse
8.  Broken Access Control / IDOR      CWE-639  — horizontal/vertical privesc
9.  CSRF                              CWE-352  — state-change without user consent
10. Server-Side Template Injection    CWE-94   — template engine code execution
11. Path Traversal / LFI              CWE-22   — file system access
12. Authentication Bypass             CWE-287  — login logic flaws
13. JWT Vulnerabilities               CWE-347  — signature bypass
14. Mass Assignment                   CWE-915  — ORM parameter binding
15. Open Redirect                     CWE-601  — URL redirect abuse
16. Business Logic Flaws              CWE-840  — workflow abuse

## WHITEBOX GREP PATTERNS

### PHP
```bash
# SQL Injection
grep -rn "mysqli_query\|mysql_query\|PDO::query\|\$pdo->query\|\$db->query" --include="*.php"
grep -rn "\$wpdb->query\|\$wpdb->get_results\|\$wpdb->get_var\|\$wpdb->get_row" --include="*.php"
grep -rn "SELECT.*\$_\|INSERT.*\$_\|UPDATE.*\$_\|DELETE.*\$_\|WHERE.*\$_" --include="*.php"
# Verify: is prepare() used? Is it parameterized correctly?

# XSS — output sinks
grep -rn "echo \$_\|print \$_\|echo \$[a-z]" --include="*.php"
grep -rn "<?=\s*\$" --include="*.php"
# Verify: esc_html / esc_attr / esc_url / htmlspecialchars / htmlentities used?

# RCE
grep -rn "system(\|exec(\|passthru(\|shell_exec(\|popen(\|proc_open(" --include="*.php"
grep -rn "eval(\|assert(\|preg_replace.*\/e\b" --include="*.php"
grep -rn "include(\|require(\|include_once(\|require_once(" --include="*.php"

# SSRF
grep -rn "curl_exec\|curl_setopt\|file_get_contents\|fopen(" --include="*.php"
grep -rn "CURLOPT_URL\|http_get\|fetch(" --include="*.php"

# XXE
grep -rn "simplexml_load\|DOMDocument\|XMLReader\|xml_parse\|SimpleXMLElement" --include="*.php"
# Verify: libxml_disable_entity_loader(true) called before parsing?

# Deserialization
grep -rn "unserialize(\|maybe_unserialize(" --include="*.php"
# Any user-controlled data reaching unserialize() is Critical

# CSRF
grep -rn "wp_verify_nonce\|check_admin_referer\|check_ajax_referer" --include="*.php"
# Flag every state-changing action WITHOUT nonce verification

# WordPress-specific
grep -rn "wp_ajax_\|wp_ajax_nopriv_" --include="*.php"
grep -rn "register_rest_route\|add_shortcode" --include="*.php"
grep -rn "current_user_can\|is_admin" --include="*.php"
grep -rn "update_option\|update_post_meta\|\$wpdb->insert\|\$wpdb->update" --include="*.php"
```

### Node.js / JavaScript
```bash
# SQL Injection
grep -rn "\.query(\|\.execute(\|\.raw(" --include="*.js" --include="*.ts"
grep -rn "SELECT.*\`\|INSERT.*\`\|UPDATE.*\`\|DELETE.*\`" --include="*.js" --include="*.ts"

# XSS
grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML\|document\.write" --include="*.js" --include="*.ts"
grep -rn "dangerouslySetInnerHTML\|v-html\|bypassSecurityTrust" --include="*.js" --include="*.ts"

# RCE
grep -rn "child_process\|exec(\|spawn(\|execSync(\|eval(\|new Function(" --include="*.js" --include="*.ts"

# SSRF
grep -rn "fetch(\|axios\.\|request(\|http\.get\|https\.get" --include="*.js" --include="*.ts"

# Prototype Pollution
grep -rn "merge(\|extend(\|assign(\|clone(" --include="*.js" --include="*.ts"
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts"

# Deserialization
grep -rn "JSON\.parse\|serialize\|unserialize\|yaml\.load\b" --include="*.js" --include="*.ts"
# yaml.load (not safeLoad) is dangerous
```

### Python
```bash
# SQL Injection
grep -rn "execute(\|cursor\.\|raw(\|\.objects\.raw(" --include="*.py"
grep -rn "SELECT.*%s\|SELECT.*format\|SELECT.*f\"" --include="*.py"

# RCE
grep -rn "os\.system\|subprocess\|eval(\|exec(\|compile(" --include="*.py"
grep -rn "pickle\.loads\|yaml\.load\b\|marshal\.loads" --include="*.py"

# SSTI
grep -rn "render_template_string\|Template(\|Jinja2\|jinja2\.Template" --include="*.py"

# SSRF
grep -rn "requests\.get\|requests\.post\|urllib\.request\|httpx\." --include="*.py"
```

### Java
```bash
# SQL Injection
grep -rn "createStatement\|executeQuery\|executeUpdate\|prepareStatement" --include="*.java"
grep -rn "\"SELECT.*\+\|\"INSERT.*\+\|\"UPDATE.*\+\|\"DELETE.*\+" --include="*.java"

# RCE
grep -rn "Runtime\.getRuntime\|ProcessBuilder\|ScriptEngine\|eval(" --include="*.java"
grep -rn "ObjectInputStream\|readObject(\|XMLDecoder" --include="*.java"

# XXE
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory" --include="*.java"
grep -rn "setFeature.*http://xml.org/sax/features/external" --include="*.java"
```

## BLACKBOX TESTING PLAYBOOK

### Injection probes (send to every parameter)
```
SQLi time-based:  ' AND SLEEP(5)--  |  '; WAITFOR DELAY '0:0:5'--
SQLi error:       '  "  ;  )  --  #
XSS:              "><script>alert(document.domain)</script>
                  '"><img src=x onerror=alert(1)>
SSTI:             {{7*7}}  ${7*7}  <%= 7*7 %>  #{7*7}
Path traversal:   ../../../etc/passwd  ....//....//etc/passwd
SSRF:             http://127.0.0.1  http://169.254.169.254/latest/meta-data/
XXE:              <!DOCTYPE x [<!ENTITY t SYSTEM "file:///etc/passwd">]><x>&t;</x>
```

### Auth testing checklist
- Password reset: Host header injection, token in referrer, token reuse
- JWT: alg:none, RS256→HS256 confusion, weak secret (jwt_tool --crack)
- OAuth: redirect_uri bypass, missing state param, token leakage in logs
- Session: fixation, parallel sessions, logout invalidation
- IDOR: increment/decrement IDs, swap UUIDs, change username in body

### GraphQL specific
```
# Introspection (should be disabled in production)
{"query": "{__schema{types{name fields{name}}}}"}

# Batch query abuse for rate limit bypass
[{"query":"mutation{login(u:\"admin\",p:\"pass1\")}"},
 {"query":"mutation{login(u:\"admin\",p:\"pass2\")}"}]

# Nested query DoS (report only if no depth limit)
```

## ENVIRONMENT SETUP (whitebox)

WordPress plugins:
  docker run -d -p 8080:80 -v $(pwd):/var/www/html/wp-content/plugins/target wordpress
  wp core install --url=localhost:8080 --title=Test --admin_user=admin --admin_password=admin --admin_email=test@test.com

Node.js:
  npm install && npm start (check package.json for start script)

PHP generic:
  php -S localhost:8080 -t ./public

Python Django:
  pip install -r requirements.txt && python manage.py runserver 8080

Java Spring:
  mvn spring-boot:run  |  gradle bootRun

---

## ADDITIONAL VULN MODULES

When the target uses these technologies or you want a focused scan,
load the corresponding module:

| Technology / Vector | Module path | Invoke with |
|---|---|---|
| GraphQL API | asset/webapp/vuln/graphql.md | --vuln graphql |
| Node.js / JS (prototype pollution) | asset/webapp/vuln/prototype_pollution.md | --vuln pp |
| iframe / cross-frame messaging | asset/webapp/vuln/postmessage.md | --vuln postmessage |
| CDN / reverse proxy | asset/webapp/vuln/web_cache_poisoning.md | --vuln wcp |
| HTTP/1.1 + proxy stack | asset/webapp/vuln/http_smuggling.md | --vuln smuggling |
| Cross-origin API access | asset/webapp/vuln/cors.md | --vuln cors |
| npm / pip / Maven deps | shared/vuln/supply_chain.md | --vuln supplychain |

Auto-load triggers (researcher loads these automatically if detected):
- If graphql or apollo found in package.json → load graphql.md
- If lodash/merge/deepmerge found AND Node.js → load prototype_pollution.md
- If addEventListener message found in JS → load postmessage.md
- If package.json / requirements.txt present → load supply_chain.md

---

## COMPLETE VULN MODULE INDEX (v3)

All available vuln modules for webapp. Auto-loaded when detected; manually with --vuln flag.

| Module | --vuln flag | Auto-load trigger |
|---|---|---|
| vuln/graphql.md | graphql | graphql/apollo in package.json |
| vuln/prototype_pollution.md | pp | lodash/merge/deepmerge in deps |
| vuln/postmessage.md | postmessage | addEventListener message in JS |
| vuln/web_cache_poisoning.md | wcp | CDN/proxy config present |
| vuln/http_smuggling.md | smuggling | proxy/nginx config present |
| vuln/cors.md | cors | Access-Control headers in code |
| vuln/deserialization.md | deser | unserialize/readObject/pickle in code |
| vuln/file_upload.md | upload | move_uploaded_file/$_FILES/multer |
| vuln/ssti_csti.md | ssti | render_template_string/Template( in code |
| vuln/auth_flaws.md | auth | login/session/password-reset endpoints |
| vuln/race_condition.md | race | payment/coupon/limit endpoints |
| vuln/xxe.md | xxe | XML parsers in code |
| vuln/nosqli.md | nosql | MongoDB/Redis/CouchDB in deps |
| vuln/business_logic.md | bizlogic | payment/coupon/workflow endpoints |
| vuln/open_redirect.md | redirect | Location header / redirect params |
| vuln/websocket.md | websocket | WebSocket endpoints |
| vuln/clickjacking.md | clickjacking | missing X-Frame-Options |
| vuln/redos.md | redos | regex patterns on user input |
| vuln/injection_other.md | injection | LDAP/XPath/SMTP/CSS endpoints |
| vuln/cloud_misconfig.md | cloud | S3/Firebase/actuator endpoints |
| vuln/mass_assignment.md | mass | ORM create/update with req.body |
| shared/vuln/supply_chain.md | supplychain | package.json/requirements.txt present |
