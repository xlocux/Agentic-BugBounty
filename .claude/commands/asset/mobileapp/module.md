# ASSET MODULE — MobileApp
# Covers: Android (APK), iOS (IPA)
# Report ID prefix: MOB

## THREAT MODEL

Mobile apps run on user-controlled devices. Attackers can:
  - Reverse engineer the app binary to extract secrets and logic
  - Intercept network traffic (certificate pinning bypass)
  - Access local storage on rooted/jailbroken devices
  - Abuse exported components (Android) or deep links (iOS)
  - Exploit WebViews that load attacker-controlled content

## VULNERABILITY CLASSES (priority order)

1.  Hardcoded Secrets / API Keys        CWE-798  — secrets in binary
2.  Insecure Data Storage               CWE-312  — sensitive data on disk
3.  Improper Certificate Validation     CWE-295  — MITM via pinning bypass
4.  Exported Activity / Deep Link Abuse CWE-926  — Android component exposure
5.  WebView XSS / JavaScript Injection  CWE-79   — WebView attack surface
6.  Insecure IPC / Intent Injection     CWE-927  — Android Intent abuse
7.  Weak Cryptography                   CWE-327  — ECB mode, MD5, SHA1
8.  Sensitive Data in Logs / Backups    CWE-532  — logcat, cloud backup
9.  Path Traversal via Content Provider CWE-22   — Android file provider abuse
10. Broken Authentication               CWE-287  — token storage, biometric bypass

## DECOMPILATION NOTE

The pipeline decompiles the APK before launching this agent.
If the target path points to a directory (not an `.apk`/`.apkx` file), decompilation is already done — do NOT run `apktool` or `jadx` again.

Check once:
```bash
# If target is a directory → already decompiled, skip to static analysis
# If target is a file ending in .apk/.apkx → decompile first (fallback case)
ls "$TARGET"   # directory = skip decompilation
```

---

## WHITEBOX STATIC ANALYSIS

### Android (APK / Java / Kotlin)
```bash
# Decompile APK (only if target is a .apk/.apkx file, not already a directory)
apktool d target.apk -o ./decompiled
jadx -d ./jadx-output target.apk

# Hardcoded secrets
grep -rn "api_key\|apikey\|secret\|password\|token\|AWS\|private_key" ./jadx-output --include="*.java" -i
grep -rn "BuildConfig\." ./jadx-output --include="*.java"

# Network security
grep -rn "ALLOW_ALL_HOSTNAME_VERIFIER\|TrustAllCerts\|X509TrustManager" ./jadx-output --include="*.java"
grep -rn "onReceivedSslError\|proceed()" ./jadx-output --include="*.java"
# Any proceed() in onReceivedSslError = cert validation disabled

# WebView
grep -rn "setJavaScriptEnabled\|addJavascriptInterface\|loadUrl\|evaluateJavascript" ./jadx-output --include="*.java"
grep -rn "setAllowFileAccess\|setAllowUniversalAccessFromFileURLs" ./jadx-output --include="*.java"

# Exported components (check AndroidManifest.xml)
grep -n "exported=\"true\"\|android:exported" ./decompiled/AndroidManifest.xml
grep -n "<intent-filter>" ./decompiled/AndroidManifest.xml

# Insecure storage
grep -rn "SharedPreferences\|getSharedPreferences\|MODE_WORLD_READABLE" ./jadx-output --include="*.java"
grep -rn "openFileOutput\|SQLiteDatabase\|Room\b" ./jadx-output --include="*.java"
grep -rn "Log\.d\|Log\.e\|Log\.v\|Log\.i\|Log\.w" ./jadx-output --include="*.java"

# Cryptography
grep -rn "DES\|ECB\|MD5\|SHA1\b\|RC4\|AES/ECB" ./jadx-output --include="*.java"
grep -rn "SecretKeySpec\|IvParameterSpec\|Cipher\.getInstance" ./jadx-output --include="*.java"
```

### iOS (IPA / Swift / Objective-C)
```bash
# Extract IPA
unzip target.ipa -d ./ipa-extracted
find ./ipa-extracted -name "*.strings" -o -name "*.plist" | xargs grep -l "key\|secret\|token\|password" -i

# Binary analysis
strings ./ipa-extracted/Payload/App.app/App | grep -iE "api[_-]?key|secret|token|password|http://"

# Check for SSL pinning
otool -l ./ipa-extracted/Payload/App.app/App | grep -A3 "NSAppTransportSecurity"
grep -rn "pinnedCertificates\|SSLPinningMode\|TrustKit" ./src --include="*.swift" --include="*.m"

# WebView
grep -rn "WKWebView\|UIWebView\|loadHTMLString\|evaluateJavaScript" ./src --include="*.swift" --include="*.m"

# Keychain vs UserDefaults
grep -rn "UserDefaults.*password\|UserDefaults.*token\|UserDefaults.*secret" ./src --include="*.swift" -i
# Sensitive data should be in Keychain, not UserDefaults

# URL schemes / deep links
grep -rn "openURL\|handleDeepLink\|application.*openURL" ./src --include="*.swift" --include="*.m"
```

## BLACKBOX DYNAMIC ANALYSIS

### Android setup
```bash
# Root emulator
emulator -avd Pixel_6_API_33 -writable-system -no-snapshot

# Install and launch
adb install target.apk
adb shell am start -n com.example.app/.MainActivity

# Certificate pinning bypass (Frida)
frida -U -f com.example.app -l ssl-pinning-bypass.js --no-pause
# Use: https://github.com/httptoolkit/frida-android-unpinning

# Intercept traffic (after pinning bypass)
# Set Burp proxy on device, install Burp CA cert

# Logcat monitoring
adb logcat | grep -i "com.example.app\|password\|token\|key" -i

# File system inspection
adb shell run-as com.example.app ls -la /data/data/com.example.app/
adb shell run-as com.example.app cat /data/data/com.example.app/shared_prefs/*.xml
```

### iOS setup
```bash
# Jailbroken device required (checkra1n / unc0ver)
# Install Frida via Cydia

# SSL pinning bypass
frida-ios-dump -H 127.0.0.1 -p 2222 -u root TargetApp
# Objection
objection -g com.example.app explore
ios sslpinning disable

# File system
# Via Objection:
ios env
# Then navigate to app sandbox and extract files
```

## DYNAMIC TEST CHECKLIST

- [ ] Traffic intercepted without SSL errors (pinning bypassed)
- [ ] API calls send JWT/token — is it validated server-side?
- [ ] Sensitive data in request/response bodies
- [ ] Password/token stored in SharedPreferences or UserDefaults
- [ ] Sensitive data appears in logcat
- [ ] Deep links accept attacker-controlled parameters
- [ ] WebView loads external URLs — can attacker inject JS?
- [ ] Exported activities accept attacker intents
- [ ] Backup includes sensitive files (adb backup)

---

## ADDITIONAL VULN MODULES

| Technology / Vector | Module path | Invoke with |
|---|---|---|
| Deep link / Intent injection | asset/mobileapp/vuln/deep_link.md | --vuln deeplink |
| Firebase backend (Firestore/Storage) | shared/vuln/firebase.md | --vuln firebase |

Auto-load triggers:
- If `google-services.json` found in APK resources OR `firebaseio.com`/`firebasestorage` in network traffic or decompiled code → load shared/vuln/firebase.md
- If `GoogleService-Info.plist` found in IPA OR Firebase SDK imports detected in Swift/ObjC source → load shared/vuln/firebase.md
- If deep link schemes (`intent://`, custom scheme) in AndroidManifest.xml OR `openURL`/`handleDeepLink` in iOS source → load asset/mobileapp/vuln/deep_link.md
