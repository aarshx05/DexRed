# CodexSec — Mobile Application Security Module

This module activates when the target is a mobile application or its backend API. Combines backend API testing with mobile-specific attack vectors.

## OWASP Mobile Top 10 (2024) Checklist

### M1: Improper Credential Usage

**Hardcoded Credentials in APK/IPA:**
```bash
# Decompile Android APK
apktool d target.apk -o decompiled/

# Search for hardcoded secrets
grep -rn "api_key\|apikey\|secret\|password\|token\|auth" decompiled/ --include="*.xml" --include="*.smali"
grep -rn "AIza\|AKIA\|sk-\|ghp_\|glpat-" decompiled/  # Known API key patterns

# Decompile to Java for better readability
jadx -d jadx_output/ target.apk
grep -rn "api_key\|apikey\|secret\|password\|token" jadx_output/ --include="*.java"

# Check for Firebase/AWS/GCP credentials
grep -rn "firebaseio.com\|amazonaws.com\|googleapis.com" jadx_output/ --include="*.java"
grep -rn "google-services.json\|GoogleService-Info.plist" decompiled/
```

**API Key Exposure:**
```bash
# Check if API keys in the app are restricted
# Test key without app signature/bundle ID
curl -s -H "X-API-Key: EXTRACTED_KEY" "https://TARGET_API/endpoint"

# Test key from different IP/origin (should be restricted)
# Check if key has unnecessary permissions (read+write when only read needed)
```

### M2: Inadequate Supply Chain Security
```bash
# Check third-party libraries for known vulnerabilities
# List dependencies from the APK
cat decompiled/apktool.yml | grep -A 50 "unknownFiles"
find jadx_output/ -name "*.java" -path "*/lib/*" | head -20

# Check for outdated/vulnerable SDKs
grep -rn "com.google.firebase\|com.facebook\|com.squareup" jadx_output/build.gradle 2>/dev/null
```

### M3: Insecure Authentication/Authorization
```bash
# Test backend API auth mechanisms
# Can you access API endpoints without the mobile app's special headers?
curl -s "https://TARGET_API/api/user/profile" -H "Authorization: Bearer TOKEN"

# Remove mobile-specific headers (X-App-Version, X-Device-ID, etc.)
curl -s "https://TARGET_API/api/user/profile" -H "Authorization: Bearer TOKEN" \
  # Note: intentionally omitting X-Device-ID, X-Platform headers

# Test if backend validates that the token belongs to a mobile session
# Reuse a web token on mobile endpoints and vice versa

# Biometric bypass — check if biometric auth is just a local check
# or if the server actually validates biometric proof
```

### M4: Insufficient Input/Output Validation
```bash
# Test API parameters that the mobile app normally constrains via UI
# The app may limit input to a dropdown, but the API may accept anything
curl -s -X POST "https://TARGET_API/api/update-profile" \
  -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "<script>alert(1)</script>", "age": -1, "role": "admin"}'

# Test with oversized inputs (the app may truncate but the API may not)
python3 -c "print('A' * 100000)" | curl -s -X POST "https://TARGET_API/api/field" \
  -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d @-
```

### M5: Insecure Communication
```bash
# Check for certificate pinning
# If pinning is implemented, test bypass:
# Frida script for SSL pinning bypass
frida -U -l ssl_bypass.js -f com.target.app

# Check for cleartext traffic
grep -rn "http://" jadx_output/ --include="*.java" | grep -v "https://"
grep -rn "cleartextTrafficPermitted" decompiled/AndroidManifest.xml

# Check network_security_config.xml
cat decompiled/res/xml/network_security_config.xml 2>/dev/null

# Intercept and analyze API traffic
# Set up mitmproxy, install CA cert on device
mitmproxy --mode regular --listen-port 8080
```

### M6: Inadequate Privacy Controls
```bash
# Check what data is stored locally
# Android shared preferences
find decompiled/ -name "*.xml" -path "*shared_prefs*"

# iOS Keychain/plist analysis (if IPA available)
# Check if sensitive data is in plist files
find . -name "*.plist" -exec plutil -p {} \;

# Check if the API returns more data than the app displays
# (common: API returns full user object but app only shows name)
curl -s "https://TARGET_API/api/users/me" -H "Authorization: Bearer TOKEN" | python3 -m json.tool
```

### M7: Insufficient Binary Protections
```bash
# Check for obfuscation
jadx -d jadx_output/ target.apk
# If class/method names are readable (not a/b/c), no obfuscation

# Check for root/jailbreak detection
grep -rn "isRooted\|isJailbroken\|su \|Superuser\|/system/xbin" jadx_output/ --include="*.java"

# Check for debug flag
grep -rn "android:debuggable" decompiled/AndroidManifest.xml

# Check for exported components
grep -rn "exported=\"true\"" decompiled/AndroidManifest.xml
```

### M8: Security Misconfiguration
```bash
# Android Manifest analysis
cat decompiled/AndroidManifest.xml

# Check for:
# - android:allowBackup="true" (data extractable via adb backup)
# - android:debuggable="true"
# - Exported activities/services/receivers/providers without permission checks
# - Custom permissions with protectionLevel="normal"
# - Intent filters that expose internal functionality

# Check for insecure WebView configuration
grep -rn "setJavaScriptEnabled(true)\|addJavascriptInterface\|setAllowFileAccess" jadx_output/ --include="*.java"
```

### M9: Insecure Data Storage
```bash
# Check for sensitive data in SQLite databases
find /data/data/com.target.app/ -name "*.db" 2>/dev/null
# Use sqlite3 to inspect tables for tokens, passwords, PII

# Check for sensitive data in log output
adb logcat -d | grep -i "token\|password\|secret\|key"

# Check for sensitive data in the app's cache/temp directories
find /data/data/com.target.app/cache/ -type f 2>/dev/null
```

### M10: Insufficient Cryptography
```bash
# Search for weak crypto usage in decompiled code
grep -rn "DES\|MD5\|SHA1\|ECB\|AES/ECB\|SecureRandom" jadx_output/ --include="*.java"
grep -rn "hardcoded.*key\|static.*key\|final.*key" jadx_output/ --include="*.java"

# Check if the app uses its own crypto instead of standard libraries
grep -rn "encrypt\|decrypt\|cipher" jadx_output/ --include="*.java" | grep -v "javax.crypto"
```

## Deep Link / Intent Abuse

```bash
# Extract deep links from manifest
grep -rn "scheme\|host\|pathPattern\|pathPrefix" decompiled/AndroidManifest.xml

# Test deep link injection
# If the app registers: myapp://action?param=value
# Test: myapp://action?param=javascript:alert(1)
# Test: myapp://action?param=../../sensitive-data
# Test: myapp://settings/admin (access admin functions via deep link)

adb shell am start -a android.intent.action.VIEW -d "myapp://transfer?to=attacker&amount=1000"
```

## API Backend Testing (Mobile-Specific)

Mobile APIs often have weaker security than web APIs because developers assume the mobile app enforces business logic.

```bash
# Capture all API endpoints by intercepting traffic
mitmproxy --mode regular -w traffic_dump.flow

# Replay requests outside the app context
# This removes all client-side validation

# Test for missing server-side validation of:
# - Input ranges (the app slider limits 1-100, but API accepts 0 or 99999)
# - Step order (the app enforces a wizard flow, but API accepts any order)
# - Feature access (premium features may only be hidden client-side)
# - Rate limiting (the app throttles locally, but API has no server-side limit)

# Test for version-specific endpoints
for v in v1 v2 v3 v4; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET_API/api/$v/users")
  echo "/api/$v/users -> $code"
done
# Older API versions may lack security fixes
```

## Frida Dynamic Analysis

```bash
# Hook crypto functions to capture keys/plaintext
frida -U -l crypto_hooks.js -f com.target.app

# Bypass root detection
frida -U -l root_bypass.js -f com.target.app

# Bypass SSL pinning
frida -U -l ssl_bypass.js -f com.target.app

# Trace API calls to find hidden endpoints
frida-trace -U -i "HttpURLConnection*" -f com.target.app

# Objection (Frida-based, higher level)
objection -g com.target.app explore
# > android sslpinning disable
# > android root disable
# > android hooking list classes
# > android hooking watch class com.target.app.api.ApiClient
```
