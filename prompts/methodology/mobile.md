# Mobile Application Security Testing Methodology

Loaded when `app_type = "mobile"`. Reference: OWASP MASTG, MASVS v2.

## Approach

Mobile pentesting via this harness focuses on the **backend API** and **application package analysis**. The agent cannot interact with a physical device, but it can:
- Decompile and analyze APK/IPA packages
- Test backend APIs the app communicates with
- Identify hardcoded secrets, insecure configurations, and API vulnerabilities
- Analyze certificate pinning implementation
- Test for insecure data storage patterns

## Phase 1: Static Analysis (Package)

### APK Analysis (Android)
1. Decompile: `apktool d app.apk -o decompiled/`
2. Decompile to Java: `jadx app.apk -d jadx-output/`
3. Search for hardcoded secrets:
   - `grep -rn "api_key\|apikey\|secret\|password\|token\|AWS_\|firebase" jadx-output/`
   - `grep -rn "http://\|https://" jadx-output/` (find all API endpoints)
   - `trufflehog filesystem jadx-output/`
4. Check AndroidManifest.xml:
   - Exported components (activities, services, receivers, providers)
   - Permissions (overprivileged?)
   - `android:debuggable="true"`
   - `android:allowBackup="true"`
   - Custom URL schemes (deep links)
   - Network security config: `android:networkSecurityConfig`
5. Check network_security_config.xml:
   - Certificate pinning implementation
   - cleartext traffic allowed?
   - Trust anchors configuration
6. Check for insecure storage:
   - SharedPreferences usage patterns
   - SQLite database usage (encrypted?)
   - File storage permissions

### Certificate Pinning Analysis
1. Check for pinning libraries: OkHttp CertificatePinner, TrustManager, network_security_config pins
2. Identify pinned domains and certificate hashes
3. Check if pinning can be bypassed via:
   - Missing root CA validation
   - Pinning only in certain code paths
   - Debug/staging builds without pinning

### Deep Link Analysis
1. Extract from AndroidManifest: `<intent-filter>` with `<data>` schemes
2. Test for open redirect via deep links
3. Test for unauthorized actions via deep links
4. Check if deep links validate caller/referrer

## Phase 2: Backend API Testing

Apply the full Web/API methodology (see web.md) with these mobile-specific additions:

### API Key Extraction
1. Extract all API endpoints and keys from decompiled source
2. Test if API keys work without app-specific headers
3. Check if rate limiting is per-key or per-user
4. Test API key rotation/revocation

### Mobile-Specific API Tests
1. Test without mobile-specific headers (User-Agent, X-App-Version, X-Device-ID)
2. Test with older app version headers (may access deprecated, unpatched endpoints)
3. Test certificate pinning bypass by calling APIs directly with curl
4. Check if APIs enforce app attestation (SafetyNet/Play Integrity, DeviceCheck)
5. Test push notification token handling
6. Test device registration/deregistration flows

### Authentication
1. Test biometric auth bypass: Does the API rely on client-side biometric check only?
2. Test token storage: Are refresh tokens properly scoped?
3. Test session management: Multiple device support, forced logout
4. Test account takeover via phone number/device ID reuse

## Phase 3: Dynamic Patterns

### Data Leakage
1. Check API responses for excessive data (full user objects when only name needed)
2. Test logging endpoints for information disclosure
3. Check error messages for stack traces, internal IPs, database info
4. Test analytics/telemetry endpoints for data exposure

### Business Logic
1. Test in-app purchase validation (receipt replay, modified receipts)
2. Test premium feature access without subscription
3. Test referral/reward systems for abuse
4. Test offline mode data synchronization for race conditions
