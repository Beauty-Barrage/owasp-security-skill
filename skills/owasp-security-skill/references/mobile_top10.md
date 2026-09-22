# OWASP Mobile Top 10 (2024) Reference: React Native Guide

This reference focuses on security controls and auditing patterns for React Native applications targeting iOS and Android platforms.

---

## 1. M1: Improper Credential Usage

### Risk Description
Hardcoding API tokens, private cryptographic keys, AWS/Azure access keys, or third-party service secrets directly within JavaScript bundles, native Gradle files, or Info.plist files.

### Auditing Rules:
* Inspect mobile source directories (e.g. `src/`) for strings matching `key=`, `secret=`, `token=`, `bearer `, or `password`.
* Ensure secrets used for background jobs or build automation are injected via CI/CD environment variables or Azure Key Vault, never committed to git.
* Native release signing configs in `android/app/build.gradle` must read keystore passwords from environment variables or gradle properties outside version control.

---

## 2. M2: Inadequate Supply Chain Security

### Risk Description
Vulnerable third-party npm packages, native CocoaPods, or Android Gradle dependencies containing known CVEs.

### Auditing Rules:
* Review `package.json` and lockfiles regularly against `npm audit`.
* Check for deprecated or unmaintained native modules.
* Verify package integrity with signed locks.

---

## 3. M3: Insecure Authentication / Authorization

### Risk Description
Client-side authorization bypasses, flawed token refresh mechanisms, or failure to handle session invalidation from backend services.

### Vulnerable Pattern (`ApiClient.ts`):
```typescript
// VULNERABLE: Only handling 401/403 while server 500s on expired tokens
// leaves user in a "zombie" authenticated state where all actions fail.
if (response.status === 401 || response.status === 403) {
  store.dispatch(logout());
}
// Any 500 status simply toasts "Having trouble connecting" and retains bad token
```

### Secure Pattern:
```typescript
// SECURE: Robust interceptor recognizing auth pipeline degradation
if (response.status === 401 || response.status === 403) {
  store.dispatch(logout());
} else if (response.status >= 500 && isAuthEndpoint(url)) {
  consecutiveAuthFailures++;
  if (consecutiveAuthFailures >= 3) {
    promptSessionReauth();
  }
}
```

---

## 4. M4: Insufficient Input / Output Validation

### Risk Description
Failure to validate data received from deep links (`Linking.openURL`), push notifications (FCM), or camera/photo uploads before rendering or transmitting to backend APIs.

### Auditing Rules:
* Validate deep link schemes and query parameters before routing.
* Restrict image upload MIME types and enforce file size limits on the client before executing multipart uploads.
* Verify survey form inputs sanitize against script injection before submitting JSON payloads.

---

## 5. M5: Insecure Communication

### Risk Description
Transmitting sensitive payload data (credentials, GPS coordinates, personal data) over unencrypted channels or failing to validate TLS certificates.

### Auditing Rules:
* **iOS:** Ensure `NSAppTransportSecurity` in `Info.plist` does **NOT** set `NSAllowsArbitraryLoads: true`.
* **Android:** Ensure `res/xml/network_security_config.xml` enforces `<cleartextTrafficPermitted="false">`.
* Ensure all API calls in `ApiClient.ts` use strictly `https://` URLs.

---

## 6. M9: Insecure Data Storage

### Risk Description
Storing unencrypted sensitive data (auth tokens, refresh tokens, user PII, compensation rates) in plain `AsyncStorage` or SQLite/WatermelonDB.

### Storage Comparison:
| Storage Mechanism | Encrypted? | Hardware Backed? | Recommended Usage |
|---|:---:|:---:|---|
| **`@react-native-async-storage/async-storage`** | ❌ No | ❌ No | UI preferences, cache flags, theme settings. |
| **`react-native-keychain`** | ✅ Yes | ✅ Yes (Keychain / KeyStore) | Auth tokens, refresh tokens, biometric keys. |
| **`react-native-encrypted-storage`** | ✅ Yes | ✅ Yes (Keystore / KeyRing) | User profile PII, sensitive survey drafts. |

### Rule:
Never store JWT session tokens or employee passwords directly in `AsyncStorage`.
