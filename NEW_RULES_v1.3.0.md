# RNSEC v1.3.0 - New Security Rules

This document lists all new security rules added in v1.3.0. A total of **17 new rules** were added across 7 scanner modules, expanding coverage for React Native, Expo, Android, and iOS vulnerabilities.

---

## React Native / Expo Scanner (5 new rules)

### EXPO_UPDATES_NO_CODE_SIGNING
- **Severity:** HIGH
- **File Types:** `.json`
- **Description:** Detects Expo OTA updates configured in `app.json` without code signing verification. Without code signing, OTA updates can be tampered with via MITM attacks, allowing attackers to inject malicious code.
- **Detection:** Checks for `expo-updates` plugin or `updates` config without `codeSigningCertificate` or `codeSigningMetadata`.
- **False Positive Mitigation:** Only triggers when Expo updates are explicitly configured.

### INSECURE_LINKING_OPEN
- **Severity:** HIGH
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects `Linking.openURL()` called with dynamic/variable URLs without validation. Can be exploited to open malicious URL schemes (`tel:`, `sms:`, custom deep links).
- **Detection:** AST analysis for `Linking.openURL()` with non-string-literal arguments. Checks surrounding code for validation patterns (`validate`, `sanitize`, `whitelist`, `allowedSchemes`, `canOpenURL`, `startsWith('https')`).
- **False Positive Mitigation:** Only flags dynamic URLs (variables, expressions), not hardcoded string literals. Skips if validation logic is present nearby.

### SENSITIVE_NAVIGATION_PARAMS
- **Severity:** MEDIUM
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects sensitive data (passwords, tokens, API keys, SSNs, etc.) passed through React Navigation `navigate()` or `push()` params. Navigation params are serialized and may persist in navigation state, making them accessible via debugging tools.
- **Detection:** AST analysis of `navigation.navigate('Screen', { token: ... })` and `navigation.push()` calls. Inspects property keys in the params object against a list of sensitive keywords.
- **False Positive Mitigation:** Only checks property key names in the params object, not arbitrary variables.

### PUSH_NOTIFICATION_SENSITIVE_DATA
- **Severity:** MEDIUM
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects push notification handlers that log or insecurely store notification payload data containing sensitive information.
- **Detection:** Checks for push notification library imports (`expo-notifications`, `@react-native-firebase/messaging`, `react-native-push-notification`, `@notifee`), then inspects notification listener callbacks for `console.log` of notification data or `AsyncStorage` writes with sensitive keywords.
- **False Positive Mitigation:** Only triggers when both a push notification import AND insecure handling pattern are present in the same file.

### EXPO_AUTH_SESSION_NO_PKCE
- **Severity:** HIGH
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects Expo AuthSession OAuth flows with PKCE explicitly disabled (`usePKCE: false`). Without PKCE, mobile OAuth flows are vulnerable to authorization code interception attacks.
- **Detection:** Checks for `expo-auth-session` imports, then inspects `useAuthRequest()` or `startAsync()` calls for `usePKCE: false`.
- **False Positive Mitigation:** Only flags when PKCE is explicitly disabled (not when it's omitted, since Expo enables PKCE by default).

---

## Storage Scanner (3 new rules)

### UNENCRYPTED_REALM_DATABASE
- **Severity:** HIGH
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects Realm database opened without `encryptionKey` in contexts handling sensitive data. Unencrypted Realm databases can be extracted from rooted/jailbroken devices.
- **Detection:** AST analysis for `Realm.open()` and `new Realm()` calls without `encryptionKey` in config. Checks surrounding code for sensitive context keywords (`user`, `auth`, `token`, `payment`, `credential`, `account`, `medical`).
- **False Positive Mitigation:** Only triggers when sensitive data context is detected nearby. Does not flag Realm databases storing non-sensitive data.

### UNENCRYPTED_SQLITE_DATABASE
- **Severity:** HIGH
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects SQLite databases used without encryption (SQLCipher) for sensitive data storage. Plain SQLite databases can be extracted and read on compromised devices.
- **Detection:** AST analysis for `openDatabase()` and `openDatabaseAsync()` calls. Checks surrounding code for both sensitive context AND absence of encryption patterns (`sqlcipher`, `encrypt`, `cipher`, `pragma key`).
- **False Positive Mitigation:** Requires both sensitive context AND missing encryption to trigger. Skips if any encryption indicator is present.

### EXPO_SECURE_STORE_WEAK_OPTIONS
- **Severity:** MEDIUM
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects Expo SecureStore configured with weak keychain accessibility options (`AFTER_FIRST_UNLOCK` or `ALWAYS`) for sensitive keys. These options make data accessible even when the device is locked.
- **Detection:** AST analysis of `SecureStore.setItemAsync()` calls with `keychainAccessible` option. Cross-references the key name against sensitive keywords.
- **False Positive Mitigation:** Only triggers when both a weak accessibility option AND a sensitive key name are present.

---

## Network Scanner (2 new rules)

### INSECURE_WEBSOCKET
- **Severity:** MEDIUM
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects WebSocket connections using unencrypted `ws://` protocol. Data transmitted over `ws://` can be intercepted via MITM attacks.
- **Detection:** AST analysis for `new WebSocket('ws://...')` and `ws://` URL assignments to variables/properties.
- **False Positive Mitigation:** Skips localhost/private IPs when behind `__DEV__` check. Only flags URL-assigned strings (not arbitrary strings containing `ws://`).

### HARDCODED_IP_ADDRESS
- **Severity:** MEDIUM (public IPs) / LOW (private IPs)
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects hardcoded IP addresses in network URLs and API configurations. Hardcoded IPs make infrastructure changes difficult and may expose internal network topology.
- **Detection:** Regex matching for IP addresses in string literals within URL context or API config properties (`url`, `host`, `endpoint`, `server`, `api`, `base`).
- **False Positive Mitigation:** Skips test/spec/config files. Only flags IPs in URL-like or API config context (not arbitrary strings). Private IPs behind `__DEV__` are skipped. Severity is reduced to LOW for private IPs.

---

## Config Scanner (2 new rules)

### EXPO_UPDATES_INSECURE_URL
- **Severity:** HIGH
- **File Types:** `.json`
- **Description:** Detects Expo updates URL configured over insecure HTTP in `app.json`. HTTP update URLs allow MITM attackers to inject malicious code via OTA updates.
- **Detection:** Checks `expo.updates.url` in `app.json` for `http://` prefix.
- **False Positive Mitigation:** Only checks the specific `updates.url` field in Expo config.

### EXPO_SENSITIVE_CONFIG_EXPOSED
- **Severity:** HIGH
- **File Types:** `.json`
- **Description:** Detects sensitive values (API keys, secrets, passwords) hardcoded in `app.json` configuration. These values are bundled into the app binary and can be extracted.
- **Detection:** Recursively inspects `expo.extra`, `expo.ios.config`, and `expo.android.config` objects for keys matching sensitive patterns (`secret`, `apikey`, `private_key`, `password`, `client_secret`, `access_token`).
- **False Positive Mitigation:** Skips values containing `process.env`, `${`, `your_`, `placeholder`, `example`, or `xxx` (environment variable references and placeholder values).

---

## Android Scanner (3 new rules)

### ANDROID_TASK_AFFINITY_VULNERABILITY
- **Severity:** MEDIUM
- **File Types:** `.xml`
- **Description:** Detects Android activities with custom `taskAffinity` attribute, which enables StrandHogg task hijacking attacks. A malicious app can set the same task affinity to intercept the activity.
- **Detection:** Regex matching for `android:taskAffinity` in AndroidManifest.xml activities.
- **False Positive Mitigation:** Skips empty task affinity (`taskAffinity=""`), which is actually the secure configuration.

### ANDROID_WEBVIEW_DEBUG_ENABLED
- **Severity:** HIGH
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`, `.java`, `.kt`
- **Description:** Detects WebView remote debugging left enabled without a build-type guard. Allows attackers with physical access to inspect and modify WebView content via Chrome DevTools.
- **Detection:** Text search for `setWebContentsDebuggingEnabled(true)` in native code and AST analysis for `webContentsDebuggingEnabled={true}` JSX prop. Checks surrounding code for `__DEV__`, `BuildConfig.DEBUG`, or `isDebuggable` guards.
- **False Positive Mitigation:** Skips if a development/debug build check is present nearby.

### ANDROID_MISSING_NETWORK_SECURITY_CONFIG
- **Severity:** MEDIUM
- **File Types:** `.xml`
- **Description:** Detects Android manifests without a `network_security_config.xml` reference for apps that use internet permission. Without this config, the app cannot enforce certificate pinning or restrict cleartext traffic per-domain.
- **Detection:** Checks for `android:networkSecurityConfig` attribute in AndroidManifest.xml.
- **False Positive Mitigation:** Only triggers for apps with `android.permission.INTERNET` declared (networked apps).

---

## iOS Scanner (2 new rules)

### IOS_INSECURE_PASTEBOARD_USAGE
- **Severity:** MEDIUM
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`, `.m`, `.swift`
- **Description:** Detects sensitive data written to the iOS pasteboard (clipboard), which is shared across all apps on the device. On iOS versions before 14, any app can silently read the pasteboard.
- **Detection:** Text search for `UIPasteboard` or `pasteboard` usage combined with sensitive data context keywords.
- **False Positive Mitigation:** Only triggers when both pasteboard usage AND sensitive data context are found in the same file.

### IOS_MISSING_APP_SNAPSHOT_PROTECTION
- **Severity:** LOW
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects sensitive apps without protection against iOS app snapshots. iOS captures a screenshot of the app when it enters the background for the app switcher, potentially exposing sensitive data.
- **Detection:** Checks App entry files for sensitive app indicators, then looks for snapshot protection patterns (`AppState` + blur/overlay, `react-native-privacy-snapshot`, `ScreenCapture.prevent`).
- **False Positive Mitigation:** Only checks App entry point files. Requires sensitive app indicators. Checks for multiple protection library patterns.

---

## Cryptography Scanner (1 new rule)

### CUSTOM_CRYPTO_IMPLEMENTATION
- **Severity:** HIGH
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects custom/DIY cryptographic implementations instead of standard libraries. Rolling your own crypto is a well-known anti-pattern that leads to exploitable vulnerabilities.
- **Detection:** AST analysis for function declarations with names matching DIY crypto patterns (`customEncrypt`, `simpleHash`, `xorCipher`, `caesarEncrypt`, `base64EncodePassword`). Also detects XOR-based "encryption" function calls.
- **False Positive Mitigation:** Skips test/spec files and node_modules. Checks if the function body uses an established crypto library (CryptoJS, expo-crypto, tweetnacl, forge) -- if so, it's a wrapper, not DIY crypto.

---

## Authentication Scanner (1 new rule)

### MISSING_SESSION_TIMEOUT
- **Severity:** MEDIUM
- **File Types:** `.js`, `.jsx`, `.ts`, `.tsx`
- **Description:** Detects authentication/session management files without session timeout or inactivity expiry logic. Without timeouts, stolen tokens remain valid indefinitely.
- **Detection:** Checks files with auth/session/login in the filename for presence of authentication logic AND absence of timeout-related keywords (`timeout`, `expir`, `ttl`, `maxAge`, `inactivity`, `autoLogout`, `idle`).
- **False Positive Mitigation:** Only checks auth-related files (filename must contain `auth`, `session`, or `login`). Requires presence of authentication logic before flagging missing timeout.

---

## Summary

| Scanner | New Rules | Rule IDs |
|---------|-----------|----------|
| React Native / Expo | 5 | `EXPO_UPDATES_NO_CODE_SIGNING`, `INSECURE_LINKING_OPEN`, `SENSITIVE_NAVIGATION_PARAMS`, `PUSH_NOTIFICATION_SENSITIVE_DATA`, `EXPO_AUTH_SESSION_NO_PKCE` |
| Storage | 3 | `UNENCRYPTED_REALM_DATABASE`, `UNENCRYPTED_SQLITE_DATABASE`, `EXPO_SECURE_STORE_WEAK_OPTIONS` |
| Network | 2 | `INSECURE_WEBSOCKET`, `HARDCODED_IP_ADDRESS` |
| Config | 2 | `EXPO_UPDATES_INSECURE_URL`, `EXPO_SENSITIVE_CONFIG_EXPOSED` |
| Android | 3 | `ANDROID_TASK_AFFINITY_VULNERABILITY`, `ANDROID_WEBVIEW_DEBUG_ENABLED`, `ANDROID_MISSING_NETWORK_SECURITY_CONFIG` |
| iOS | 2 | `IOS_INSECURE_PASTEBOARD_USAGE`, `IOS_MISSING_APP_SNAPSHOT_PROTECTION` |
| Cryptography | 1 | `CUSTOM_CRYPTO_IMPLEMENTATION` |
| Authentication | 1 | `MISSING_SESSION_TIMEOUT` |
| **Total** | **17** | |

### Total Rule Count: 85+ (up from 68+)
