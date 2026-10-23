# Changelog

All notable changes to rnsec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.4.0] - 2026-10-23

### New rules, CI features and far fewer false positives

rnsec now ships **105 rules** (87 in 1.3.0): 18 new rules, SARIF output, baselines, a configurable failure threshold and a much quieter scanner. No rule ID was removed or renamed, so existing `ignoredRules` entries keep working. Read the upgrade notes below before updating a CI pipeline: some changes surface findings that were hidden before.

### Added

#### New rules (18)

- `ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT` (HIGH/MEDIUM): `network_security_config.xml` permits cleartext (HTTP) traffic; `debug-overrides` is ignored
- `ANDROID_SIGNING_CREDENTIALS_HARDCODED` (HIGH): literal `storePassword`/`keyPassword` in `build.gradle(.kts)` (debug config exempt) and signing passwords in tracked `gradle.properties`
- `ANDROID_USER_CA_TRUSTED` (MEDIUM): `network_security_config.xml` trusts user-installed CAs or sets `overridePins`
- `BUNDLED_ENV_SECRET` (HIGH/MEDIUM): secret-named `EXPO_PUBLIC_*`, `react-native-config` and `@env` values, which ship in the app bundle
- `COMMITTED_CREDENTIAL_FILE` (HIGH/MEDIUM): git-tracked signing keys and certificates (`.jks`, `.keystore` other than `debug.keystore`, `.p12`/`.pfx`, `.p8`), `.mobileprovision` profiles and service-account JSON files
- `DEPENDENCY_NONREGISTRY_SOURCE` (MEDIUM/LOW): dependencies installed from git, tarball URLs or an unbounded version such as `latest`
- `EAS_JSON_SECRET_IN_ENV` (HIGH/MEDIUM): secret-named literals in `eas.json` build `env`
- `EXPO_CONFIG_INSECURE_SETTINGS` (HIGH/MEDIUM/LOW): `allowBackup: true`, `usesCleartextTraffic: true`, ATS disabled and `UIFileSharingEnabled` in `app.json` / `app.config.*` (checked per platform, and skipped for a platform whose native project is committed, where the native-file rules apply)
- `HARDCODED_BASIC_AUTH_CREDENTIALS` (HIGH): `scheme://user:pass@host` URLs and base64-encoded `user:pass` literals
- `IOS_FILE_SHARING_ENABLED` (LOW/MEDIUM): `UIFileSharingEnabled` exposes the Documents directory through Finder/Files
- `JWT_INSECURE_SIGNING` (HIGH): literal secret passed to `jsonwebtoken`/`jose`/`jws`/`jwt-simple` (and similar) sign/verify, hardcoded `secret`/`secretOrKey` options, `algorithms: ['none']`
- `MMKV_UNENCRYPTED_SENSITIVE_DATA` (MEDIUM): sensitive keys in an unencrypted `react-native-mmkv` instance, or a hardcoded `encryptionKey`
- `NPM_REGISTRY_CONFIG_INSECURE` (HIGH/MEDIUM): literal auth tokens, `strict-ssl=false` and plain-http registries in tracked `.npmrc` / `.yarnrc.yml`
- `OAUTH_INSECURE_FLOW` (MEDIUM): `usePKCE: false`, implicit flow (`response_type=token`), `useNonce: false`
- `SQLITE_QUERY_INJECTION` (HIGH/MEDIUM): SQL built with string interpolation instead of bound parameters (`expo-sqlite`, `op-sqlite`, `react-native-sqlite-storage`); HIGH when the value looks user-controlled
- `TLS_VALIDATION_DISABLED_ENV` (HIGH): `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` and similar process-wide or property-assignment disabling of TLS validation
- `WEAK_CIPHER_OR_MODE` (HIGH/MEDIUM): DES/3DES/RC4/Blowfish, ECB block mode and hardcoded IVs
- `WEBVIEW_ORIGIN_WHITELIST_WILDCARD` (HIGH/MEDIUM/LOW): `originWhitelist={['*']}`; LOW for bundled static content, HIGH for dynamic sources

Secrets in `expo.extra` and the other Expo config sections are reported by the existing `EXPO_SENSITIVE_CONFIG_EXPOSED` rule, which now also reads `app.config.*`, classifies names (`SECRET`, `PASSWORD`, `PRIVATE_KEY`, ...) and skips public SDK identifiers.

#### CI and workflow features

- **SARIF 2.1.0 output**: `--sarif <file>` for GitHub Code Scanning (`github/codeql-action/upload-sarif`). Paths are relative to the git root and results carry stable fingerprints.
- **Baselines**: `--write-baseline <file>` records the current findings and exits 0; `--baseline <file>` (or `baseline` in the config) hides them. Findings are matched by a fingerprint of rule, path and source line text, not by line number.
- **`--fail-on <high|medium|low|none>`** and `failOn` in the config choose which severities fail the scan (default `high`).
- **`severityOverrides`** in the config: `{ "RULE_ID": "HIGH" | "MEDIUM" | "LOW" }`, applied to reports, SARIF and the exit code.
- **Inline suppression**: `// rnsec-ignore: RULE_ID [reason]` on the same line or the line above (`<!-- -->` in XML/plist, several IDs separated by commas). A rule ID is required.
- **`confidence`** (`high`/`medium`/`low`) on findings and `--min-confidence <level>` to filter by it.
- **`.gitignore` support**: git-ignored files are skipped; `--no-gitignore` or `respectGitignore: false` turns that off.
- **JSONC config**: `.rnsec.json`, `.rnsec.jsonc` or `.rnsec.config.json` (in that order), with comments and trailing commas allowed; parse errors are reported.

#### Scanner coverage

- The file walker now also collects native sources (`.java`, `.kt`, `.swift`, `.m`, `.mm`), `.entitlements`, `network_security_config.xml` and other Android `src/*/res/xml/*.xml`, `eas.json`, `build.gradle(.kts)`, Firebase `*.rules` / `*.rules.json` / `firebase.json`, lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`) and, when git tracks them, `gradle.properties`, `.npmrc`/`.yarnrc.yml`, `.env*`, signing keys and service-account files, and `sentry.properties` / `keystore.properties` / `signing.properties` / `credentials.json`. Rules registered for those file types (such as secret detection) now see them. Vendored and generated code, Pods and build output are excluded.
- `.env*` files are now actually scanned (`ENV_FILE_COMMITTED` never fired in 1.3.0), but only when git tracks them. Generic API-key detection in `.env` requires the variable name to end in key/secret, so `*_API_KEY_ISSUER_ID` and `*_KEY_ID` are not reported.
- Rules can see the project's declared dependencies (root `package.json`), so absence rules no longer guess from words in a file.
- `INSECURE_KEYCHAIN_USAGE` also detects `Keychain.ACCESSIBLE.ALWAYS` / `SecureStore.ALWAYS*`; `CERT_PINNING_DISABLED` also covers `disableAllSecurity: true` (react-native-ssl-pinning).
- Test suite: `npm test` builds, then runs `node --test` over `tests/*.test.mjs` with fixtures in `tests/cases/`.

### Upgrade notes (CI behaviour can change)

- **More findings can appear, including HIGH ones.** The old debug-context filter dropped *every* finding in a file as soon as one line contained `__DEV__ &&`, `DEBUG &&` and similar. Suppression is now local to the guarded code (`if (__DEV__)`, `__DEV__ && x`, ternaries, `NODE_ENV` checks; `else` branches are not suppressed), so previously hidden findings may now fail your build. Use `--write-baseline` to adopt the new results gradually.
- **`.gitignore` is respected.** Findings in git-ignored files disappear. Pass `--no-gitignore` or set `respectGitignore: false` to restore the old behaviour.
- **`--json` stdout is pure JSON.** Informational lines now go to stderr, and piped `--json` output is no longer truncated at 8 KB (the process used to exit before stdout was flushed).
- **Severity changes:**
  - Public-by-design keys are now LOW: Firebase web `AIza` keys, Stripe `pk_` keys, Google OAuth client IDs and Sentry DSNs. Stripe `sk_test_` keys are LOW too, because test-mode keys cannot move real money.
  - `NO_REQUEST_TIMEOUT` is now LOW.
  - `ROOT_JAILBREAK_DETECTION_ABSENT` and `MISSING_RUNTIME_INTEGRITY_CHECKS` dropped from HIGH/MEDIUM to LOW with low confidence. They fire only in the app entry file (`index`/`App`), and only when `package.json` dependencies or the file's imports include a payments, banking, crypto-wallet or health SDK (Stripe, Plaid, `react-native-iap`, `ethers`, `react-native-health`, ...) and no detection library.
  - `EXPO_SECURE_STORE_WEAK_OPTIONS` no longer flags `AFTER_FIRST_UNLOCK`, which Apple recommends for data needed in the background.
  - Heuristic rules report a lower `confidence`.
- **Same-line duplicates are merged** by "dedup families" (`src/core/ruleEngine.ts`): for example `EVAL_USAGE` and `INSECURE_DESERIALIZATION` on a line that `OBFUSCATED_EVAL_EXECUTION` already reports, or `HARDCODED_SECRETS` next to a provider-specific `API_KEY_EXPOSED`. Finding counts drop; the most specific rule is kept.
- **Exit code:** still 1 only for HIGH findings by default, but now configurable with `--fail-on` / `failOn`. Errors also exit 1.
- **Node.js 20 or newer is required** (`engines` was `>=18`).

### Fixed

- `ASYNCSTORAGE_SENSITIVE_KEY` flags `last_token` / `lastToken` / `lastAuthToken`-style keys again. An over-broad "last" qualifier had dropped them; this restores the 1.3.0 behaviour.
- `--changed-files`:
  - with `--path` pointing at a monorepo subfolder it used to scan nothing without saying so; it now works (`git diff --relative`);
  - **security:** the git ref was interpolated into a shell command. It is now passed to git without a shell, and refs starting with `-` are rejected;
  - unreadable changed files are reported on stderr again;
  - the default and configured excludes now apply.
- When a folder is not a git checkout, rnsec prints a stderr notice that `.env`, credential and registry-config files were not checked (they are only reported when git tracks them).
- Plain `.ts` files are now parsed without the JSX plugin, so files that use `<Type>value` type assertions no longer fail to parse (in 1.3.0 every AST-based rule skipped them).
- A rule that throws is reported under `RNSEC_VERBOSE` instead of looking like a clean scan.
- Path exclusions match segments relative to the scan root, so projects under a folder named `dev` or `assets` are no longer skipped entirely.
- Secrets are reported once: a single Firebase web key gave three `API_KEY_EXPOSED` findings on one line in 1.3.0 (HIGH, HIGH, MEDIUM) and now gives one, at LOW because the key is public by design. Placeholder words such as "example" are checked against the secret value only, so a real key a couple of lines below a `// example usage` comment is no longer missed.
- Secrets: loose patterns (Bearer, Basic, Mailgun, Twilio, Heroku) need a keyword and entropy; `mock`-named files are no longer skipped.
- `INSECURE_HTTP_URL`, `DEBUG_ENDPOINTS_EXPOSED`: localhost, `10.0.2.2` and private ranges are no longer flagged; hosts are parsed instead of regex-matched.
- `SENSITIVE_LOGGING` no longer flags sensitive words inside plain string literals (`console.log('Password reset email sent')` was MEDIUM in 1.3.0).
- `INSECURE_RANDOM` follows the value into security-sensitive names (token, nonce, otp, salt, session, key): `const otp = Math.floor(Math.random() * 1e6)` was missed in 1.3.0 and is HIGH now, while `chartSeed = Math.random()` stays quiet.
- `TEST_CREDENTIALS_IN_CODE` no longer matches `bypass`/`passport`.
- `WEAK_HASH_ALGORITHM` (checksums/ETags are LOW), `EVAL_USAGE` (constant arguments ignored), `THIRD_PARTY_SDK_RISK` (imports/dependencies, not substrings).
- `IOS_CUSTOM_URL_SCHEME_UNPROTECTED` never fired because of a plist parsing bug (a lazy regex stopped at the inner `</array>`). It now reports custom URL schemes once per `Info.plist`, as LOW with low confidence; its declared severity changes from MEDIUM to LOW.
- `IOS_UNIVERSAL_LINKS_MISCONFIGURED` now reads `*.entitlements` files, where associated domains are declared. It ignores Apple's `?mode=developer` / `?mode=managed` suffix and reports line numbers.
- `REDUX_DEVTOOLS_ENABLED` also detects the TypeScript form `(window as any).__REDUX_DEVTOOLS_EXTENSION__`.
- `HARDCODED_ENCRYPTION_KEY` and `HARDCODED_SECRETS` no longer both report the same line; the encryption-key rule wins.
- The default severity shown by `rnsec rules` and in SARIF rule metadata now matches what these rules report: `IOS_BACKGROUND_MODES_UNNECESSARY` (LOW), `IOS_ATS_EXCEPTION_TOO_PERMISSIVE` (MEDIUM), `SCREENSHOT_PROTECTION_MISSING` (MEDIUM), `DEBUG_ENDPOINTS_EXPOSED` (HIGH). The findings themselves are unchanged.
- `SUSPICIOUS_LIFECYCLE_SCRIPT`: `patch-package || true` and similar known-benign tools are no longer flagged.
- Native config: launcher activities and permission-protected components are not "exported" findings; backup rules honour `dataExtractionRules`; `NSAllowsLocalNetworking`-only ATS is fine; XML/plist findings now carry line numbers.
- AsyncStorage rules follow import aliases and wrappers and match keys by whole words (`tokenizer_enabled` is no longer a token).
- WebView rules no longer fire on static HTML sources; `dangerouslySetInnerHTML` through a sanitizer is LOW.

### Removed noise (behaviour changes)

- `INSECURE_DESERIALIZATION` no longer reports `JSON.parse()`; it cannot execute code. The `eval`/`Function` branch is unchanged.
- `IMPROPER_BIOMETRIC_FALLBACK` no longer reports "no fallback found" for any file that mentions biometrics; device-passcode fallback is the platform default. Hardcoded PIN/password fallbacks are still reported.
- `SENSITIVE_DATA_IN_ERROR_MESSAGES` reports console-only error logging as LOW.
- JS bundled under `android/app/src/*/assets/` is treated as non-first-party and skipped.
- `ROOT_JAILBREAK_DETECTION_ABSENT` / `MISSING_RUNTIME_INTEGRITY_CHECKS` no longer fire on projects that are not payments/banking/crypto/health apps (see the upgrade notes).

### Known gaps

- Typosquat detection (DEPENDENCY_POSSIBLE_TYPOSQUAT) was not shipped because of its false-positive risk.
- CodePush code signing is not covered. Expo Updates signing is (`EXPO_UPDATES_NO_CODE_SIGNING`, since 1.3.0).
- Expo config rules only read literal values in `app.config.js|ts`.
- `network_security_config.xml` is scanned directly; it is not resolved through the manifest's `android:networkSecurityConfig`.
- Checks that need git tracking (`.env`, credential files, `.npmrc`, `gradle.properties`) need a git checkout.

---

## [1.3.0] - 2026-04-19

> This entry was reconstructed after the fact: 1.3.0 was published to npm without a changelog entry. It lists the rules added since 1.2.0 (67 to 87 rule IDs), with their severities as released in 1.3.0; some rules reported other levels depending on context.

### Added

- `ANDROID_MISSING_NETWORK_SECURITY_CONFIG` (MEDIUM): manifest has no network security config reference
- `ANDROID_TASK_AFFINITY_VULNERABILITY` (MEDIUM): activity with a custom `taskAffinity`, open to task hijacking
- `ANDROID_WEBVIEW_DEBUG_ENABLED` (HIGH): WebView debugging enabled, allowing remote inspection
- `CUSTOM_CRYPTO_IMPLEMENTATION` (HIGH): hand-rolled cryptography instead of a standard library
- `EXPO_AUTH_SESSION_NO_PKCE` (HIGH): Expo AuthSession used without PKCE
- `EXPO_SECURE_STORE_WEAK_OPTIONS` (MEDIUM): SecureStore used with weak accessibility options
- `EXPO_SENSITIVE_CONFIG_EXPOSED` (HIGH): sensitive values in the Expo `app.json` configuration, including `expo.extra`
- `EXPO_UPDATES_INSECURE_URL` (HIGH): Expo updates URL over plain HTTP
- `EXPO_UPDATES_NO_CODE_SIGNING` (HIGH): Expo OTA updates without code signing verification
- `HARDCODED_IP_ADDRESS` (MEDIUM, LOW for private addresses): hardcoded IP address in production code
- `INSECURE_LINKING_OPEN` (HIGH): `Linking.openURL` called with unvalidated user-controlled input
- `INSECURE_WEBSOCKET` (MEDIUM): unencrypted `ws://` connection
- `IOS_INSECURE_PASTEBOARD_USAGE` (MEDIUM): sensitive data written to the iOS pasteboard
- `IOS_MISSING_APP_SNAPSHOT_PROTECTION` (LOW): sensitive app without snapshot protection when backgrounded
- `MISSING_SESSION_TIMEOUT` (MEDIUM): authentication session without a timeout or inactivity expiry
- `MMKV_NO_ENCRYPTION` (HIGH): MMKV used without encryption for sensitive data
- `PUSH_NOTIFICATION_SENSITIVE_DATA` (MEDIUM): push notification handler processing sensitive data without protection
- `SENSITIVE_NAVIGATION_PARAMS` (MEDIUM): sensitive data passed through React Navigation params
- `UNENCRYPTED_REALM_DATABASE` (HIGH): Realm database opened without encryption in a sensitive context
- `UNENCRYPTED_SQLITE_DATABASE` (HIGH): SQLite database used without encryption for sensitive data

---

## [1.2.0] - 2026-03-05

### Supply chain security rules

This release adds **2 new rules** to detect supply chain–style risks: malicious or hijacked commits that add dangerous install scripts (e.g. postinstall/preinstall running obfuscated code).

### Added

1. **SUSPICIOUS_LIFECYCLE_SCRIPT** (package.json) – HIGH
   - Flags `postinstall`, `preinstall`, or `install` scripts that run `node` on:
     - A file under `.github/workflows/*.js` (e.g. `node ./.github/workflows/deploy.js`)
     - Root-level `preinstall.js` or `postinstall.js`
   - Flags any such script ending with `|| true` (hides script failure; common in malicious commits)

2. **OBFUSCATED_EVAL_EXECUTION** (JS/TS) – HIGH
   - Detects `eval(Buffer.from(...).toString('utf-8'))` (or equivalent), the pattern used in many malicious install scripts to run decoded payloads

### Other

- Added test fixture `examples/supply-chain-test/` for validating these rules (do not run `npm install` there)
- Documentation: DEVELOPMENT.md updated with how to test supply-chain rules

---

## [1.1.0] - 2026-01-18

### Major Feature Release

This release significantly expands rnsec's security coverage with **16 new high-impact rules**, improved context-aware detection, and better false positive filtering.

### Added

#### New HIGH Severity Rules

1. **INSECURE_KEYSTORE_USAGE** (Android)
   - Detects improper Android Keystore usage
   - Flags `BLOCK_MODE_ECB` (insecure block mode)
   - Identifies missing user authentication requirements
   - Checks for missing StrongBox backing

2. **INSECURE_KEYCHAIN_USAGE** (iOS)
   - Detects `kSecAttrAccessibleAlways` (insecure keychain access)
   - Flags missing `kSecAttrAccessControl` (no biometric protection)
   - Ensures keychain items require device authentication

3. **ROOT_JAILBREAK_DETECTION_ABSENT** (React Native)
   - Critical for banking, fintech, and healthcare apps
   - Detects missing root/jailbreak detection
   - Helps prevent attacks on compromised devices

4. **MISSING_RUNTIME_INTEGRITY_CHECKS** (React Native)
   - Detects missing tamper detection
   - Identifies missing code signature verification
   - Checks for missing Play Integrity API / App Attest usage

5. **INSECURE_DESERIALIZATION** (React Native)
   - Detects `JSON.parse()` on untrusted input
   - Flags `eval()`-like dynamic object construction
   - Identifies unsafe native deserialization

#### New MEDIUM Severity Rules

6. **SENSITIVE_DATA_IN_ERROR_MESSAGES** (Logging)
   - Detects backend errors exposed directly to UI
   - Flags production stack traces shown to users
   - Prevents information disclosure vulnerabilities

7. **IMPROPER_BIOMETRIC_FALLBACK** (Authentication)
   - Detects biometric auth with insecure fallbacks
   - Flags plaintext password fallbacks
   - Identifies PIN stored in JavaScript memory

8. **NO_REQUEST_TIMEOUT** (Network)
   - Detects network requests without timeout configuration
   - Prevents denial-of-service (DoS) risks
   - Ensures proper timeout handling for fetch/axios/xhr

9. **WEAK_TLS_CONFIGURATION** (Network)
   - Detects TLS < 1.2 usage
   - Flags custom `httpsAgent` with insecure options
   - Identifies disabled certificate validation

10. **INSECURE_FILE_STORAGE** (Storage)
    - Detects files written to external/shared storage
    - Flags unencrypted file writes
    - Checks for proper file encryption on sensitive data

#### New LOW/INFO Severity Rules

11. **EXCESSIVE_PERMISSIONS** (Android)
    - Detects Android permissions declared but unused in code
    - Helps minimize attack surface
    - Improves privacy compliance

12. **THIRD_PARTY_SDK_RISK** (React Native)
    - Flags known risky SDKs (session replay, invasive analytics)
    - Identifies ad SDKs in sensitive apps (banking, healthcare)
    - Helps maintain user privacy

13. **MISSING_SECURITY_HEADERS** (WebView)
    - Detects missing Content-Security-Policy (CSP)
    - Flags missing X-Frame-Options
    - Improves web content security

### Improved

- **Context-Aware Detection**: `INSECURE_RANDOM` now only triggers HIGH severity when actually used in security-sensitive contexts (token/key generation)
- **Rule Reclassification**: `CERT_PINNING_DISABLED` moved from HIGH → MEDIUM severity (reflects real-world usage patterns)
- **False Positive Reduction**: Enhanced debug context filtering to eliminate noise
- **Performance**: Optimized rule engine for faster scans on large codebases

### Removed

Eliminated low-value rules that created false positives and reduced developer trust:

- `ANIMATED_TIMING_SENSITIVE` (subjective UX concern, not security)
- `TOUCHABLEOPACITY_SENSITIVE_ACTION` (no clear exploit model)
- `FLATLIST_SENSITIVE_DATA` (too broad, unreliable detection)
- `SESSION_TIMEOUT_MISSING` (product decision, not vulnerability)
- `BIOMETRIC_NO_FALLBACK` (replaced by `IMPROPER_BIOMETRIC_FALLBACK`)
- `EXPO_SECURE_STORE_FALLBACK` (false positives)
- `ANDROID_NETWORK_SECURITY_CONFIG_MISSING` (too opinionated)
- `ALERT_IN_PRODUCTION` (not a security issue)
- `STORYBOOK_IN_PRODUCTION` (dev artifact, not security threat)
- `SOURCEMAP_REFERENCE` (dev artifact, not security threat)
- `DEBUGGER_ENABLED_PRODUCTION` (dev artifact, not security threat)

### Statistics

- **Total Rules**: 63 → 66 security rules
- **Coverage**: Android, iOS, React Native, Network, Storage, Auth, Crypto, Logging, WebView
- **Detection Patterns**: 27+ API key patterns, 15+ crypto patterns, 20+ network patterns
- **Scan Speed**: < 100ms for most projects

### Bug Fixes

- Fixed TypeScript errors in `webviewScanner.ts` with null safety checks
- Fixed `authenticationScanner.ts` missing rule exports
- Improved HTML report rendering for edge cases
- Fixed line number display in code snippets

### Security

- All new rules thoroughly tested for false positives
- Enhanced AST-based detection for accuracy
- Improved pattern matching for secrets detection

---

## [1.0.1] - 2026-01-17

### Bug Fixes

- Fixed CI/CD workflows for GitHub Actions
- Improved CodeQL integration
- Enhanced security audit workflow
- Fixed npm package metadata

### Documentation

- Added professional open-source project files
- Created CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md
- Added GitHub issue and PR templates
- Enhanced README with badges and examples

---

## [1.0.0] - 2026-01-16

### Initial Release

The first public release of **rnsec** - React Native Security Scanner!

#### Core Features

- Complete static analysis engine with AST-based parsing
- 53 comprehensive security rules across 13 categories
- Beautiful HTML report generation with syntax highlighting
- JSON output for CI/CD integration
- Terminal output with color-coded severity levels
- Zero configuration required

#### Platform Support

- macOS
- Linux
- Windows
- Node.js 18+ required

#### File Types Analyzed

- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Android Manifests (.xml)
- iOS Plists (.plist)
- Configuration files (.json)

#### Security Categories

- Storage Security
- Network Security
- Authentication & Authorization
- Cryptography
- Logging
- React Native Specific
- API Keys & Secrets Detection
- Debug & Production Security
- Android Platform
- iOS Platform
- Configuration
- WebView Security

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute to rnsec.

## Questions?

- Email: adnanpoviolabs@gmail.com
- Issues: https://github.com/adnxy/rnsec/issues
- Sponsor: https://github.com/sponsors/adnxy
- Star us: https://github.com/adnxy/rnsec

---

**Made with love for the React Native security community**
