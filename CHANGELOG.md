# Changelog

All notable changes to rnsec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
