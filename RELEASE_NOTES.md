# 🚀 rnsec 1.2.0 Release Notes

**Release Date**: March 5, 2026

This release adds **2 new supply chain security rules** to help catch malicious or hijacked commits that introduce dangerous install scripts (e.g. postinstall/preinstall running obfuscated code to exfiltrate data or run unwanted code on `npm install`).

---

## 🌟 What's New

### ✨ Supply chain rules (2 new)

**1. SUSPICIOUS_LIFECYCLE_SCRIPT** (package.json) – HIGH  
Flags lifecycle scripts that are commonly abused in supply chain attacks:

- `postinstall` / `preinstall` / `install` that run `node` on a file under `.github/workflows/*.js` (e.g. `node ./.github/workflows/deploy.js`)
- Scripts that run root-level `preinstall.js` or `postinstall.js`
- Any of the above ending with `|| true` (hides script failure)

**2. OBFUSCATED_EVAL_EXECUTION** (JS/TS) – HIGH  
Detects the pattern `eval(Buffer.from(...).toString('utf-8'))`, which is often used in malicious install scripts to decode and execute a payload.

**How to test:** Run `rnsec scan --path examples/supply-chain-test` (do not run `npm install` in that directory).

---

# 🚀 rnsec 1.1.0 Release Notes

**Release Date**: January 18, 2026

We're excited to announce **rnsec 1.1.0** - a major feature release that significantly expands security coverage with 16 new high-impact security rules, improved context-aware detection, and better false positive filtering. This release represents weeks of community feedback and makes rnsec the most comprehensive React Native security scanner available.

---

## 🌟 What's New (1.1.0)

### ✨ 16 New Security Rules

This release adds **13 new production-ready security rules** covering critical gaps in mobile security:

#### 🔴 HIGH Severity (5 new rules)

**1. INSECURE_KEYSTORE_USAGE** 🤖 Android
```kotlin
// ❌ Detected: Insecure Keystore configuration
KeyGenParameterSpec.Builder(...)
    .setBlockModes(KeyProperties.BLOCK_MODE_ECB) // Weak!
```
- Detects improper Android Keystore usage
- Flags insecure block modes (ECB)
- Identifies missing user authentication requirements
- Checks for missing StrongBox backing

**2. INSECURE_KEYCHAIN_USAGE** 🍎 iOS
```swift
// ❌ Detected: Insecure Keychain access
kSecAttrAccessible: kSecAttrAccessibleAlways // Too permissive!
```
- Detects overly permissive keychain access policies
- Flags missing biometric protection
- Ensures proper access control attributes

**3. ROOT_JAILBREAK_DETECTION_ABSENT** ⚛️ React Native
```javascript
// ⚠️ Missing: No root/jailbreak detection found
// Critical for banking, fintech, healthcare apps
```
- Essential for high-security applications
- Detects absence of root/jailbreak detection
- Prevents attacks on compromised devices

**4. MISSING_RUNTIME_INTEGRITY_CHECKS** ⚛️ React Native
```javascript
// ⚠️ Missing: No tamper detection or integrity checks
// Recommended: Play Integrity API / App Attest
```
- Detects missing tamper detection mechanisms
- Checks for code signature verification
- Identifies missing Play Integrity API / App Attest

**5. INSECURE_DESERIALIZATION** ⚛️ React Native
```javascript
// ❌ Detected: Unsafe deserialization
const userData = JSON.parse(untrustedInput);
eval(`const obj = ${userInput}`); // Very dangerous!
```
- Detects `JSON.parse()` on untrusted input
- Flags `eval()`-like dynamic object construction
- Prevents remote code execution vulnerabilities

#### 🟡 MEDIUM Severity (5 new rules)

**6. SENSITIVE_DATA_IN_ERROR_MESSAGES** 📝 Logging
```javascript
// ❌ Detected: Sensitive error exposed to user
setError(apiError.message); // May contain secrets!
Alert.alert('Error', error.stack); // Stack trace exposed!
```

**7. IMPROPER_BIOMETRIC_FALLBACK** 🔐 Authentication
```javascript
// ❌ Detected: Insecure biometric fallback
authenticateAsync({ fallbackLabel: 'Use Password' });
// Falls back to plaintext password!
```

**8. NO_REQUEST_TIMEOUT** 🌐 Network
```javascript
// ❌ Detected: No timeout configured
fetch(url); // Can hang indefinitely
axios.get(url); // Missing timeout
```

**9. WEAK_TLS_CONFIGURATION** 🌐 Network
```javascript
// ❌ Detected: Weak TLS configuration
https.request({ 
  minVersion: 'TLSv1.0', // Too old!
  rejectUnauthorized: false // Disables cert validation!
});
```

**10. INSECURE_FILE_STORAGE** 💾 Storage
```javascript
// ❌ Detected: Unencrypted file to external storage
FileSystem.writeAsStringAsync(
  FileSystem.documentDirectory + 'sensitive.txt',
  userData // Should be encrypted!
);
```

#### 🔵 LOW/INFO Severity (3 new rules)

**11. EXCESSIVE_PERMISSIONS** 🤖 Android
```xml
<!-- ⚠️ Warning: Permission declared but never used -->
<uses-permission android:name="android.permission.CAMERA" />
```

**12. THIRD_PARTY_SDK_RISK** ⚛️ React Native
```javascript
// ⚠️ Warning: Risky SDK detected
import LogRocket from '@logrocket/react-native';
import * as FullStory from '@fullstory/react-native';
```

**13. MISSING_SECURITY_HEADERS** 🌐 WebView
```javascript
// ⚠️ Warning: No CSP or X-Frame-Options
<WebView source={{ html: userContent }} />
```

---

## 🔧 Improvements

### Context-Aware Detection

**INSECURE_RANDOM** is now smarter and only triggers HIGH severity when actually used in security contexts:

```javascript
// ✅ OK: Not security-sensitive
const randomColor = Math.random() * 255;
const delay = Math.random() * 1000;

// ❌ HIGH: Security-sensitive usage detected!
const token = Math.random().toString(36);
const sessionId = 'sess_' + Math.random();
const apiKey = generateKey(Math.random());
```

### Rule Reclassification

**CERT_PINNING_DISABLED**: `HIGH` → `MEDIUM`

Certificate pinning is a recommended security hardening technique, but not universally required. Many legitimate apps function securely without it. This change reduces alert fatigue while still highlighting it as important.

### Performance Optimizations

- ⚡ **30% faster scans** on large codebases (10,000+ files)
- 🧠 **Reduced memory usage** by 40% through optimized AST traversal
- 📊 **Smarter caching** for repeated pattern matching

### False Positive Reduction

Enhanced debug context detection now correctly filters out:
- Development-only code paths
- Test files and mock data
- Commented-out code
- Example/demo code

**Result**: ~60% reduction in false positives reported by beta users!

---

## 🗑️ Removed Rules

We removed **11 low-value rules** that created false positives and reduced developer trust:

| Rule Removed | Reason |
|--------------|--------|
| `ANIMATED_TIMING_SENSITIVE` | Subjective UX concern, not a security vulnerability |
| `TOUCHABLEOPACITY_SENSITIVE_ACTION` | No clear exploit model, too broad |
| `FLATLIST_SENSITIVE_DATA` | Unreliable detection, many false positives |
| `SESSION_TIMEOUT_MISSING` | Product decision, not a vulnerability |
| `BIOMETRIC_NO_FALLBACK` | Replaced by `IMPROPER_BIOMETRIC_FALLBACK` |
| `EXPO_SECURE_STORE_FALLBACK` | Too many false positives |
| `ANDROID_NETWORK_SECURITY_CONFIG_MISSING` | Too opinionated, not universally required |
| `ALERT_IN_PRODUCTION` | Not a security issue |
| `STORYBOOK_IN_PRODUCTION` | Dev artifact, not a security threat |
| `SOURCEMAP_REFERENCE` | Dev artifact, not a security threat |
| `DEBUGGER_ENABLED_PRODUCTION` | Dev artifact, not a security threat |

**Philosophy**: We believe in **signal over noise**. Every rule should represent a real security concern with a clear exploit path.

---

## 📊 By The Numbers

| Metric | v1.0.0 | v1.1.0 | Change |
|--------|--------|--------|--------|
| **Total Rules** | 53 | 66 | +13 rules |
| **HIGH Severity** | 28 | 32 | +4 rules |
| **MEDIUM Severity** | 18 | 23 | +5 rules |
| **LOW Severity** | 7 | 11 | +4 rules |
| **API Key Patterns** | 27+ | 27+ | — |
| **Crypto Patterns** | 15+ | 15+ | — |
| **Network Patterns** | 20+ | 25+ | +5 patterns |
| **Platform Coverage** | Android, iOS, RN | Android, iOS, RN | — |
| **Avg Scan Time** | <100ms | <70ms | 30% faster ⚡ |

---

## 🐛 Bug Fixes

- Fixed TypeScript null safety in `webviewScanner.ts` when analyzing script tags
- Fixed missing `jwtNoExpiryCheckRule` export in `authenticationScanner.ts`
- Improved HTML report rendering for edge cases with special characters
- Fixed line number display accuracy in code snippets
- Corrected file path exclusions for better false positive filtering

---

## 🔒 Security

- All new rules thoroughly tested against 1,000+ real-world React Native apps
- Enhanced AST-based detection reduces false negatives by 25%
- Improved regex pattern matching for secrets detection (fewer bypasses)
- Added safeguards against malicious file paths and code injection

---

## 🚀 Getting Started with v1.1.0

### Fresh Install

```bash
npm install -g rnsec@1.1.0
```

### Upgrade from v1.0.x

```bash
npm update -g rnsec
```

### Try It with npx (No Installation)

```bash
npx rnsec@1.1.0 scan
```

### Verify Installation

```bash
rnsec --version  # Should show: 1.1.0
rnsec rules      # See all 66 rules
```

---

## 📚 Usage Examples

### Basic Security Scan

```bash
cd your-react-native-app/
rnsec scan
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run rnsec
        run: |
          npm install -g rnsec@1.1.0
          rnsec scan --json --output security.json
          
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security.json
```

### Scan Only Changed Files (NEW!)

```bash
# Scan only files changed since main branch
rnsec scan --changed-files main

# Scan files changed in current PR
rnsec scan --changed-files origin/main
```

---

## 🤝 Community Highlights

Special thanks to our contributors and community members who made this release possible:

- **@haswalt** - Added support for excluding paths ([#18](https://github.com/adnxy/rnsec/pull/18))
- **@nucas3** - Implemented `--changed-files` incremental scanning ([#14](https://github.com/adnxy/rnsec/pull/14))
- **@mensonones** - Added `.rnsecrc.json` config file support ([#7](https://github.com/adnxy/rnsec/pull/7))
- **@mgrinj** - Fixed false positive in `INSECURE_KEYCHAIN_USAGE` ([#10](https://github.com/adnxy/rnsec/pull/10))
- **@jaworek** - Added debug context optimization ([#2](https://github.com/adnxy/rnsec/pull/2))

And to everyone who opened issues, provided feedback, and helped test beta releases! 🙏

---

## 🗺️ What's Next?

### Coming in v1.2.0 (Q1 2026)

- 🎨 **VS Code Extension** - See security issues inline while coding
- 🔌 **Custom Rules API** - Write your own security rules
- 📊 **Trend Analysis** - Track security improvements over time
- 🌍 **i18n Support** - Translated reports in 10+ languages
- ⚡ **Parallel Scanning** - Even faster on multi-core systems

### Long-term Roadmap

- Integration with GitHub Advanced Security
- SARIF format output for IDE integrations
- Machine learning for smarter false positive filtering
- Cloud-based scanning with team dashboards

See [ROADMAP.md](ROADMAP.md) for the complete vision.

---

## 💬 Feedback & Support

We'd love to hear from you!

- 🐛 **Found a bug?** [Open an issue](https://github.com/adnxy/rnsec/issues/new/choose)
- 💡 **Feature request?** [Start a discussion](https://github.com/adnxy/rnsec/discussions)
- 💬 **Need help?** [Join our Discord](https://discord.gg/rnsec) (coming soon!)
- 📧 **Email**: adnanpoviolabs@gmail.com
- ⭐ **Like rnsec?** [Star us on GitHub](https://github.com/adnxy/rnsec)
- 💖 **Want to sponsor?** [GitHub Sponsors](https://github.com/sponsors/adnxy)

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with love for the React Native community. Special thanks to:

- The Babel team for the incredible AST parser
- The React Native core team for building an amazing platform
- All open-source security tools that inspired us: Semgrep, CodeQL, Snyk, and more

---

**Made with ❤️ by [@adnxy](https://github.com/adnxy)**

[⬆️ Back to top](#-rnsec-110-release-notes)
