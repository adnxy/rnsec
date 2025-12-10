# rnsec

<p align="center">
  <strong>🔒 Professional Security Scanner for React Native & Expo</strong>
</p>

<p align="center">
  Static analysis tool detecting 62+ security vulnerabilities in mobile applications
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#security-checks">Security Checks</a> •
  <a href="#cicd-integration">CI/CD</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Why rnsec?

**Comprehensive Coverage**: 62 security rules across 13 categories including storage, network, authentication, cryptography, and platform-specific vulnerabilities.

**API Key Detection**: Automatically identifies 27+ types of exposed secrets (Firebase, AWS, Stripe, GitHub, Slack, etc.)

**Platform-Specific**: Dedicated scanners for Android (AndroidManifest.xml) and iOS (Info.plist) with 14+ mobile-specific checks.

**Production Ready**: Zero configuration, fast scanning, and multiple output formats for development and CI/CD workflows.

## Installation

```bash
npm install -g rnsec
```

<details>
<summary>Install from source</summary>

```bash
git clone https://github.com/yourusername/rnsec.git
cd rnsec
npm install
npm run build
npm link
```
</details>

## Quick Start

```bash
# Scan your project
rnsec scan

# Generate interactive HTML report
rnsec scan --html report.html

# View all available rules
rnsec rules
```

## Usage

### Command Line Options

```bash
rnsec scan [options]

Options:
  -p, --path <path>        Path to project root (default: ".")
  --json                   Output results as JSON
  --html <filename>        Generate HTML report
  --output <filename>      Save JSON results to file
  --silent                 Suppress console output
```

### Examples

```bash
# Scan current directory with HTML report
rnsec scan --html security-report.html

# Scan specific project with JSON output
rnsec scan --path ./my-app --json

# Generate report for CI/CD
rnsec scan --output results.json --silent
```

## Security Checks

rnsec includes **62 security rules** organized into 13 categories:

| Category | Rules | Key Checks |
|----------|-------|------------|
| 🔐 **Storage** | 5 | AsyncStorage sensitive data, hardcoded secrets, PII encryption |
| 🌐 **Network** | 10 | HTTP usage, WebView security, SSL/TLS configuration |
| 🔑 **Authentication** | 7 | JWT validation, biometric fallback, session management |
| 🔐 **Cryptography** | 2 | Weak algorithms (MD5/SHA1), hardcoded keys |
| 📝 **Logging** | 1 | Sensitive data in logs |
| 📱 **React Native** | 12 | Bridge security, deep links, eval() usage, XSS |
| 🔓 **Secrets** | 2 | API keys (27+ patterns), exposed credentials |
| 🐛 **Debug** | 6 | Test credentials, debug endpoints, dev tools |
| 🤖 **Android** | 7 | Manifest misconfigurations, exported components |
| 🍎 **iOS** | 7 | Info.plist issues, ATS exceptions, permissions |
| ⚙️ **Configuration** | 1 | Dangerous permissions |

<details>
<summary><strong>View All 62 Rules</strong></summary>

### 🔐 Storage Security (5 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `ASYNCSTORAGE_SENSITIVE_KEY` | HIGH | Detects sensitive data stored in AsyncStorage (tokens, passwords, credentials) |
| `HARDCODED_SECRETS` | HIGH | Identifies hardcoded API keys, JWT tokens, AWS credentials, and secrets |
| `ASYNCSTORAGE_PII_DATA` | HIGH | AsyncStorage storing PII (email, phone, SSN) without encryption |
| `REDUX_PERSIST_NO_ENCRYPTION` | MEDIUM | Redux persist configuration without encryption transform for sensitive data |
| `CLIPBOARD_SENSITIVE_DATA` | MEDIUM | Sensitive data copied to clipboard (accessible by other apps) |

### 🌐 Network Security (10 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `INSECURE_HTTP_URL` | MEDIUM | Detects HTTP URLs in fetch(), axios, and API calls (should use HTTPS) |
| `INSECURE_WEBVIEW` | HIGH | Identifies WebView components with dangerous configurations |
| `WEBVIEW_JAVASCRIPT_INJECTION` | HIGH | WebView with JavaScript enabled loading dynamic or user-controlled content |
| `WEBVIEW_FILE_ACCESS` | HIGH | WebView with file access enabled - allows access to local files |
| `WEBVIEW_DOM_STORAGE_ENABLED` | MEDIUM | WebView with DOM storage enabled - may expose sensitive data |
| `WEBVIEW_GEOLOCATION_ENABLED` | MEDIUM | WebView with geolocation enabled - requires proper permission handling |
| `WEBVIEW_MIXED_CONTENT` | MEDIUM | WebView allows mixed content - HTTPS pages can load HTTP resources |
| `WEBVIEW_UNVALIDATED_NAVIGATION` | HIGH | WebView without URL validation on navigation - potential open redirect |
| `WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK` | HIGH | WebView onMessage handler without origin validation |
| `WEBVIEW_CACHING_ENABLED` | LOW | WebView with caching enabled - may cache sensitive content |

### 🔑 Authentication & Authorization (7 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `INSECURE_RANDOM` | HIGH | Detects use of Math.random() for security-sensitive operations |
| `JWT_NO_EXPIRY_CHECK` | MEDIUM | JWT token retrieved from storage without expiration validation |
| `TEXT_INPUT_NO_SECURE` | MEDIUM | TextInput for passwords without secureTextEntry property |
| `BIOMETRIC_NO_FALLBACK` | MEDIUM | Biometric authentication without PIN/password fallback |
| `SESSION_TIMEOUT_MISSING` | LOW | No session timeout or inactivity logout detected |
| `OAUTH_TOKEN_IN_URL` | HIGH | OAuth/access token passed in URL query parameters |
| `CERT_PINNING_DISABLED` | HIGH | SSL certificate pinning disabled or bypassed |

### 🔐 Cryptography (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `WEAK_HASH_ALGORITHM` | HIGH | Detects weak hashing algorithms (MD5, SHA1) |
| `HARDCODED_ENCRYPTION_KEY` | HIGH | Identifies hardcoded encryption keys and IVs |

### 📝 Logging (1 rule)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `SENSITIVE_LOGGING` | MEDIUM | Detects console.log() statements containing sensitive data |

### 📱 React Native Specific (12 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `JAVASCRIPT_ENABLED_BRIDGE` | HIGH | Detects dangerous JavaScript bridge interactions with native modules |
| `DEBUGGER_ENABLED_PRODUCTION` | MEDIUM | Identifies debugger statements and debug code in production |
| `INSECURE_DEEPLINK_HANDLER` | HIGH | Detects deep link handlers without proper URL validation |
| `FLATLIST_SENSITIVE_DATA` | LOW | FlatList rendering sensitive financial or PII data without removeClippedSubviews |
| `EXPO_SECURE_STORE_FALLBACK` | MEDIUM | Expo SecureStore used without checking availability or fallback |
| `ANIMATED_TIMING_SENSITIVE` | LOW | Sensitive data visible during animations or transitions |
| `TOUCHABLEOPACITY_SENSITIVE_ACTION` | MEDIUM | Destructive or financial action without confirmation dialog |
| `SCREENSHOT_PROTECTION_MISSING` | MEDIUM | Sensitive screen without screenshot/screen recording protection |
| `ROOT_DETECTION_MISSING` | LOW | No root/jailbreak detection for sensitive application |
| `UNSAFE_DANGEROUSLY_SET_INNER_HTML` | HIGH | dangerouslySetInnerHTML used with potentially unsafe content |
| `NETWORK_LOGGER_IN_PRODUCTION` | MEDIUM | Network request/response logging enabled - may expose sensitive data |
| `EVAL_USAGE` | HIGH | eval() used - code injection risk |

### 🔓 API Keys & Secrets Detection (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `API_KEY_EXPOSED` | HIGH | Detects 27+ types of API keys: Firebase, AWS, Stripe, GitHub, Slack, Twilio, SendGrid, etc. |
| `ENV_FILE_COMMITTED` | HIGH | Environment file with secrets potentially committed to repository |

### 🐛 Debug & Development Artifacts (6 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `TEST_CREDENTIALS_IN_CODE` | MEDIUM | Test credentials or example passwords found in source code |
| `DEBUG_ENDPOINTS_EXPOSED` | MEDIUM | Debug or development endpoints exposed in production code |
| `REDUX_DEVTOOLS_ENABLED` | MEDIUM | Redux DevTools enabled in production |
| `STORYBOOK_IN_PRODUCTION` | LOW | Storybook imports detected in production code |
| `SOURCEMAP_REFERENCE` | LOW | Source map reference in production bundle |
| `ALERT_IN_PRODUCTION` | LOW | Alert or prompt used in production code (development artifact) |

### 🤖 Android Security (7 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `ANDROID_CLEARTEXT_ENABLED` | HIGH | android:usesCleartextTraffic="true" in manifest |
| `ANDROID_DEBUGGABLE_ENABLED` | HIGH | android:debuggable="true" in production manifest |
| `ANDROID_BACKUP_ALLOWED` | MEDIUM | android:allowBackup="true" for sensitive app |
| `ANDROID_EXPORTED_COMPONENT` | HIGH | Exported Android component without permission protection |
| `ANDROID_INTENT_FILTER_PERMISSIVE` | MEDIUM | Overly permissive intent filter may expose functionality |
| `ANDROID_NETWORK_SECURITY_CONFIG_MISSING` | MEDIUM | Network security config not configured |
| `ANDROID_UNPROTECTED_RECEIVER` | HIGH | Broadcast receiver without permission protection |
| `ANDROID_CONTENT_PROVIDER_NO_PERMISSION` | HIGH | Content provider without read/write permissions |

### 🍎 iOS Security (7 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `IOS_ATS_DISABLED` | HIGH | App Transport Security (ATS) disabled (NSAllowsArbitraryLoads) |
| `IOS_USAGE_DESCRIPTIONS_MISSING` | MEDIUM | Missing iOS usage description for privacy-sensitive permission |
| `IOS_BACKGROUND_MODES_UNNECESSARY` | MEDIUM | Potentially unnecessary background modes enabled |
| `IOS_UNIVERSAL_LINKS_MISCONFIGURED` | MEDIUM | Universal links configured without proper validation |
| `IOS_CUSTOM_URL_SCHEME_UNPROTECTED` | MEDIUM | Custom URL scheme without validation code |
| `IOS_KEYCHAIN_ACCESS_GROUP_INSECURE` | MEDIUM | Keychain access group configuration may expose data |
| `IOS_DATA_PROTECTION_MISSING` | LOW | Data protection entitlement not configured for sensitive app |
| `IOS_ATS_EXCEPTION_TOO_PERMISSIVE` | HIGH | App Transport Security exception too permissive |

### ⚙️ Configuration (1 rule)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `EXPO_INSECURE_PERMISSIONS` | LOW | Flags potentially dangerous permissions in app.json |

</details>

### 🔍 API Key Detection

The `API_KEY_EXPOSED` rule detects 27+ types of exposed secrets:

**Cloud Providers**: Firebase, AWS (Access Keys, Secrets), Google Cloud, Heroku, DigitalOcean  
**Payment**: Stripe (Live, Restricted, Publishable), PayPal  
**Communication**: Twilio, SendGrid, Mailgun, Mailchimp, Slack  
**Development**: GitHub (PAT, OAuth), GitLab  
**Cryptographic**: Private Keys (RSA, SSH, PGP), Certificates  
**Authentication**: JWT, Bearer Tokens, Basic Auth, OAuth Client Secrets

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm install -g rnsec
      - run: rnsec scan --output security-results.json
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-results.json
```

### Exit Codes

- `0`: No high-severity issues found
- `1`: High-severity vulnerabilities detected (fails CI/CD)

## Examples

Test the scanner with sample projects in the `examples/` directory:

```bash
# Scan vulnerable app (35+ issues)
rnsec scan examples/vulnerable-app --html vulnerable-report.html

# Scan secure app (minimal issues)
rnsec scan examples/secure-app --html secure-report.html
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-rule`
3. Make your changes and test with examples
4. Commit: `git commit -m 'Add new security rule'`
5. Push: `git push origin feature/new-rule`
6. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/yourusername/rnsec.git
cd rnsec
npm install
npm run build
```

### Adding New Security Rules

1. Create or modify a scanner in `src/scanners/`
2. Follow the `Rule` interface pattern
3. Test with `examples/vulnerable-app`
4. Update README with rule details

### Project Structure

```
src/
├── cli/              # Command-line interface
├── core/             # Scanning engine (AST parser, file walker, rule engine)
├── scanners/         # 13 security scanners with 62 rules
├── types/            # TypeScript definitions
└── utils/            # Helper functions
```

## License

MIT License - see [LICENSE](LICENSE) for details

## Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/rnsec/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/rnsec/discussions)
- 📖 **Documentation**: [Wiki](https://github.com/yourusername/rnsec/wiki)

---

<p align="center">
  Built with ❤️ for the React Native community
</p>
