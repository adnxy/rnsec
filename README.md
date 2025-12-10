# rnsec

Lightweight security scanner for React Native and Expo applications. Performs static analysis to detect security vulnerabilities in your mobile codebase.

## Installation

### NPM

```bash
npm install -g rnsec
```

### From Source

```bash
git clone https://github.com/yourusername/rnsec.git
cd rnsec
npm install
npm run build
npm link
```

## Usage

### Basic Scan

```bash
rnsec scan /path/to/your/project
```

### Output Formats

```bash
# JSON output
rnsec scan /path/to/your/project --json

# HTML report
rnsec scan /path/to/your/project --html
```

## Security Checks

**Total: 62 security rules** across 13 categories

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

### 🔍 Pattern Detection

The scanner detects **27+ types of API keys and secrets**:
- Firebase API Keys
- AWS Access Keys & Secrets
- Google Cloud & OAuth Keys
- Stripe Keys (Live, Restricted, Publishable)
- GitHub Tokens (Personal Access, OAuth)
- Slack Tokens & Webhooks
- Twilio API Keys
- SendGrid API Keys
- Mailgun & Mailchimp Keys
- Private Keys (RSA, SSH, PGP)
- Heroku & DigitalOcean Tokens
- JWT Tokens
- Bearer Tokens
- Basic Auth Credentials
- And more...

## Examples

The `examples/` directory contains sample projects demonstrating security issues:

### Running the Vulnerable App Example

```bash
# Scan the vulnerable app
rnsec scan examples/vulnerable-app

# Generate HTML report
rnsec scan examples/vulnerable-app --html
```

### Running the Secure App Example

```bash
# Scan the secure app (should show minimal or no issues)
rnsec scan examples/secure-app
```

The vulnerable app demonstrates common security mistakes, while the secure app shows best practices for secure React Native development.

## Contributing

We welcome contributions! Here's how to get started:

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/rnsec.git
cd rnsec

# Install dependencies
npm install

# Build the project
npm run build

# Run in development mode
npm run dev
```

### Project Structure

```
src/
├── cli/              # Command-line interface
├── core/             # Core scanning engine
│   ├── astParser.ts      # JavaScript/TypeScript AST parsing
│   ├── fileWalker.ts     # File system traversal
│   ├── ruleEngine.ts     # Rule execution engine
│   └── reporter.ts       # Report generation
├── scanners/         # Security rule implementations
│   ├── authenticationScanner.ts  # Auth & session security
│   ├── configScanner.ts          # Expo config checks
│   ├── cryptoScanner.ts          # Cryptography issues
│   ├── loggingScanner.ts         # Sensitive data logging
│   ├── manifestScanner.ts        # Basic manifest checks
│   ├── networkScanner.ts         # Network & HTTP security
│   ├── reactNativeScanner.ts     # RN-specific vulnerabilities
│   ├── storageScanner.ts         # Storage & secrets
│   ├── webviewScanner.ts         # WebView security
│   ├── secretsScanner.ts         # API key detection (27+ patterns)
│   ├── debugScanner.ts           # Debug artifacts
│   ├── androidScanner.ts         # Android-specific security
│   └── iosScanner.ts             # iOS-specific security
├── types/            # TypeScript type definitions
└── utils/            # Utility functions
```

### Adding New Rules

1. Create or modify a scanner in `src/scanners/`
2. Define your rule following the `Rule` interface
3. Add tests using the examples in `examples/vulnerable-app`
4. Update this README with your new rule

### Code Style

- Use TypeScript with strict mode
- Follow functional programming patterns
- Write clear, descriptive variable names
- Add comments for complex logic

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-rule`)
3. Commit your changes (`git commit -m 'Add amazing security rule'`)
4. Push to the branch (`git push origin feature/amazing-rule`)
5. Open a Pull Request

## License

MIT

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/rnsec/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/rnsec/discussions)

---

Built with ❤️ for the React Native community
