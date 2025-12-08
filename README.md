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

### Storage Security

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `ASYNCSTORAGE_SENSITIVE_KEY` | HIGH | Detects sensitive data stored in AsyncStorage (tokens, passwords, credentials) |
| `HARDCODED_SECRETS` | HIGH | Identifies hardcoded API keys, JWT tokens, AWS credentials, and secrets |

### Network Security

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `INSECURE_HTTP_URL` | MEDIUM | Detects HTTP URLs in fetch(), axios, and API calls (should use HTTPS) |
| `INSECURE_WEBVIEW` | HIGH | Identifies WebView components with dangerous configurations |

### Authentication Security

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `INSECURE_RANDOM` | HIGH | Detects use of Math.random() for security-sensitive operations |
| `JWT_NO_EXPIRY_CHECK` | HIGH | Identifies JWT token usage without expiration validation |
| `TEXT_INPUT_NO_SECURE` | MEDIUM | Detects TextInput for passwords without secureTextEntry |

### Cryptography Security

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `WEAK_HASH_ALGORITHM` | HIGH | Detects weak hashing algorithms (MD5, SHA1) |
| `HARDCODED_ENCRYPTION_KEY` | HIGH | Identifies hardcoded encryption keys and IVs |

### Logging Security

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `SENSITIVE_LOGGING` | MEDIUM | Detects console.log() statements containing sensitive data |

### React Native Specific

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `JAVASCRIPT_ENABLED_BRIDGE` | HIGH | Detects dangerous JavaScript bridge interactions with native modules |
| `DEBUGGER_ENABLED_PRODUCTION` | MEDIUM | Identifies debugger statements and debug code in production |
| `INSECURE_DEEPLINK_HANDLER` | HIGH | Detects deep link handlers without proper URL validation |
| `FLATLIST_SENSITIVE_DATA` | MEDIUM | Identifies FlatList rendering sensitive data without proper protection |
| `EXPO_SECURE_STORE_FALLBACK` | LOW | Detects SecureStore usage without error handling or fallback |
| `ANIMATED_TIMING_SENSITIVE` | LOW | Identifies animations revealing sensitive information |
| `TOUCHABLEOPACITY_SENSITIVE_ACTION` | MEDIUM | Detects sensitive actions without confirmation dialogs |

### Configuration Security

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `EXPO_INSECURE_PERMISSIONS` | LOW | Flags potentially dangerous permissions in app.json |
| `ANDROID_CLEARTEXT_ENABLED` | HIGH | Detects cleartext traffic enabled in AndroidManifest.xml |
| `IOS_ATS_DISABLED` | HIGH | Identifies disabled App Transport Security in iOS Info.plist |

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
│   ├── authenticationScanner.ts
│   ├── configScanner.ts
│   ├── cryptoScanner.ts
│   ├── loggingScanner.ts
│   ├── manifestScanner.ts
│   ├── networkScanner.ts
│   ├── reactNativeScanner.ts
│   └── storageScanner.ts
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
