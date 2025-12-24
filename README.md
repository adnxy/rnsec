# rnsec

A zero-configuration security scanner for React Native and Expo applications that detects vulnerabilities, hardcoded secrets, and security misconfigurations with a single command.

[![npm version](https://img.shields.io/npm/v/rnsec.svg?style=flat)](https://www.npmjs.com/package/rnsec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Issues](https://img.shields.io/github/issues/adnxy/rnsec.svg)](https://github.com/adnxy/rnsec/issues)
[![GitHub Stars](https://img.shields.io/github/stars/adnxy/rnsec.svg)](https://github.com/adnxy/rnsec/stargazers)

---

## Installation

### Global Installation (Recommended)

```bash
npm install -g rnsec
```

### Using npx (No Installation Required)

```bash
npx rnsec scan
```

### Building from Source

```bash
git clone https://github.com/adnxy/rnsec.git
cd rnsec
npm install
npm run build
npm link
```

## Quick Start

Scan your React Native or Expo project:

```bash
rnsec scan
```

View the generated HTML report:

```bash
open rnsec-report.html
```

That's it. No configuration needed.

## Usage

### Basic Commands

**Scan current directory:**
```bash
rnsec scan
```

**Scan specific project:**
```bash
rnsec scan --path ./my-app
```

**Custom output filenames:**
```bash
rnsec scan --html security-report.html --output results.json
```

**CI/CD mode (silent, JSON only):**
```bash
rnsec scan --silent --output results.json
```

**Console JSON output (no files):**
```bash
rnsec scan --json
```

**View all security rules:**
```bash
rnsec rules
```

### Command Options

```bash
rnsec scan [options]

Options:
  -p, --path <path>      Project directory to scan (default: current directory)
  --html <filename>      Custom HTML report filename
  --output <filename>    Custom JSON report filename
  --json                 Output JSON to console only (no files)
  --silent               Suppress console output
  -h, --help             Display help information
  -V, --version          Display version number
```

### Exit Codes

- `0` - No high-severity issues found
- `1` - High-severity security issues detected

## What It Detects

rnsec identifies 63 different security issues across 13 categories:

**Common vulnerabilities found:**

```typescript
// Hardcoded API keys and secrets
const API_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';

// Insecure data storage
await AsyncStorage.setItem('user_token', token);

// Unencrypted HTTP requests
fetch('http://api.example.com/data');

// Weak cryptographic algorithms
const hash = MD5(password);

// Missing security properties
<TextInput value={password} />  // Missing secureTextEntry
```

## Security Rules

rnsec implements 63 security rules covering:

| Category | Rules | Description |
|----------|-------|-------------|
| **Storage** | 6 | AsyncStorage security, encryption requirements, PII handling |
| **Network** | 13 | HTTP connections, SSL/TLS validation, WebView security |
| **Authentication** | 6 | JWT handling, OAuth implementation, biometric authentication |
| **Secrets** | 2 | API key detection (27+ patterns), hardcoded credentials |
| **Cryptography** | 2 | Weak algorithms, hardcoded encryption keys |
| **Logging** | 2 | Sensitive data exposure in logs |
| **React Native** | 10 | Native bridge security, deep links, eval() usage |
| **Debug** | 3 | Test credentials, development tools in production |
| **Android** | 8 | Manifest security, Keystore issues, permission checks |
| **iOS** | 8 | App Transport Security, Keychain usage, Info.plist |
| **Config** | 1 | Dangerous permission configurations |
| **WebView** | 1 | WebView injection vulnerabilities |
| **Manifest** | 1 | Platform-specific manifest issues |

### API Key Detection

rnsec detects 27+ types of hardcoded API keys and secrets:

- AWS Access Keys, Secret Keys, Session Tokens
- Firebase API Keys
- Google Cloud API Keys, OAuth tokens
- Stripe Keys (Live, Test, Restricted)
- GitHub Personal Access Tokens
- GitLab Personal Access Tokens
- Slack Tokens, Webhooks
- Twilio API Keys, Auth Tokens
- SendGrid API Keys
- Mailgun API Keys
- Mailchimp API Keys
- Heroku API Keys
- DigitalOcean Access Tokens
- Private Keys (RSA, SSH, PGP, PKCS8)
- JWT Tokens
- Bearer Tokens
- Generic API Keys and Secrets

## Reports

rnsec generates two report formats automatically:

### HTML Report
- Interactive dashboard with filtering capabilities
- Syntax highlighting for code snippets
- Categorized findings by severity
- Quick navigation and search
- Default filename: `rnsec-report.html`

### JSON Report
- Machine-readable format for automation
- CI/CD pipeline integration
- Programmatic analysis
- Default filename: `rnsec-report.json`

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install rnsec
        run: npm install -g rnsec
      
      - name: Run security scan
        run: rnsec scan --output security.json --silent
      
      - name: Upload reports
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: |
            security.json
            rnsec-report.html
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
security-scan:
  stage: test
  image: node:18
  script:
    - npm install -g rnsec
    - rnsec scan --output security.json --silent
  artifacts:
    paths:
      - security.json
      - rnsec-report.html
    when: always
```

### Jenkins

```groovy
stage('Security Scan') {
  steps {
    sh 'npm install -g rnsec'
    sh 'rnsec scan --output security.json --silent'
    archiveArtifacts artifacts: 'security.json,rnsec-report.html', allowEmptyArchive: true
  }
}
```

## Examples

Test rnsec with included sample projects:

**Vulnerable application (35+ issues):**
```bash
rnsec scan --path examples/vulnerable-app
```

**Secure application (minimal issues):**
```bash
rnsec scan --path examples/secure-app
```

## Requirements

- **Node.js**: Version 18 or higher
- **Project Type**: React Native or Expo application

## Why Use rnsec?

### Simple
One command with zero configuration required. Works out of the box with any React Native or Expo project.

### Comprehensive
63 security rules covering all major vulnerability categories from OWASP Mobile Top 10 to platform-specific issues.

### Fast
Scans complete projects in seconds using efficient static analysis techniques.

### Mobile-First
Purpose-built for React Native and Expo with Android and iOS platform-specific checks.

### Actionable
Clear findings with code context, severity levels, and remediation guidance.

### CI/CD Ready
JSON output and exit codes designed for automated security pipelines.

## Architecture

rnsec uses static analysis to examine your codebase without executing it:

1. **File Walker**: Recursively scans project files
2. **AST Parser**: Analyzes JavaScript/TypeScript using Abstract Syntax Trees
3. **Pattern Matching**: Detects secrets using regex patterns
4. **Rule Engine**: Applies security rules to AST nodes
5. **Platform Scanners**: Checks Android and iOS configuration files
6. **Reporter**: Generates HTML and JSON reports

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Ways to Contribute

- **Report Bugs**: [Create a bug report](https://github.com/adnxy/rnsec/issues/new?template=bug_report.md)
- **Request Features**: [Submit a feature request](https://github.com/adnxy/rnsec/issues/new?template=feature_request.md)
- **Submit Pull Requests**: [Open a PR](https://github.com/adnxy/rnsec/pulls)
- **Improve Documentation**: Help us make the docs better
- **Add Security Rules**: Contribute new detection rules

### Development Setup

See [DEVELOPMENT.md](DEVELOPMENT.md) for the complete developer guide.

```bash
# Clone repository
git clone https://github.com/adnxy/rnsec.git
cd rnsec

# Install dependencies
npm install

# Build project
npm run build

# Run tests
npm test

# Link for local development
npm link
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for upcoming features and planned improvements.

## Frequently Asked Questions

**Q: Does rnsec modify my code?**  
A: No. rnsec is a static analysis tool that only reads your code.

**Q: Can I customize which rules run?**  
A: Currently all rules run automatically. Custom rule configuration is planned for a future release.

**Q: Does it work with TypeScript?**  
A: Yes. rnsec fully supports both JavaScript and TypeScript.

**Q: What about React Native Web?**  
A: rnsec focuses on mobile security. Web-specific checks are not included.

**Q: How do I exclude files or directories?**  
A: rnsec automatically respects `.gitignore`. Additional exclusion options are planned.

**Q: Does it replace manual security audits?**  
A: No. rnsec is a complementary tool. Professional security audits are still recommended for production applications.

## Limitations

rnsec is a static analysis tool with inherent limitations:

- **No Runtime Analysis**: Cannot detect issues that only appear during execution
- **No Network Testing**: Does not test actual API endpoints or network security
- **No Binary Analysis**: Does not analyze compiled native code
- **Pattern-Based Detection**: May produce false positives or miss context-dependent issues
- **Configuration Required**: Some security measures may be configured outside the codebase

## Security Best Practices

Using rnsec is one part of a comprehensive security strategy:

**Do:**
- Review all findings manually to understand context
- Use rnsec as part of your development workflow
- Combine with other security tools and practices
- Run scans regularly in CI/CD pipelines
- Address high-severity issues promptly

**Don't:**
- Rely solely on static analysis for security
- Ignore findings without investigation
- Skip professional security audits for sensitive applications
- Assume passing scans mean complete security

For production applications handling sensitive data, we strongly recommend professional security audits and penetration testing.

## Support

### Get Help

- **Email**: adnanpoviolabs@gmail.com
- **Issues**: [GitHub Issues](https://github.com/adnxy/rnsec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/adnxy/rnsec/discussions)

### Report Security Vulnerabilities

If you discover a security vulnerability in rnsec itself, please email adnanpoviolabs@gmail.com directly instead of using public issue trackers.

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2024 [adnxy](https://github.com/adnxy)

## Acknowledgments

Built for the React Native and Expo community. Special thanks to all contributors and users who help improve mobile security.

---

**Found this useful?** Consider giving it a star on GitHub to help others discover it.
