# rnsec

A zero-configuration security scanner for React Native and Expo applications that detects vulnerabilities, hardcoded secrets, and security misconfigurations with a single command.

[![npm version](https://img.shields.io/npm/v/rnsec.svg?style=flat)](https://www.npmjs.com/package/rnsec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Issues](https://img.shields.io/github/issues/adnxy/rnsec.svg)](https://github.com/adnxy/rnsec/issues)
[![GitHub Stars](https://img.shields.io/github/stars/adnxy/rnsec.svg)](https://github.com/adnxy/rnsec/stargazers)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/adnxy?style=flat&logo=github)](https://github.com/sponsors/adnxy)

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

**HTML Report:**



<img width="1058" height="787" alt="Screenshot 2025-12-25 at 00 56 44" src="https://github.com/user-attachments/assets/6d265338-30a1-4008-a5d3-1061ee25bd1f" />



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

**Scan only changed files:**
```bash
rnsec scan --changed-files main
rnsec scan --changed-files abc123
rnsec scan --changed-files ${{ github.base_ref }}
```

### Command Options

```bash
rnsec scan [options]

Options:
  -p, --path <path>      Project directory to scan (default: current directory)
  --html <filename>      Custom HTML report filename
  --output <filename>    Custom JSON report filename
  --md <filename>        Generate Markdown report for PR comments
  --json                 Output JSON to console only (no files)
  --silent               Suppress console output
  --changed-files <ref>  Scan only files changed since git reference (branch, commit, or tag)
  -h, --help             Display help information
  -V, --version          Display version number
```

### Exit Codes

- `0` - No high-severity issues found
- `1` - High-severity security issues detected

## Changed Files Scanning

The `--changed-files` option allows you to scan only files that have changed since a specific git reference, making it perfect for CI/CD pipelines and pull request validation.

### Usage

```bash
# Scan files changed since main branch
rnsec scan --changed-files main

# Scan files changed since specific commit
rnsec scan --changed-files abc123def456

# Scan files changed since a tag
rnsec scan --changed-files v1.2.0

# Use in CI/CD with JSON output
rnsec scan --changed-files main --output security.json --silent
```

### Git References

The `--changed-files` option accepts any valid git reference:

- **Branch names**: `main`, `develop`, `feature/new-auth`
- **Commit hashes**: `abc123def456`, `HEAD~1`
- **Tags**: `v1.0.0`, `release-2024`
- **Special references**: `HEAD`, `origin/main`

### CI/CD Integration

**GitHub Actions:**
```yaml
- name: Run security scan on PR changes
  run: rnsec scan --changed-files ${{ github.base_ref }} --output security.json --silent
```

**GitLab CI:**
```yaml
security-scan:
  script:
    - rnsec scan --changed-files $CI_MERGE_REQUEST_TARGET_BRANCH_NAME --output security.json --silent
```

### Benefits

- **Faster scans**: Only analyzes changed files instead of the entire codebase
- **PR-focused**: Perfect for pull request validation
- **CI/CD optimized**: Reduces pipeline execution time
- **Incremental security**: Focus on new security issues introduced in changes

## GitHub PR Comments Integration

Generate markdown reports that can be automatically posted as GitHub PR comments, bringing security results directly into your pull requests.

### Usage

```bash
# Generate markdown report for PR comment
rnsec scan --md security-report.md --silent

# Combine with changed files for PR-focused scanning
rnsec scan --changed-files main --md pr-security-report.md --silent
```

### GitHub Actions Workflow

Create `.github/workflows/security-scan.yml`:

```yaml
name: 🔒 Security Scan

on:
  pull_request:
    branches: [ main, develop ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0  # Fetch full history for git diff
    
    - name: Install rnsec
      run: npm install -g rnsec
    
    - name: Run security scan on changed files
      run: |
        # Generate markdown report for PR comment
        rnsec scan --changed-files ${{ github.base_ref || 'main' }} --md security-report.md --silent
      continue-on-error: true
    
    - name: Comment PR with security results
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          
          try {
            const markdownReport = fs.readFileSync('security-report.md', 'utf8');
            
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: markdownReport
            });
          } catch (error) {
            console.log('No security report found:', error.message);
          }
```

### Features

- **📊 Rich formatting**: Tables, emojis, and structured sections
- **🎯 Risk assessment**: Clear risk levels and recommendations
- **📍 File locations**: Direct links to vulnerable code
- **💡 Suggestions**: Actionable recommendations for each issue
- **⚡ Performance metrics**: Scan duration and files scanned
- **🔒 Security-focused**: Designed for security team review

### Example PR Comment

The markdown report includes:
- Summary table with issue counts by severity
- Detailed findings with file locations and suggestions
- Risk assessment with clear action items
- Performance metrics and scan information

## Configuration

rnsec supports configuration files to customize the scanning behavior. Create a `.rnsec.jsonc` or `.rnsec.json` file in your project root.

### Ignoring Rules

You can ignore specific rules by adding them to the `ignoredRules` array:

```jsonc
{
  "ignoredRules": [
    "ASYNCSTORAGE_SENSITIVE_KEY",
    "LOGGING_SENSITIVE_DATA"
  ]
}
```

To find the rule ID for a specific finding, check the `ruleId` field in the JSON output or HTML report.

### Excluding Files

You can exclude specific files and directories by adding exclude patterns to the `exclude` array:

```jsonc
{
  "exclude": [
    "**/scripts/**"
  ]
}
```

Any pattern supported by `fast-glob` can be used, for more information see [Pattern syntax](https://github.com/mrmlnc/fast-glob?tab=readme-ov-file#pattern-syntax).

## What It Detects

rnsec identifies 63 different security issues across 13 categories:

**Common vulnerabilities found:**

```typescript
// Hardcoded API keys and secrets
const API_KEY = 'your_secret_api_key_here'; // Never commit real keys!

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
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
      
      - name: Install rnsec
        run: npm install -g rnsec
      
      - name: Run security scan
        run: rnsec scan --output security.json --silent
      
      - name: Upload reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: |
            security.json
            rnsec-report.html
```
### EAS
```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  security_scan:
    type: build
    params:
      platform: android
    steps:
      - name: Security validation only
        run: |
          echo "🔒 Running security validation..."
          echo "Current directory: $(pwd)"
          echo "Contents:"
          ls -la
          
          # Look for project in current and parent directories
          echo "🔍 Searching for project..."
          
          # Check current directory first
          if [ -f "package.json" ]; then
            PROJECT_DIR="."
          else
            # Check parent directory
            if [ -f "../package.json" ]; then
              PROJECT_DIR=".."
            else
              # Search recursively
              PROJECT_DIR=$(find .. -name "package.json" -type f -printf '%h' | head -1)
            fi
          fi
          
          if [ -z "$PROJECT_DIR" ] || [ ! -f "$PROJECT_DIR/package.json" ]; then
            echo "❌ No package.json found in any location"
            echo "📁 Searching all directories:"
            find .. -name "package.json" -type f 2>/dev/null || echo "No package.json found anywhere"
            exit 1
          fi
          
          echo "✅ Found project at: $PROJECT_DIR"
          cd "$PROJECT_DIR"
          echo "📁 Project contents:"
          ls -la | head -10
          
          # Install dependencies and run security scan
          npm install -g rnsec
          echo "y" | rnsec scan --output security.json
          echo "✅ Security validation completed"
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

### Support This Project

If rnsec helps secure your React Native apps, consider supporting its development:

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-GitHub-ea4aaa?style=for-the-badge&logo=github)](https://github.com/sponsors/adnxy)

Your sponsorship helps:
- Maintain and improve rnsec
- Add new security rules and features
- Provide faster support and bug fixes
- Keep the project free and open source

### Report Security Vulnerabilities

If you discover a security vulnerability in rnsec itself, please email adnanpoviolabs@gmail.com directly instead of using public issue trackers.

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2024 [adnxy](https://github.com/adnxy)

## Acknowledgments

Built for the React Native and Expo community. Special thanks to all contributors and users who help improve mobile security.

---

**Found this useful?** Consider giving it a star on GitHub to help others discover it.
