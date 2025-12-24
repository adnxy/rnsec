# Security Policy

## Reporting Security Vulnerabilities

The rnsec project takes security seriously. If you discover a security vulnerability in rnsec itself, we appreciate your help in disclosing it to us in a responsible manner.

### Please Do Not

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before we've had a chance to address it
- Exploit the vulnerability beyond what is necessary to demonstrate it

### How to Report

**Email**: adnanpoviolabs@gmail.com

**Subject Line**: `[SECURITY] Brief description of vulnerability`

### What to Include

When reporting a security vulnerability, please include:

1. **Description**: A clear description of the vulnerability
2. **Impact**: What an attacker could do with this vulnerability
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Affected Versions**: Which versions of rnsec are affected
5. **Suggested Fix**: If you have ideas for how to fix it
6. **Contact Info**: How we can reach you for follow-up questions

### Example Report

```
Subject: [SECURITY] Command Injection in File Scanner

Description:
The file scanning functionality is vulnerable to command injection when
processing specially crafted file paths.

Impact:
An attacker could execute arbitrary commands on the system running rnsec
by crafting a malicious project structure.

Steps to Reproduce:
1. Create a file with name: `; rm -rf /`
2. Run rnsec scan on the directory
3. Observe command execution

Affected Versions:
rnsec 1.0.0 and earlier

Suggested Fix:
Sanitize file paths before processing and use path.join() instead of
string concatenation.

Contact: security-researcher@example.com
```

## Our Commitment

When you report a security vulnerability, we commit to:

1. **Acknowledge receipt** within 48 hours
2. **Provide a timeline** for fixing the issue within 7 days
3. **Keep you informed** of our progress
4. **Credit you** in our security advisories (if you wish)
5. **Coordinate disclosure** with you before making the issue public

## Security Update Process

When we receive a security report:

1. **Verification** (1-3 days): We verify the vulnerability
2. **Fix Development** (1-7 days): We develop and test a fix
3. **Release** (immediately after testing): We release a patch version
4. **Advisory** (same day as release): We publish a security advisory
5. **Notification**: We notify users through GitHub and npm

## Supported Versions

We support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

We recommend always using the latest version of rnsec for the best security posture.

## Security Best Practices for Users

When using rnsec:

### Do

- ✅ Keep rnsec updated to the latest version
- ✅ Run rnsec in a sandboxed or isolated environment if scanning untrusted code
- ✅ Review rnsec's output and reports manually
- ✅ Use rnsec as part of a comprehensive security strategy
- ✅ Report false positives or false negatives to help improve detection

### Don't

- ❌ Run rnsec with elevated privileges unless necessary
- ❌ Scan untrusted code without proper isolation
- ❌ Rely solely on rnsec for security validation
- ❌ Share generated reports that contain sensitive information publicly
- ❌ Ignore rnsec findings without investigation

## Known Limitations

rnsec is a static analysis tool with inherent limitations:

- **Static Analysis Only**: Cannot detect runtime vulnerabilities
- **Pattern-Based**: May produce false positives or miss context-specific issues
- **No Code Execution**: Does not actually test for exploitability
- **No Network Analysis**: Does not analyze actual network traffic
- **Configuration Dependent**: Security issues configured outside the codebase are not detected

For comprehensive security, combine rnsec with:
- Dynamic application security testing (DAST)
- Manual security audits
- Penetration testing
- Security-focused code reviews

## Security Features in rnsec

rnsec itself is designed with security in mind:

- **No External API Calls**: All analysis is performed locally
- **No Data Collection**: No telemetry or data sent to external servers
- **Read-Only Operations**: rnsec only reads files, never writes or modifies code
- **Sandboxing**: File operations are limited to the scanned project
- **No Code Execution**: Scanned code is never executed, only analyzed

## Vulnerability Disclosure Policy

When we fix a security vulnerability:

### Timeline

- **Day 0**: Vulnerability reported
- **Day 1-2**: Acknowledgment sent to reporter
- **Day 3-7**: Vulnerability verified and assessed
- **Day 7-14**: Fix developed and tested
- **Day 14**: Patch released, security advisory published
- **Day 14+**: Public disclosure with full details

### Public Disclosure

Our security advisories include:

- CVE identifier (if applicable)
- Affected versions
- Severity rating (using CVSS)
- Description of the vulnerability
- Impact assessment
- Remediation steps
- Credit to the reporter (if desired)
- Timeline of the fix

## Security Hall of Fame

We recognize security researchers who help make rnsec more secure:

_No vulnerabilities reported yet. Be the first to help us improve!_

## Questions?

For security-related questions that are not vulnerability reports:

- Open a [GitHub Discussion](https://github.com/adnxy/rnsec/discussions)
- Email: adnanpoviolabs@gmail.com (for private matters)

## PGP Key

For encrypted communications, use our PGP key:

_PGP key to be published upon request_

---

**Thank you for helping keep rnsec and its users safe!**

Last updated: December 2024

