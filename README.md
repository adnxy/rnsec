# rnsec

A zero-configuration security scanner for React Native and Expo applications that detects vulnerabilities, hardcoded secrets, and security misconfigurations with a single command.

[![npm version](https://img.shields.io/npm/v/rnsec.svg?style=flat)](https://www.npmjs.com/package/rnsec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Issues](https://img.shields.io/github/issues/adnxy/rnsec.svg)](https://github.com/adnxy/rnsec/issues)
[![GitHub Stars](https://img.shields.io/github/stars/adnxy/rnsec.svg)](https://github.com/adnxy/rnsec/stargazers)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/adnxy?style=flat&logo=github)](https://github.com/sponsors/adnxy)

---

## What's new in 1.5.0

- **OWASP mapping (`--owasp`)**: findings carry OWASP MASVS 2.1.0 / MASWE / MASTG / CWE references, and `--owasp` adds a MASVS coverage report (`failed`, `checked`, `not-applicable`, `not-assessed`) plus `rnsec rules --owasp`. 100 of the 106 rules are mapped. Static analysis does not establish MASVS compliance. See [OWASP MASVS / MASWE / MASTG](#owasp-masvs--maswe--mastg).
- **`--format console|json|sarif`**, a **CRITICAL** severity (`--fail-on critical`), SARIF rules with MASVS/MASWE/CWE tags and help links, and `app.config.js` / `app.config.ts` support for three Expo rules. 106 rules in total.
- **Behaviour changes**: errors now exit `2` (findings still exit `1`), `rnsec scan -p <missing directory>` fails instead of scanning zero files, and findings are sorted deterministically. See the [CHANGELOG](CHANGELOG.md#150---2026-10-30).

---

## What's new in 1.4.0

- **18 new rules (105 total)**: committed signing keys and service accounts, hardcoded Android signing passwords, secrets in `eas.json` and bundled env vars, insecure `.npmrc`/`.yarnrc.yml`, `network_security_config.xml` checks, JWT/OAuth/SQLite/MMKV/cipher misuse and more. See the [CHANGELOG](CHANGELOG.md) for the full list.
- **Built for CI**: SARIF 2.1.0 output for GitHub Code Scanning (`--sarif`), baselines for adopting rnsec on an existing codebase (`--baseline`, `--write-baseline`), a configurable failure threshold (`--fail-on`, `failOn`) and per-rule `severityOverrides`.
- **Fewer false positives**: `__DEV__` guards now apply to the guarded code only, public-by-design keys are LOW, findings carry a `confidence`, and `.gitignore` is respected.
- **Behaviour changes to be aware of** (more findings can appear, `--json` stdout is pure JSON, Node 20+ required): see the [upgrade notes](CHANGELOG.md#140---2026-10-23).

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

**Add OWASP MASVS data and a coverage report:**
```bash
rnsec scan --owasp
```

**SARIF on stdout (redirect it to a file):**
```bash
rnsec scan --format sarif > rnsec.sarif
```

**View all security rules:**
```bash
rnsec rules
rnsec rules --owasp   # with each rule's MASVS and MASWE ids
```

**Scan only changed files:**
```bash
rnsec scan --changed-files main
rnsec scan --changed-files abc123
# In GitHub Actions (needs fetch-depth: 0 on checkout): origin/${{ github.base_ref }}
rnsec scan --changed-files origin/${{ github.base_ref }}
```

### Command Options

```bash
rnsec scan [options]

Options:
  -p, --path <path>      Project directory to scan (default: current directory)
  --html <filename>      Custom HTML report filename
  --output <filename>    Custom JSON report filename
  --md <filename>        Generate Markdown report for PR comments
  --json                 Output JSON to console only (no HTML/JSON files are written); same as --format json
  --format <format>      What stdout carries: console (default), json or sarif. json and sarif write no report files
  --owasp                Add OWASP MASVS/MASWE/MASTG/CWE data to findings and a MASVS coverage section
  --silent               Suppress console output
  --changed-files <ref>  Scan only files changed since git reference (branch, commit, or tag)
  --min-confidence <l>   Only report findings at or above this confidence: low (default), medium, high
  --fail-on <level>      Exit 1 when a finding at or above this severity is reported: critical, high (default, includes critical), medium, low, none
  --sarif <filename>     Generate a SARIF 2.1.0 report (e.g. rnsec.sarif) for GitHub Code Scanning
  --baseline <filename>  Hide findings that are listed in this baseline file
  --write-baseline <f>   Write the current findings to a baseline file and exit 0
  --no-gitignore         Also scan files that git ignores
  -h, --help             Display help information
  -V, --version          Display version number
```

Notes:

- `--json` prints the result to stdout and nothing else: informational lines go to stderr, so `rnsec scan --json | jq` works. It ignores `--html` and `--output`. `--md` and `--sarif` files are still written.
- `--format json` is the same as `--json`. `--format sarif` prints the SARIF 2.1.0 document to stdout (use `> rnsec.sarif`, or `--sarif <file>` to get the same text in a file) and writes no report files either. `--json` cannot be combined with another `--format`, and an unknown `--format` value is an error (exit `2`).
- Without `--json` or `--format`, rnsec writes `rnsec-report.html` and `rnsec-report.json` into the current directory (or the names you give with `--html` and `--output`), also with `--silent`, which only suppresses the console report. `--silent` does not affect `--json` and `--format` output.
- `--owasp` is described in [OWASP MASVS / MASWE / MASTG](#owasp-masvs--maswe--mastg).
- `--changed-files` needs a git checkout.

### Exit Codes

- `0` - No finding at or above the `--fail-on` threshold (default `high`, which includes `critical`), or `--help` / `--version`
- `1` - A finding at or above the threshold was reported
- `2` - rnsec hit an error: invalid option or option value (`--fail-on`, `--format`, `--min-confidence`, an unknown flag), a `--path` that is not a directory, an invalid config value (`failOn`, `severityOverrides`, `owasp`), an unreadable baseline, `--changed-files` outside a git repository, ...

**Changed in 1.5.0:** errors used to exit `1`, the same code as findings, so a CI job could not tell "the scan found issues" from "the scan did not run". Errors now exit `2`. Also, `rnsec scan -p <missing directory>` used to look like a clean scan of zero files and now exits `2` with an error. If a script treats every non-zero exit as "findings", it keeps working; a script that compares the code with `1` must also handle `2`.

Severity levels are `CRITICAL`, `HIGH`, `MEDIUM` and `LOW`. A finding is `CRITICAL` only when it alone gives direct privileged access, or lets an attacker defeat a core control, with no further precondition, and detection is high precision. Today that is `COMMITTED_CREDENTIAL_FILE` for a service-account JSON or `.p8` file holding an unencrypted PEM private key; any other rule can be raised through [`severityOverrides`](#changing-a-rules-severity). `--fail-on critical` fails only on critical findings, and every other level also fails on everything above it.

`--fail-on none` never fails on findings, and `--write-baseline` always exits 0. The threshold can also be set with `failOn` in the [config file](#configuration); the command line wins.

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

In CI checkouts there is usually no local branch for the target, so use `origin/<branch>` (and fetch full history, e.g. `fetch-depth: 0` in `actions/checkout`).

### CI/CD Integration

**GitHub Actions:**
```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0
- name: Run security scan on PR changes
  env:
    BASE_REF: ${{ github.base_ref }}
  run: rnsec scan --changed-files "origin/$BASE_REF" --output security.json --silent
```

A full example with SARIF upload and a `--fail-on` gate is in [`examples/github-actions/security-scan.yml`](examples/github-actions/security-scan.yml).

**GitLab CI:**
```yaml
security-scan:
  script:
    - rnsec scan --changed-files origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME --output security.json --silent
```

See [`examples/gitlab-ci/security-scan.yml`](examples/gitlab-ci/security-scan.yml) for the full job.

### Benefits

- **Faster scans**: Only analyzes changed files instead of the entire codebase
- **PR-focused**: Perfect for pull request validation
- **CI/CD optimized**: Reduces pipeline execution time
- **Incremental security**: Focus on new security issues introduced in changes

## GitHub PR Comments Integration

Generate markdown reports that can be automatically posted as GitHub PR comments, bringing security results directly into your pull requests with advanced features like automatic comment updates, comparison tracking, and security metrics.

### Usage

```bash
# Generate markdown report for PR comment
rnsec scan --md security-report.md --silent

# Combine with changed files for PR-focused scanning
rnsec scan --changed-files main --md pr-security-report.md --silent
```

### Advanced Features

#### Smart Comment Management
- **Automatic updates**: Detects and updates existing comments instead of creating duplicates
- **No spam**: Keeps PR conversations clean by updating the same comment
- **Unique identifier**: Uses hidden HTML markers to identify rnsec comments

#### Comparison Tracking
- **New/resolved issues**: Automatically shows which issues were introduced or fixed
- **Trend indicators**: Visual indicators for improving/declining security posture
- **Historical data**: Stores scan results for comparison between runs

#### Security Metrics
- **Security score**: 0-100 score based on issue severity and count
- **Vulnerability density**: Issues per 1000 lines of code
- **Trend analysis**: Automatic detection of improving/declining/stable trends
- **Visual dashboards**: Comprehensive metrics in markdown format

#### Enhanced Formatting
- **Collapsible sections**: Each severity level can be expanded/collapsed
- **Code snippets**: Shows vulnerable code with syntax highlighting
- **Better organization**: Reduces clutter for reports with many issues

### GitHub Actions Workflow

A simplified variant of [`examples/github-actions/security-scan.yml`](examples/github-actions/security-scan.yml), which also gates the job with `--fail-on` and uploads SARIF (see [GitHub Code Scanning](#github-code-scanning-sarif)):

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
      uses: actions/checkout@v7
      with:
        fetch-depth: 0
    
    - name: Install rnsec
      run: npm install -g rnsec
    
    - name: Run security scan
      env:
        BASE_REF: ${{ github.base_ref || 'main' }}
      run: rnsec scan --changed-files "origin/$BASE_REF" --md security-report.md --output rnsec-report.json --fail-on none --silent
    
    - name: Comment PR with security results
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const markdownReport = fs.readFileSync('security-report.md', 'utf8');
          const commentIdentifier = '<!-- rnsec-security-report -->';
          
          // Find and update existing comment
          const { data: comments } = await github.rest.issues.listComments({
            owner: context.repo.owner,
            repo: context.repo.repo,
            issue_number: context.issue.number,
          });
          
          const existingComment = comments.find(c => c.body?.includes(commentIdentifier));
          
          if (existingComment) {
            await github.rest.issues.updateComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              comment_id: existingComment.id,
              body: markdownReport
            });
          } else {
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: markdownReport
            });
          }
```

### Multi-Platform Support

#### GitLab CI/CD
See [`examples/gitlab-ci/security-scan.yml`](examples/gitlab-ci/security-scan.yml) for GitLab merge request integration (`--fail-on` gate, SARIF and JSON artifacts).

#### Bitbucket Pipelines
See `examples/bitbucket-pipelines/bitbucket-pipelines.yml` for Bitbucket pull request integration.

#### Azure DevOps
See `examples/azure-devops/azure-pipelines.yml` for Azure Pipelines integration.

### Example PR Comment

The enhanced markdown report includes:
- **Summary table** with issue counts by severity
- **Comparison data** showing new/resolved issues since last scan
- **Security metrics dashboard** with score and trends
- **Collapsible findings** organized by severity
- **Code snippets** with syntax highlighting
- **Risk assessment** with clear action items
- **Performance metrics** and scan information

## GitHub Code Scanning (SARIF)

`--sarif <file>` writes a SARIF 2.1.0 report that GitHub shows in the Security tab and as inline annotations on pull requests:

```yaml
name: rnsec
on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: '20'
      - run: npx rnsec scan --sarif rnsec.sarif --silent
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: rnsec.sarif
```

The step uses `if: always()` so the report is uploaded even when `rnsec scan` exits 1 because of HIGH findings. Add `--fail-on none` if the upload should be the only gate. If `rnsec scan` itself fails (exit `2`) no SARIF file is written and the upload step has nothing to send; the example workflow guards it with `hashFiles('rnsec.sarif') != ''`. Always upload a full-project scan: a `--changed-files` report would make Code Scanning close the alerts of every file it did not scan.

Rules carry their MASVS and MASWE ids, CWE tags and a `helpUri` in the SARIF report, and the MASVS controls are published as a taxonomy, whether or not `--owasp` is set (see [OWASP MASVS / MASWE / MASTG](#owasp-masvs--maswe--mastg)). `--format sarif` prints the same document to stdout; redirect it (`rnsec scan --format sarif > rnsec.sarif`) if you prefer that to `--sarif <file>`. Full workflow: [`examples/github-actions/security-scan.yml`](examples/github-actions/security-scan.yml). Finding paths in the report are relative to the git repository root, and each result carries a stable fingerprint so GitHub can track alerts across commits.

## OWASP MASVS / MASWE / MASTG

rnsec maps its rules to the [OWASP Mobile Application Security](https://mas.owasp.org/) standards, so findings and CI reports speak the same language as a mobile security review. The mapping is pinned to these versions (vendored in `src/standards/owasp/snapshot.json`; only IDs that exist in it are accepted):

| Standard | Pinned version | Used for |
|----------|----------------|----------|
| OWASP MASVS | 2.1.0: eight categories (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY) and 24 controls | The coverage report and `masvs` references |
| OWASP MASWE | 1.0.0 | The weakness behind each rule (`maswe`) |
| OWASP MASTG | v2.0.0 + master@2eb0f70 | Static tests that match a rule's check (`mastg`); runtime tests are not listed |

`CWE` ids are listed where one fits. 100 of the 106 rules are mapped; the six that have no sound MASVS fit are listed with their reason in the [coverage matrix](docs/owasp-coverage.md#unmapped-rules). The matrix ([`docs/owasp-coverage.md`](docs/owasp-coverage.md)) shows, for every MASVS control, which rules map to it and whether it is automated, heuristic only or manual/dynamic, plus a reference table of all rules with severity, platform, confidence and standard ids. It is generated from the mapping (`npm run docs:owasp`) and a test fails when it is stale.

### Using `--owasp`

```bash
npx rnsec scan                                  # findings only, as before
npx rnsec scan --owasp                          # + OWASP references and MASVS coverage in the console report
npx rnsec scan --owasp --format json            # JSON on stdout with `standards` per finding and an `owasp` section
npx rnsec scan --owasp --format sarif           # SARIF on stdout (see below: the SARIF content does not depend on --owasp)
npx rnsec scan --owasp --fail-on high           # same, and exit 1 on HIGH or CRITICAL findings
npx rnsec rules --owasp                         # every rule with its MASVS and MASWE ids
```

`--owasp` (or `"owasp": true` in the [config file](#configuration)) changes the output like this:

- **Console**: each mapped finding gets a line such as `OWASP: MASVS-STORAGE-1 · MASWE-0004 · CWE-798`, and a MASVS coverage section follows the summary.
- **JSON** (`--json`, `--format json` and the `--output` file): each mapped finding gains `title`, `platform` and `standards` (`masvs`, `maswe`, `mastg`, `cwe`, `confidence`), and the result gains an `owasp` object with the pinned versions, a summary and one entry per control. Without `--owasp` neither exists.
- **SARIF**: unchanged. SARIF output always carries the MASVS taxonomy, rule tags (`MASVS-*`, `MASWE-*`, `external/cwe/cwe-*`), relationships to the MASVS controls and a `helpUri` per rule, with or without `--owasp`.
- **Markdown and HTML reports**: unchanged.
- With `--changed-files` the coverage is labelled `"scope": "changed-files"` and its disclaimer says the scan covered only the changed files.

Sample console output (`rnsec scan --owasp` on `examples/vulnerable-app`, long paths shortened by rnsec, rows omitted):

```text
   HIGH  Potential hardcoded secret in variable "JWT_TOKEN"
      .../examples/vulnerable-app/App.tsx:12
      OWASP: MASVS-STORAGE-1 · MASWE-0004 · CWE-798

  OWASP MASVS 2.1.0 coverage (static analysis only)
  ────────────────────────────────────────────────────────────
  100 automated rules map to MASVS controls in this project
  24 controls: 15 failed, 2 checked, 4 checked (heuristic), 0 not applicable, 3 not assessed

    MASVS-AUTH-1         FAILED 4 findings 7 rules
    MASVS-CODE-2         not assessed
    MASVS-CODE-3         checked 6 rules
    MASVS-NETWORK-2      checked 1 rule
    MASVS-PRIVACY-2      checked (heuristic) 1 rule
    MASVS-STORAGE-1      FAILED 14 findings 24 rules
    ...

  Static analysis does not establish MASVS compliance. This report lists which controls rnsec checked and where it found issues. Controls marked not-assessed need manual or dynamic verification (see the MASTG).
```

Sample JSON (`rnsec scan --owasp --format json`, same project, `filePath` shortened, controls omitted):

```json
{
  "findings": [
    {
      "ruleId": "IOS_MISSING_APP_SNAPSHOT_PROTECTION",
      "severity": "LOW",
      "filePath": "/path/to/examples/vulnerable-app/App.tsx",
      "line": 1,
      "title": "No app snapshot protection",
      "platform": ["ios"],
      "standards": {
        "masvs": ["MASVS-PLATFORM-3", "MASVS-STORAGE-2"],
        "maswe": ["MASWE-0038"],
        "mastg": [],
        "cwe": [200],
        "confidence": "low"
      }
    }
  ],
  "owasp": {
    "standards": { "masvs": "2.1.0", "maswe": "1.0.0", "mastg": "v2.0.0 + master@2eb0f70" },
    "scope": "project",
    "summary": { "controls": 24, "failed": 15, "checked": 2, "checkedHeuristic": 4, "notApplicable": 0, "notAssessed": 3, "automatedRules": 100 },
    "controls": [
      {
        "id": "MASVS-NETWORK-2",
        "statement": "The app performs identity pinning for all remote endpoints under the developer's control.",
        "status": "checked",
        "rules": ["CERT_PINNING_DISABLED"],
        "findings": 0
      },
      {
        "id": "MASVS-CODE-2",
        "statement": "The app has a mechanism for enforcing app updates.",
        "status": "not-assessed",
        "rules": [],
        "findings": 0,
        "reason": "No enabled automated rule maps to this control; verify manually or dynamically."
      }
    ]
  }
}
```

(The real output has the remaining finding fields, such as `description`, `suggestion` and `fingerprint`, all 24 controls and a `disclaimer`.)

### Control statuses

Each of the 24 MASVS controls gets exactly one status per scan:

| Status (JSON value) | Meaning |
|---------------------|---------|
| `failed` | At least one reported finding maps to the control. |
| `checked` | At least one enabled rule that applies to the project maps to the control and reported nothing. This is not a pass verdict: it only says what rnsec looked for. `checked-heuristic` is the same, but every such rule is a low-confidence presence/absence heuristic (for example "no root detection found"). |
| `not-applicable` | Every enabled rule that maps to the control targets a platform the project does not have (for example only Android rules map to it and the project has just an `ios/` directory). |
| `not-assessed` | No enabled rule maps to the control: it needs manual or dynamic verification (see the MASTG). Rules switched off with `ignoredRules` also leave their controls `not-assessed`. |

### Limitations

rnsec is static analysis of source code, configuration files and dependency metadata. **It does not verify MASVS compliance**, and a `checked` control is not a certified one: it only means the rules that map to it found nothing in the files rnsec can read. Controls that are `not-assessed` (in the pinned mapping: the update-enforcement control and two of the four privacy controls) need manual review or dynamic testing, and rnsec does not scan built APK/IPA files or run the app, so anything that only shows up in the compiled binary or at runtime is out of scope. Mappings are judgements: each rule lists a mapping confidence, and heuristic rules can miss issues or flag harmless code. Treat the coverage report as a map of what was automated, not as an assessment result.

## Baselines

A baseline lets you adopt rnsec on an existing codebase: record today's findings once, then fail only on new ones.

```bash
# 1. Record the current findings (always exits 0) and commit the file
rnsec scan --write-baseline .rnsec-baseline.json

# 2. From now on, only findings that are not in the baseline are reported
rnsec scan --baseline .rnsec-baseline.json
```

You can also set `"baseline": ".rnsec-baseline.json"` in the [config file](#configuration) (relative to the scan root). Each finding is identified by a fingerprint of the rule ID, the file path, the whitespace-normalized source line and an occurrence index, not by its line number, so findings survive code moving around. Changing the flagged line itself makes the finding show up again. The number of hidden findings is printed and stored as `baselinedCount` in the JSON result. `--write-baseline` honors `--min-confidence`.

## Configuration

rnsec supports configuration files to customize the scanning behavior. Create a `.rnsec.jsonc` or `.rnsec.json` file in your project root (rnsec looks for `.rnsec.json`, then `.rnsec.jsonc`, then `.rnsec.config.json`). The file is parsed as JSONC, so comments and trailing commas are allowed.

```jsonc
{
  "ignoredRules": ["ASYNCSTORAGE_SENSITIVE_KEY"],
  "exclude": ["**/scripts/**"],
  "failOn": "high",                                // critical | high (default) | medium | low | none
  "owasp": false,                                  // true: same as --owasp
  "severityOverrides": { "INSECURE_HTTP_URL": "LOW" },
  "baseline": ".rnsec-baseline.json",
  "respectGitignore": true,                        // default
  "npmVulnerabilityScanning": { "enabled": true, "dataSource": "npm-audit", "excludeDevDependencies": false }
}
```

| Key | Description |
|-----|-------------|
| `ignoredRules` | Rule IDs that never run |
| `exclude` | Extra glob patterns to skip (see [Excluding Files](#excluding-files)) |
| `failOn` | Severity that makes `rnsec scan` exit 1 (`critical`, `high`, `medium`, `low` or `none`); same values as `--fail-on`, which takes precedence |
| `owasp` | `true` adds OWASP data and the MASVS coverage report, like `--owasp` (the flag cannot switch it off); must be a boolean (see [OWASP MASVS / MASWE / MASTG](#owasp-masvs--maswe--mastg)) |
| `severityOverrides` | Map of rule ID to `CRITICAL`, `HIGH`, `MEDIUM` or `LOW`; applied to the reports, SARIF and the exit code |
| `baseline` | Baseline file, relative to the scan root (see [Baselines](#baselines)) |
| `respectGitignore` | `false` also scans git-ignored files, like `--no-gitignore` |
| `npmVulnerabilityScanning` | `enabled`, `dataSource` (`npm-audit` or `hardcoded`) and `excludeDevDependencies` for the dependency checks |

### Ignoring Rules

You can ignore specific rules by adding them to the `ignoredRules` array:

```jsonc
{
  "ignoredRules": [
    "ASYNCSTORAGE_SENSITIVE_KEY",
    "SENSITIVE_LOGGING"
  ]
}
```

To find the rule ID for a specific finding, check the `ruleId` field in the JSON output or HTML report.

### Changing a Rule's Severity

Use `severityOverrides` to raise or lower a rule without disabling it, for example to treat a noisy rule as informational or to make a MEDIUM rule fail the build:

```jsonc
{
  "severityOverrides": {
    "INSECURE_HTTP_URL": "LOW",
    "WEBVIEW_DOM_STORAGE_ENABLED": "HIGH"
  }
}
```

Severities are `CRITICAL`, `HIGH`, `MEDIUM` and `LOW`. Unknown rule IDs print a warning, and an invalid severity is an error (exit `2`).

### Suppressing a Single Finding

Add an inline comment on the same line as the finding, or on its own line directly above it. The rule ID is mandatory (there is no blanket ignore), and any text after it is treated as the reason:

```ts
// rnsec-ignore: INSECURE_HTTP_URL legacy partner endpoint, tracked in SEC-123
fetch('http://partner.example-corp.com/status');

const key = 'AIza...'; // rnsec-ignore: API_KEY_EXPOSED restricted Firebase web key
```

Use `<!-- rnsec-ignore: RULE_ID -->` in `AndroidManifest.xml`, `Info.plist` and other XML files, and put multiple IDs in one comment separated by commas.

### Automatic Exclusions and Dev-Only Code

- Test, mock, fixture, story and vendored code is skipped automatically (`__tests__`, `__mocks__`, `*.test.*`, `*.spec.*`, `e2e`, `fixtures`, `mocks`, `node_modules`, `build`, `dist`, ...). Folder names are matched against the path **relative to the scan root**.
- Code that only runs in development builds (`if (__DEV__) { ... }`, `__DEV__ && ...`, `NODE_ENV !== 'production'` branches) is not reported. This is decided **per finding**, so a `__DEV__` check elsewhere in a file never hides a real issue.
- Files that `.gitignore` excludes are not scanned (tracked files are always scanned). Use `--no-gitignore` or `"respectGitignore": false` to scan them too. Outside a git checkout this has no effect.
- `.env`, `.npmrc`/`.yarnrc.yml`, `gradle.properties` and signing-key or service-account files are only checked when git tracks them. Ignored local copies are never reported, and templates such as `.env.example` are skipped. In a folder that is not a git checkout these files are not checked at all.
- Findings carry a `confidence` (`high`, `medium`, `low`). Heuristic rules report lower confidence; use `--min-confidence medium` to see only the more certain ones.

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

rnsec identifies 106 different security issues across 13 categories:

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

rnsec implements 106 security rules covering:

| Category | Rules | Description |
|----------|-------|-------------|
| **Storage** | 11 | AsyncStorage, MMKV, Realm and SQLite encryption, SQL injection, SecureStore options, file storage, clipboard, redux-persist |
| **Network** | 7 | HTTP/WebSocket connections, request timeouts, TLS configuration, certificate pinning, disabled TLS validation, hardcoded IPs |
| **Authentication** | 8 | JWT handling and signing, OAuth flows and PKCE, biometrics, session timeout, secure text inputs |
| **Secrets** | 6 | API key detection (provider-specific patterns), bundled env secrets, committed `.env` files, committed keystores and service-account files, basic-auth credentials |
| **Cryptography** | 5 | Weak hashes, weak ciphers/ECB mode/static IVs, hardcoded encryption keys, custom crypto, insecure randomness |
| **Logging** | 2 | Sensitive data exposure in logs and error messages |
| **React Native** | 13 | Native bridge, deep links, `Linking.openURL`, `eval()`, deserialization, navigation params, push notifications, screenshots, integrity checks, SDK risk |
| **Debug** | 4 | Test credentials, debug endpoints, dev tools and network loggers in production |
| **WebView** | 11 | JS injection, file access, origin whitelist, mixed content, navigation, postMessage, DOM storage, geolocation, caching, headers |
| **Android** | 15 | Manifest security, exported components, backup, Keystore, `network_security_config.xml`, hardcoded signing passwords in Gradle |
| **iOS** | 12 | App Transport Security, Keychain, pasteboard, file sharing, Info.plist, snapshot protection |
| **Expo / EAS** | 7 | `app.json`/`app.config.*` settings and secrets, `eas.json` secrets, update URL and code signing, permissions |
| **Supply chain** | 5 | Vulnerable/deprecated dependencies, suspicious lifecycle scripts, non-registry dependency sources, insecure `.npmrc`/`.yarnrc.yml` |

Run `rnsec rules` to list every rule with its default severity (`rnsec rules --owasp` adds the MASVS and MASWE ids). Severity is the default: some rules report a lower or higher level depending on context, and `severityOverrides` can change it. The [OWASP coverage matrix](docs/owasp-coverage.md) lists every rule with its severity, platform, confidence and OWASP ids.

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

rnsec generates two report formats automatically, and can add more on request:

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

### Markdown and SARIF
- `--md <file>` writes a Markdown report for pull request comments
- `--sarif <file>` writes SARIF 2.1.0 for [GitHub Code Scanning](#github-code-scanning-sarif); `--format sarif` prints it to stdout

### OWASP data
- `--owasp` adds OWASP MASVS/MASWE/MASTG/CWE references to findings and a MASVS coverage section to the console and JSON output (see [OWASP MASVS / MASWE / MASTG](#owasp-masvs--maswe--mastg))

## CI/CD Integration

Ready-to-copy configurations live in [`examples/`](examples/):

| CI system | File |
|-----------|------|
| GitHub Actions (SARIF upload to Code Scanning, PR comment, `--fail-on` gate) | [`examples/github-actions/security-scan.yml`](examples/github-actions/security-scan.yml) |
| GitLab CI (`--fail-on` gate, SARIF and JSON artifacts, MR comment) | [`examples/gitlab-ci/security-scan.yml`](examples/gitlab-ci/security-scan.yml) |
| Git pre-commit hooks (pre-commit framework, plain git hook, husky) | [`examples/pre-commit/`](examples/pre-commit/) |
| Azure DevOps | [`examples/azure-devops/azure-pipelines.yml`](examples/azure-devops/azure-pipelines.yml) |
| Bitbucket Pipelines | [`examples/bitbucket-pipelines/bitbucket-pipelines.yml`](examples/bitbucket-pipelines/bitbucket-pipelines.yml) |

In the GitHub and GitLab examples the job fails when `rnsec scan` exits non-zero: `1` for findings at or above `--fail-on` (default `high`), `2` for an rnsec error (see [Exit Codes](#exit-codes)). Steps that must run after a failed scan (uploading reports or SARIF) need `if: always()` on GitHub or `artifacts: when: always` on GitLab. GitLab has no SARIF report type, so there the SARIF file is just a job artifact.

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
        uses: actions/checkout@v7
      
      - name: Setup Node.js
        uses: actions/setup-node@v7
        with:
          node-version: '20'
      
      - name: Install rnsec
        run: npm install -g rnsec
      
      - name: Run security scan
        run: rnsec scan --output security.json --silent
      
      - name: Upload reports
        uses: actions/upload-artifact@v7
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
  image: node:20
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

## Local Development Workflow

Install rnsec as a dev dependency so every developer and CI job uses the same version:

```bash
npm install --save-dev rnsec
```

```jsonc
// package.json
"scripts": {
  "security": "rnsec scan --fail-on high",
  "security:owasp": "rnsec scan --owasp"
}
```

```bash
npm run security                       # fails (exit 1) on HIGH or CRITICAL findings
npx rnsec scan --changed-files main    # only the files your branch changed (tracked, staged files included)
npx rnsec scan --owasp                 # also show the MASVS coverage
```

A pre-commit hook runs the same command before each commit: see [`examples/pre-commit/`](examples/pre-commit/). Console scans write `rnsec-report.html` and `rnsec-report.json` into the working directory, so add them to `.gitignore`. To adopt rnsec on an existing codebase, record a [baseline](#baselines) first.

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

- **Node.js**: Version 20 or higher
- **Project Type**: React Native or Expo application

## Why Use rnsec?

### Simple
One command with zero configuration required. Works out of the box with any React Native or Expo project.

### Comprehensive
106 security rules for Android, iOS, React Native and Expo, 100 of them mapped to OWASP MASVS 2.1.0 controls and MASWE weaknesses (see the [coverage matrix](docs/owasp-coverage.md)). rnsec does not claim to cover the OWASP Mobile Top 10 or to verify MASVS compliance.

### Fast
Scans complete projects in seconds using efficient static analysis techniques.

### Mobile-First
Purpose-built for React Native and Expo with Android and iOS platform-specific checks.

### Actionable
Clear findings with code context, severity levels, and remediation guidance.

### CI/CD Ready
JSON, Markdown and SARIF output, baselines and a configurable `--fail-on` exit code designed for automated security pipelines.

## Architecture

rnsec uses static analysis to examine your codebase without executing it:

1. **File Walker**: Recursively scans project files
2. **AST Parser**: Analyzes JavaScript/TypeScript using Abstract Syntax Trees
3. **Pattern Matching**: Detects secrets using regex patterns
4. **Rule Engine**: Applies security rules to AST nodes
5. **Platform Scanners**: Checks Android and iOS configuration files
6. **Reporter**: Generates HTML and JSON reports

Design note: the OWASP snapshot (`src/standards/owasp/snapshot.json`) and the rule mapping (`RULE_STANDARDS` in `src/standards/owasp/mappings.ts`) do not depend on how a finding was produced. A future analyzer for built binaries or running apps that emits `Finding`s whose `ruleId`s are listed in `RULE_STANDARDS` would reuse the same `--owasp` enrichment, MASVS coverage and SARIF output unchanged. Only static analysis of source, configuration and dependency metadata exists today.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details, and [docs/adding-rules.md](docs/adding-rules.md) for how to add a rule (including its OWASP mapping).

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

## Frequently Asked Questions

**Q: Does rnsec modify my code?**  
A: No. rnsec is a static analysis tool that only reads your code.

**Q: Can I customize which rules run?**  
A: Yes. Disable a rule with `ignoredRules`, change its severity with `severityOverrides`, silence one finding with `// rnsec-ignore: RULE_ID`, or show only high-confidence findings with `--min-confidence`. See [Configuration](#configuration). Writing your own custom rules is not supported.

**Q: Does it work with TypeScript?**  
A: Yes. rnsec fully supports both JavaScript and TypeScript.

**Q: What about React Native Web?**  
A: rnsec focuses on mobile security. Web-specific checks are not included.

**Q: How do I exclude files or directories?**  
A: rnsec skips tests, mocks, fixtures and build output by default, and you can add your own globs with the `exclude` setting in `.rnsec.json`/`.rnsec.jsonc` (see [Excluding Files](#excluding-files)). Files that `.gitignore` excludes are skipped too (use `--no-gitignore` to include them). Single findings can be silenced with `// rnsec-ignore: RULE_ID`.

**Q: Does it replace manual security audits?**  
A: No. rnsec is a complementary tool. Professional security audits are still recommended for production applications.

## Limitations

rnsec is a static analysis tool with inherent limitations:

- **No Runtime Analysis**: Cannot detect issues that only appear during execution
- **No Network Testing**: Does not test actual API endpoints or network security
- **No Binary Analysis**: Does not analyze compiled native code; APK and IPA files are not scanned
- **No MASVS verification**: The [OWASP mapping](#owasp-masvs--maswe--mastg) shows which controls rules were run against, not that the app complies; `not-assessed` controls need manual or dynamic testing
- **Pattern-Based Detection**: May produce false positives or miss context-dependent issues
- **Configuration Required**: Some security measures may be configured outside the codebase
- **Native and Expo configuration**: `network_security_config.xml` is scanned directly, not resolved through the manifest's `android:networkSecurityConfig`; Expo config rules read only literal values in `app.config.js|ts`; CodePush code signing is not checked (Expo Updates signing is)
- **Git checkout needed for some checks**: `.env`, credential and registry-config files are only reported when git tracks them

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
