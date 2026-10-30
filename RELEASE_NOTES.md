# 🚀 rnsec 1.5.0 Release Notes

**Release Date**: October 30, 2026

rnsec 1.5.0 maps its findings to the OWASP Mobile Application Security standards (MASVS, MASWE and MASTG) and adds a MASVS coverage report. It still performs static analysis only: it does not verify MASVS compliance. Please read the upgrade notes: error exit codes changed.

The full list of changes is in the [CHANGELOG](https://github.com/adnxy/rnsec/blob/main/CHANGELOG.md#150---2026-10-30).

---

## 🌟 Highlights

### OWASP MASVS, MASWE and MASTG mapping

- 103 of the 110 rules are mapped to MASVS 2.1.0 controls, MASWE 1.0.0 weaknesses and MASTG tests. The mapping lives in one table, separate from the detection code.
- The standards data is a pinned, vendored snapshot (8 MASVS categories including PRIVACY, 24 controls). A test fails if a mapping uses an ID that is not in the snapshot.
- `--owasp` adds the references to every finding and prints a coverage section. Each of the 24 controls is reported as `failed`, `checked`, `checked (heuristic)`, `not applicable` or `not assessed`. Controls marked `not assessed` need manual or dynamic verification.
- `rnsec rules --owasp` lists every rule with its MASVS and MASWE references.

```bash
rnsec scan --owasp
rnsec scan --owasp --format json
rnsec scan --owasp --format sarif
rnsec scan --owasp --fail-on high
```

### Precision

Fewer false positives. On 8 open-source apps (pinned in `bench/corpus.json`) the default output went from 1460 findings to 524, and to 533 with the four new rules, which added 9 hand-verified true positives. None of the 12 known true positives was lost. Generated bundles and non-app source (scripts, tools, e2e, mocks) are no longer scanned by code-pattern rules, absence checks are one project-level finding, and several rules were tightened. A crash in `INSECURE_WEBSOCKET` that silently dropped files is fixed, and rule exceptions and parse failures are now reported (`Scan incomplete: ...` on stderr, `ruleErrors` / `parseFailures` in the JSON output).

**Caveat:** hand-reviewed samples of removed findings were almost all correct removals, but the remaining findings are mostly "plausible, needs review" rather than confirmed exploitable. Precision as a percentage is not established: it was measured by volume and hand sampling, not on a labelled hold-out set. See [docs/benchmark.md](https://github.com/adnxy/rnsec/blob/main/docs/benchmark.md).

### CI output

- `--format console|json|sarif` prints one machine-readable format to stdout with nothing else mixed in.
- SARIF now carries MASVS, MASWE, MASTG and CWE tags, a help link per rule and an MASVS taxonomy.
- `critical` is a new severity, usable with `--fail-on`. It applies to a committed service-account JSON with a real private key and to a `.p8` file containing a PEM private key. Other rules can be raised with `severityOverrides`.
- Updated GitHub Actions and GitLab CI examples, plus a pre-commit example in `examples/pre-commit/`.

### Rules

- `EXPO_UPDATES_INSECURE_URL`, `EXPO_UPDATES_NO_CODE_SIGNING` and `EXPO_INSECURE_PERMISSIONS` now read static values in `app.config.js|ts`. Values that cannot be established statically are never flagged.
- New rule `EXPO_PUBLIC_ENV_SECRET` for secrets in `EXPO_PUBLIC_*` variables of committed `.env` files.
- New rule `TLS_VALIDATION_DISABLED_NATIVE` for certificate or host name validation switched off in Java, Kotlin, Swift and Objective-C code (trust-all managers, always-true host name verifiers, `onReceivedSslError` + `proceed()`, challenge handlers that trust any server).
- New rule `GRADLE_INSECURE_REPOSITORY` for Maven repositories over plain HTTP or with `allowInsecureProtocol = true`; `settings.gradle[.kts]` files are now scanned.
- New rule `ANDROID_FILEPROVIDER_BROAD_PATHS` for FileProvider paths files with `<root-path>` or whole-directory paths.
- New rule `FIREBASE_RULES_OPEN_ACCESS` for Firestore, Storage and Realtime Database rules that allow everyone to read or write.

---

## ⚠️ Upgrade notes

- **Errors now exit 2.** Exit codes are `0` (clean), `1` (findings at or above `--fail-on`) and `2` (scan, usage or internal error). CI that treated any non-zero exit the same is unaffected; CI that matched `1` for errors must be updated.
- **`scan -p <missing dir>` now fails** with exit 2 instead of passing with zero files.
- **Finding order is deterministic** (sorted by file, line, column and rule), so JSON and console order differs from 1.4.0.
- **`--fail-on high` also fails on `critical`.**
- `--owasp` does not change the HTML or Markdown reports.
- **Finding counts drop**, and the missing-protection rules (`IOS_MISSING_APP_SNAPSHOT_PROTECTION`, `SCREENSHOT_PROTECTION_MISSING`, `MISSING_SESSION_TIMEOUT`) now give one project-level finding, so old baseline entries for them may no longer match.
- **CI using `--min-confidence` or `--fail-on medium` may see changes**: 22 heuristic rules now carry explicit confidence values, and `DEPENDENCY_NONREGISTRY_SOURCE` is LOW for dependencies pinned to a git commit.

## Known gaps

- Static analysis cannot establish MASVS compliance. There is no APK, IPA or dynamic analysis.
- 7 rules have no OWASP mapping, with the reason listed in [docs/owasp-coverage.md](https://github.com/adnxy/rnsec/blob/main/docs/owasp-coverage.md).
- `critical` is used by two cases by default.
- `HARDCODED_SECRETS` and `API_KEY_EXPOSED` were not improved (26 findings on the benchmark corpus, mostly false positives); a few `NO_REQUEST_TIMEOUT` false positives remain for server code in app repositories; findings are not tiered.

---

## 📦 Install

```bash
npm install -g rnsec@1.5.0
```

## 💬 Support

- 🐛 **Issues**: [github.com/adnxy/rnsec/issues](https://github.com/adnxy/rnsec/issues)
- 📧 **Email**: adnanpoviolabs@gmail.com
- ⭐ **Like rnsec?** [Star us on GitHub](https://github.com/adnxy/rnsec)
- 💖 **Want to sponsor?** [GitHub Sponsors](https://github.com/sponsors/adnxy)

---

## 📄 License

MIT License - see [LICENSE](https://github.com/adnxy/rnsec/blob/main/LICENSE) for details.

---

**Made with ❤️ by [@adnxy](https://github.com/adnxy)**
