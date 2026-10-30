# 🚀 rnsec 1.5.0 Release Notes

**Release Date**: October 30, 2026

rnsec 1.5.0 maps its findings to the OWASP Mobile Application Security standards (MASVS, MASWE and MASTG) and adds a MASVS coverage report. It still performs static analysis only: it does not verify MASVS compliance. Please read the upgrade notes: error exit codes changed.

The full list of changes is in the [CHANGELOG](https://github.com/adnxy/rnsec/blob/main/CHANGELOG.md#150---2026-10-30).

---

## 🌟 Highlights

### OWASP MASVS, MASWE and MASTG mapping

- 100 of the 106 rules are mapped to MASVS 2.1.0 controls, MASWE 1.0.0 weaknesses and MASTG tests. The mapping lives in one table, separate from the detection code.
- The standards data is a pinned, vendored snapshot (8 MASVS categories including PRIVACY, 24 controls). A test fails if a mapping uses an ID that is not in the snapshot.
- `--owasp` adds the references to every finding and prints a coverage section. Each of the 24 controls is reported as `failed`, `checked`, `checked (heuristic)`, `not applicable` or `not assessed`. Controls marked `not assessed` need manual or dynamic verification.
- `rnsec rules --owasp` lists every rule with its MASVS and MASWE references.

```bash
rnsec scan --owasp
rnsec scan --owasp --format json
rnsec scan --owasp --format sarif
rnsec scan --owasp --fail-on high
```

### CI output

- `--format console|json|sarif` prints one machine-readable format to stdout with nothing else mixed in.
- SARIF now carries MASVS, MASWE, MASTG and CWE tags, a help link per rule and an MASVS taxonomy.
- `critical` is a new severity, usable with `--fail-on`. It applies to a committed service-account JSON with a real private key and to a `.p8` file containing a PEM private key. Other rules can be raised with `severityOverrides`.
- Updated GitHub Actions and GitLab CI examples, plus a pre-commit example in `examples/pre-commit/`.

### Rules

- `EXPO_UPDATES_INSECURE_URL`, `EXPO_UPDATES_NO_CODE_SIGNING` and `EXPO_INSECURE_PERMISSIONS` now read static values in `app.config.js|ts`. Values that cannot be established statically are never flagged.
- New rule `EXPO_PUBLIC_ENV_SECRET` for secrets in `EXPO_PUBLIC_*` variables of committed `.env` files.

---

## ⚠️ Upgrade notes

- **Errors now exit 2.** Exit codes are `0` (clean), `1` (findings at or above `--fail-on`) and `2` (scan, usage or internal error). CI that treated any non-zero exit the same is unaffected; CI that matched `1` for errors must be updated.
- **`scan -p <missing dir>` now fails** with exit 2 instead of passing with zero files.
- **Finding order is deterministic** (sorted by file, line, column and rule), so JSON and console order differs from 1.4.0.
- **`--fail-on high` also fails on `critical`.**
- `--owasp` does not change the HTML or Markdown reports.

## Known gaps

- Static analysis cannot establish MASVS compliance. There is no APK, IPA or dynamic analysis.
- 6 rules have no OWASP mapping, with the reason listed in [docs/owasp-coverage.md](https://github.com/adnxy/rnsec/blob/main/docs/owasp-coverage.md).
- `critical` is used by two cases by default.

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
