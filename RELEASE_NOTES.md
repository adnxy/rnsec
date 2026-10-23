# 🚀 rnsec 1.4.0 Release Notes

**Release Date**: October 23, 2026

rnsec 1.4.0 grows from 87 to **105 security rules**, adds the CI features teams asked for (SARIF for GitHub Code Scanning, baselines, a configurable failure threshold) and removes a lot of false-positive noise. Please read the upgrade notes: some changes make findings appear that were hidden before.

The full list of changes is in the [CHANGELOG](https://github.com/adnxy/rnsec/blob/main/CHANGELOG.md#140---2026-10-23).

---

## 🌟 Highlights

### 18 new rules

| Area | Rules |
|------|-------|
| Secrets and credentials | `COMMITTED_CREDENTIAL_FILE`, `BUNDLED_ENV_SECRET`, `HARDCODED_BASIC_AUTH_CREDENTIALS`, `EAS_JSON_SECRET_IN_ENV`, `ANDROID_SIGNING_CREDENTIALS_HARDCODED` |
| Crypto, TLS and auth | `WEAK_CIPHER_OR_MODE`, `JWT_INSECURE_SIGNING`, `OAUTH_INSECURE_FLOW`, `TLS_VALIDATION_DISABLED_ENV` |
| Storage and injection | `MMKV_UNENCRYPTED_SENSITIVE_DATA`, `SQLITE_QUERY_INJECTION` |
| Android and iOS config | `ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT`, `ANDROID_USER_CA_TRUSTED`, `EXPO_CONFIG_INSECURE_SETTINGS`, `IOS_FILE_SHARING_ENABLED` |
| WebView and supply chain | `WEBVIEW_ORIGIN_WHITELIST_WILDCARD`, `DEPENDENCY_NONREGISTRY_SOURCE`, `NPM_REGISTRY_CONFIG_INSECURE` |

### Built for CI

```bash
# Upload findings to GitHub Code Scanning
rnsec scan --sarif rnsec.sarif

# Adopt rnsec on an existing codebase: record today's findings, fail only on new ones
rnsec scan --write-baseline .rnsec-baseline.json
rnsec scan --baseline .rnsec-baseline.json

# Choose what fails the build: high (default), medium, low or none
rnsec scan --fail-on medium
```

- `severityOverrides` in `.rnsec.jsonc` changes a rule's severity; `// rnsec-ignore: RULE_ID reason` silences a single finding.
- Findings carry a `confidence`; `--min-confidence medium` shows only the more certain ones.
- `.gitignore` is respected, and the config file may contain comments and trailing commas.

### Less noise

`__DEV__` guards now apply to the guarded code only, public-by-design keys (Firebase web keys, Stripe `pk_`, Sentry DSNs) are LOW, same-line duplicates are merged, and many rules got tighter matching.

---

## ⚠️ Upgrade notes

- **More findings can appear, including HIGH ones.** One `__DEV__ &&` used to hide every finding in a file. If your CI now fails, record a baseline with `--write-baseline`.
- **`.gitignore` is respected.** Findings in git-ignored files disappear. Use `--no-gitignore` to scan them.
- **`--json` stdout is pure JSON.** Informational lines moved to stderr, and piped output is no longer cut off at 8 KB.
- **Severity changes:** public-by-design keys, Stripe `sk_test_` keys and `NO_REQUEST_TIMEOUT` are LOW; `ROOT_JAILBREAK_DETECTION_ABSENT` and `MISSING_RUNTIME_INTEGRITY_CHECKS` are LOW with low confidence and only fire for payments, banking, crypto-wallet and health apps; `EXPO_SECURE_STORE_WEAK_OPTIONS` no longer flags `AFTER_FIRST_UNLOCK`.
- **Exit code:** still 1 only for HIGH findings by default; configurable with `--fail-on` / `failOn`. Errors exit 1.
- **Node.js 20 or newer is required** (was 18).

## 🐛 Fixes

- `ASYNCSTORAGE_SENSITIVE_KEY` flags `last_token`-style keys again.
- `--changed-files` works with `--path` on a monorepo subfolder, and no longer passes the git ref through a shell (refs starting with `-` are rejected).
- rnsec tells you when `.env`, credential and registry-config files were not checked because the folder is not a git checkout.

## Known gaps

Typosquat detection and CodePush code signing checks are not included. Expo config rules read only literal values in `app.config.js|ts`. See the [CHANGELOG](https://github.com/adnxy/rnsec/blob/main/CHANGELOG.md#140---2026-10-23) for details.

---

## 📦 Install

```bash
npm install -g rnsec@1.4.0
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
