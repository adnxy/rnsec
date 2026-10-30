/**
 * Central rule -> OWASP mapping (MASVS v2.1.0 / MASWE v1.0.0 / MASTG v2.0.0 + master@2eb0f70, see snapshot.json).
 *
 * Kept separate from rule detection: rule definitions know nothing about standards.
 * Every registered rule id is in exactly one of RULE_STANDARDS or UNMAPPED_RULES
 * (enforced by tests/owasp-mappings.test.mjs).
 *
 * Conventions:
 * - `masvs` is derived from the chosen MASWE entries (their own `masvs` list in the snapshot).
 *   An explicit `masvs` is written only when it is narrower than that union (comment says why),
 *   or when no MASWE fits and a MASVS control is the honest ceiling.
 * - `mastg` lists static tests whose title matches the check ("References to...", "Hardcoded...",
 *   "Configurations Allowing..."). Runtime/dynamic tests are not listed: a static rule does not cover them.
 * - `cwe` entries are chosen from the MASWE's CWE list where one fits, else only numbers whose
 *   meaning is certain. Weak spots are left out rather than guessed.
 */
import { loadOwaspSnapshot } from "./snapshot.js";

export type RulePlatform = "android" | "ios" | "cross-platform" | "expo";
export type MappingConfidence = "high" | "medium" | "low";

export interface RuleStandards {
  /** MASVS v2 control ids, e.g. "MASVS-STORAGE-1" */
  masvs: string[];
  /** MASWE ids, e.g. "MASWE-0001" */
  maswe: string[];
  /** MASTG test ids, e.g. "MASTG-TEST-0231" */
  mastg: string[];
  cwe?: number[];
  platform: RulePlatform[];
  /** How well the rule's check matches the mapped weakness (presence/absence heuristics are 'low') */
  confidence: MappingConfidence;
  /** Short human title (rules only carry a `description`) */
  title: string;
  mappingNote?: string;
}

/** Union (sorted, de-duplicated) of the MASVS controls listed by the given MASWE entries in the snapshot. */
export function masvsFromMaswe(maswe: string[]): string[] {
  const entries = loadOwaspSnapshot().maswe;
  const out = new Set<string>();
  for (const id of maswe) {
    const entry = entries[id];
    if (!entry) throw new Error(`Unknown MASWE id in mapping: ${id}`);
    for (const control of entry.masvs) out.add(control);
  }
  return [...out].sort();
}

interface RuleStandardsSpec extends Omit<RuleStandards, "masvs" | "maswe" | "mastg"> {
  maswe?: string[];
  mastg?: string[];
  /** Only when narrower than the MASWE union, or when `maswe` is empty */
  masvs?: string[];
}

function define(specs: Record<string, RuleStandardsSpec>): Record<string, RuleStandards> {
  const out: Record<string, RuleStandards> = {};
  for (const [id, spec] of Object.entries(specs)) {
    const maswe = spec.maswe ?? [];
    out[id] = { ...spec, maswe, mastg: spec.mastg ?? [], masvs: spec.masvs ?? masvsFromMaswe(maswe) };
  }
  return out;
}

export const RULE_STANDARDS: Record<string, RuleStandards> = define({
  // ── android/androidScanner.ts ─────────────────────────────────────────────
  ANDROID_BACKUP_ALLOWED: {
    title: "Android backup allowed",
    maswe: ["MASWE-0006"],
    mastg: ["MASTG-TEST-0216", "MASTG-TEST-0262"],
    cwe: [212],
    platform: ["android"],
    confidence: "high",
  },
  ANDROID_CONTENT_PROVIDER_NO_PERMISSION: {
    title: "Content provider without permissions",
    maswe: ["MASWE-0018"],
    mastg: ["MASTG-TEST-0355", "MASTG-TEST-0357"],
    cwe: [926],
    platform: ["android"],
    confidence: "high",
  },
  ANDROID_DEBUGGABLE_ENABLED: {
    title: "Debuggable flag enabled",
    maswe: ["MASWE-0063"],
    mastg: ["MASTG-TEST-0226"],
    cwe: [489],
    platform: ["android"],
    confidence: "high",
  },
  ANDROID_EXPORTED_COMPONENT: {
    title: "Exported component without permission",
    maswe: ["MASWE-0018"],
    mastg: ["MASTG-TEST-0364", "MASTG-TEST-0365", "MASTG-TEST-0366"],
    cwe: [926],
    platform: ["android"],
    confidence: "high",
  },
  ANDROID_INTENT_FILTER_PERMISSIVE: {
    title: "Overly permissive intent filter",
    maswe: ["MASWE-0018"],
    cwe: [926],
    platform: ["android"],
    confidence: "medium",
    mappingNote: "No static MASTG test targets permissive intent filters; MASWE-0032 (insecure intents) concerns implicit intents sent by the app.",
  },
  ANDROID_MISSING_NETWORK_SECURITY_CONFIG: {
    title: "Missing network security config",
    maswe: ["MASWE-0026"],
    platform: ["android"],
    confidence: "low",
    mappingNote: "A missing config is not a weakness by itself on API 28+ (cleartext is off by default); it only means no explicit hardening.",
  },
  ANDROID_TASK_AFFINITY_VULNERABILITY: {
    title: "Custom task affinity (task hijacking)",
    maswe: ["MASWE-0039"],
    cwe: [1021],
    platform: ["android"],
    confidence: "low",
    mappingNote: "Task hijacking is a UI redress attack; the closest MASWE is the overlay-attack entry and no MASTG test covers task affinity.",
  },
  ANDROID_UNPROTECTED_RECEIVER: {
    title: "Broadcast receiver without permission",
    maswe: ["MASWE-0018"],
    mastg: ["MASTG-TEST-0366"],
    cwe: [926],
    platform: ["android"],
    confidence: "high",
  },
  ANDROID_WEBVIEW_DEBUG_ENABLED: {
    title: "WebView debugging enabled",
    maswe: ["MASWE-0063"],
    mastg: ["MASTG-TEST-0227"],
    cwe: [489],
    platform: ["android"],
    confidence: "high",
  },
  EXCESSIVE_PERMISSIONS: {
    title: "Unused Android permissions",
    maswe: ["MASWE-0066"],
    mastg: ["MASTG-TEST-0255"],
    cwe: [250],
    platform: ["android"],
    confidence: "medium",
  },
  INSECURE_KEYSTORE_USAGE: {
    title: "Weak Android Keystore configuration",
    maswe: ["MASWE-0007", "MASWE-0016"],
    mastg: ["MASTG-TEST-0232"],
    cwe: [327],
    platform: ["android"],
    confidence: "medium",
    mappingNote: "Covers ECB mode (MASWE-0007, MASTG-TEST-0232) and keys without user-authentication requirement (MASWE-0016); the StrongBox check has no matching weakness.",
  },

  // ── android/gradleScanner.ts ──────────────────────────────────────────────
  ANDROID_SIGNING_CREDENTIALS_HARDCODED: {
    title: "Signing password hardcoded in Gradle",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["android"],
    confidence: "medium",
    mappingNote: "The secret sits in a build file, not in the shipped package; MASWE-0004 is the closest hardcoded-secret weakness.",
  },

  // ── android/manifestScanner.ts ────────────────────────────────────────────
  ANDROID_CLEARTEXT_ENABLED: {
    title: "Cleartext traffic enabled",
    maswe: ["MASWE-0026"],
    mastg: ["MASTG-TEST-0235"],
    cwe: [319],
    platform: ["android"],
    confidence: "high",
  },
  IOS_ATS_DISABLED: {
    title: "App Transport Security disabled",
    maswe: ["MASWE-0026"],
    mastg: ["MASTG-TEST-0322"],
    cwe: [319],
    platform: ["ios"],
    confidence: "high",
  },

  // ── android/networkSecurityConfigScanner.ts ───────────────────────────────
  ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT: {
    title: "Network security config allows cleartext",
    maswe: ["MASWE-0026"],
    mastg: ["MASTG-TEST-0235"],
    cwe: [319],
    platform: ["android"],
    confidence: "high",
  },
  ANDROID_USER_CA_TRUSTED: {
    title: "User CAs or overridePins trusted",
    maswe: ["MASWE-0027"],
    mastg: ["MASTG-TEST-0286"],
    cwe: [295],
    platform: ["android"],
    confidence: "high",
  },

  // ── ios/iosPlistExtraScanner.ts ───────────────────────────────────────────
  IOS_FILE_SHARING_ENABLED: {
    title: "iOS file sharing enabled",
    maswe: ["MASWE-0002"],
    cwe: [921],
    platform: ["ios"],
    confidence: "medium",
  },

  // ── ios/iosScanner.ts ─────────────────────────────────────────────────────
  IOS_ATS_EXCEPTION_TOO_PERMISSIVE: {
    title: "Permissive ATS exception",
    maswe: ["MASWE-0026"],
    mastg: ["MASTG-TEST-0322", "MASTG-TEST-0342"],
    cwe: [319],
    platform: ["ios"],
    confidence: "high",
  },
  IOS_CUSTOM_URL_SCHEME_UNPROTECTED: {
    title: "Custom URL scheme without validation",
    maswe: ["MASWE-0029"],
    mastg: ["MASTG-TEST-0370"],
    cwe: [939],
    platform: ["ios"],
    confidence: "medium",
  },
  IOS_DATA_PROTECTION_MISSING: {
    title: "NSFileProtectionNone used",
    maswe: ["MASWE-0001"],
    mastg: ["MASTG-TEST-0299"],
    cwe: [312],
    platform: ["ios"],
    confidence: "high",
  },
  IOS_INSECURE_PASTEBOARD_USAGE: {
    title: "Sensitive data on iOS pasteboard",
    maswe: ["MASWE-0030"],
    cwe: [200],
    platform: ["ios"],
    confidence: "medium",
    mappingNote: "MASTG-TEST-0276 (iOS general pasteboard) is filed upstream under MASWE-0036 (UI exposure), which would add MASVS-PLATFORM-3 coverage this check does not earn, so it is not listed.",
  },
  IOS_KEYCHAIN_ACCESS_GROUP_INSECURE: {
    title: "Keychain access group may expose data",
    maswe: ["MASWE-0016"],
    cwe: [284],
    platform: ["ios"],
    confidence: "low",
    mappingNote: "No MASTG test covers keychain access groups.",
  },
  IOS_MISSING_APP_SNAPSHOT_PROTECTION: {
    title: "No app snapshot protection",
    maswe: ["MASWE-0038"],
    cwe: [200],
    platform: ["ios"],
    confidence: "low",
    mappingNote: "Presence heuristic. The only iOS MASTG test for backgrounding screenshots (MASTG-TEST-0290) is runtime-only, so it is not listed.",
  },
  IOS_UNIVERSAL_LINKS_MISCONFIGURED: {
    title: "Universal links without validation",
    maswe: ["MASWE-0029"],
    mastg: ["MASTG-TEST-0395"],
    platform: ["ios"],
    confidence: "medium",
  },
  IOS_USAGE_DESCRIPTIONS_MISSING: {
    title: "Missing iOS usage description",
    maswe: ["MASWE-0066"],
    mastg: ["MASTG-TEST-0360"],
    platform: ["ios"],
    confidence: "medium",
    mappingNote: "MASTG-TEST-0360 checks purpose-string accuracy; this rule only checks that one exists.",
  },
  INSECURE_KEYCHAIN_USAGE: {
    title: "Keychain accessible while locked",
    maswe: ["MASWE-0016"],
    cwe: [284],
    platform: ["ios"],
    confidence: "medium",
  },

  // ── modules/dependencySourceScanner.ts ────────────────────────────────────
  DEPENDENCY_NONREGISTRY_SOURCE: {
    title: "Dependency from non-registry source",
    masvs: ["MASVS-CODE-3"], // no MASWE for dependency provenance; MASWE-0075 (reproducible builds) does not fit
    cwe: [1357],
    platform: ["cross-platform"],
    confidence: "low",
    mappingNote: "Supply-chain hygiene (git/URL/unbounded versions). No MASWE or MASTG test is a faithful match.",
  },

  // ── modules/npmScanner.ts ─────────────────────────────────────────────────
  DEPRECATED_NPM_PACKAGE: {
    title: "Deprecated npm package",
    masvs: ["MASVS-CODE-3"], // MASWE-0046 is about deprecated APIs, not deprecated packages
    cwe: [1104],
    platform: ["cross-platform"],
    confidence: "low",
    mappingNote: "Unmaintained component; a deprecation notice is not a known vulnerability (that is NPM_VULNERABLE_DEPENDENCY).",
  },
  NPM_VULNERABLE_DEPENDENCY: {
    title: "Vulnerable npm dependency",
    maswe: ["MASWE-0044"],
    mastg: ["MASTG-TEST-0272", "MASTG-TEST-0273"],
    cwe: [1395],
    platform: ["cross-platform"],
    confidence: "high",
    mappingNote: "The MASTG tests scan Gradle/iOS dependency managers; npm lockfile scanning is the same check for the JS layer.",
  },
  SUSPICIOUS_LIFECYCLE_SCRIPT: {
    title: "Suspicious npm lifecycle script",
    maswe: ["MASWE-0048"],
    cwe: [506],
    platform: ["cross-platform"],
    confidence: "medium",
  },

  // ── modules/registryConfigScanner.ts ──────────────────────────────────────
  NPM_REGISTRY_CONFIG_INSECURE: {
    title: "Insecure npm/Yarn registry config",
    masvs: ["MASVS-CODE-3"], // build supply chain; no MASWE covers package-registry transport or credentials
    cwe: [319, 798],
    platform: ["cross-platform"],
    confidence: "low",
  },

  // ── react-native/reactNativeScanner.ts ────────────────────────────────────
  EVAL_USAGE: {
    title: "eval() usage",
    maswe: ["MASWE-0050"],
    cwe: [95],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  EXPO_AUTH_SESSION_NO_PKCE: {
    title: "Expo AuthSession without PKCE",
    masvs: ["MASVS-AUTH-1"], // no MASWE for OAuth flow hardening
    platform: ["expo"],
    confidence: "medium",
  },
  EXPO_UPDATES_NO_CODE_SIGNING: {
    title: "Expo OTA updates without code signing",
    maswe: ["MASWE-0049"],
    cwe: [494],
    platform: ["expo"],
    confidence: "high",
  },
  INSECURE_DEEPLINK_HANDLER: {
    title: "Deep link handled without validation",
    maswe: ["MASWE-0029"],
    mastg: ["MASTG-TEST-0370", "MASTG-TEST-0394"],
    cwe: [939],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  INSECURE_DESERIALIZATION: {
    title: "eval/Function on dynamic input",
    maswe: ["MASWE-0050"],
    cwe: [95, 502],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "The rule flags eval/Function on data; MASTG-TEST-0337/0386 target native object deserialization and are not listed.",
  },
  INSECURE_LINKING_OPEN: {
    title: "Linking.openURL with unvalidated input",
    maswe: ["MASWE-0050"],
    cwe: [20],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  JAVASCRIPT_ENABLED_BRIDGE: {
    title: "Native module without input validation",
    maswe: ["MASWE-0050"],
    cwe: [20],
    platform: ["cross-platform"],
    confidence: "low",
    mappingNote: "Native-module bridge, not a WebView bridge, so MASWE-0033 and its MASTG tests do not apply.",
  },
  MISSING_RUNTIME_INTEGRITY_CHECKS: {
    title: "No runtime integrity checks",
    maswe: ["MASWE-0058"],
    platform: ["cross-platform"],
    confidence: "low",
  },
  NETWORK_LOGGER_IN_PRODUCTION: {
    title: "Network logger in production",
    maswe: ["MASWE-0005"],
    cwe: [532],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  OBFUSCATED_EVAL_EXECUTION: {
    title: "Obfuscated eval (likely malware)",
    maswe: ["MASWE-0048"],
    cwe: [506],
    platform: ["cross-platform"],
    confidence: "high",
  },
  PUSH_NOTIFICATION_SENSITIVE_DATA: {
    title: "Sensitive data in push notifications",
    maswe: ["MASWE-0037"],
    mastg: ["MASTG-TEST-0315"],
    cwe: [200],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  ROOT_JAILBREAK_DETECTION_ABSENT: {
    title: "No root/jailbreak detection",
    maswe: ["MASWE-0051"],
    mastg: ["MASTG-TEST-0240", "MASTG-TEST-0324"],
    // snapshot lists CWE-1326 (hardware root of trust) for MASWE-0051; it does not describe this check, so omitted
    platform: ["cross-platform"],
    confidence: "low",
  },
  SCREENSHOT_PROTECTION_MISSING: {
    title: "No screenshot protection",
    maswe: ["MASWE-0038"],
    mastg: ["MASTG-TEST-0291"],
    cwe: [200],
    platform: ["cross-platform"],
    confidence: "low",
    mappingNote: "Presence heuristic; MASTG-TEST-0291 is Android-only (no static iOS test exists in the snapshot).",
  },
  THIRD_PARTY_SDK_RISK: {
    title: "Risky analytics/session-replay SDK",
    maswe: ["MASWE-0069"],
    cwe: [359],
    platform: ["cross-platform"],
    confidence: "low",
    mappingNote: "MASTG-TEST-0318 lists SDK references too, but upstream files it under MASWE-0073 (data collection declarations); this rule does not check declarations, so it is not listed.",
  },
  UNSAFE_DANGEROUSLY_SET_INNER_HTML: {
    title: "dangerouslySetInnerHTML with unsafe content",
    maswe: ["MASWE-0050"],
    cwe: [79],
    platform: ["cross-platform"],
    confidence: "medium",
  },

  // ── security/authenticationScanner.ts ─────────────────────────────────────
  CERT_PINNING_DISABLED: {
    title: "Certificate pinning disabled",
    maswe: ["MASWE-0028"],
    cwe: [295],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "MASTG-TEST-0242/0385 check native pinning config, not JS-level bypass, so they are not listed.",
  },
  IMPROPER_BIOMETRIC_FALLBACK: {
    title: "Biometric auth with insecure fallback",
    maswe: ["MASWE-0021"],
    mastg: ["MASTG-TEST-0268", "MASTG-TEST-0326"],
    cwe: [288],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  INSECURE_RANDOM: {
    title: "Math.random() for security values",
    maswe: ["MASWE-0012"],
    mastg: ["MASTG-TEST-0204", "MASTG-TEST-0311"],
    cwe: [338],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  JWT_NO_EXPIRY_CHECK: {
    title: "JWT used without expiry check",
    masvs: ["MASVS-AUTH-1"], // no MASWE for token/session lifetime handling
    cwe: [613],
    platform: ["cross-platform"],
    confidence: "low",
  },
  MISSING_SESSION_TIMEOUT: {
    title: "No session timeout",
    maswe: ["MASWE-0024"],
    cwe: [613],
    platform: ["cross-platform"],
    confidence: "low",
    mappingNote: "MASWE-0024 (data accessible after session termination) is the nearest entry; there is no MASWE for session timeouts as such.",
  },
  OAUTH_TOKEN_IN_URL: {
    title: "OAuth token in URL query",
    masvs: ["MASVS-NETWORK-1"], // no MASWE for credentials in URLs
    cwe: [598],
    platform: ["cross-platform"],
    confidence: "low",
  },
  TEXT_INPUT_NO_SECURE: {
    title: "Password input without secureTextEntry",
    maswe: ["MASWE-0036"],
    mastg: ["MASTG-TEST-0316", "MASTG-TEST-0346"],
    cwe: [549],
    platform: ["cross-platform"],
    confidence: "high",
  },

  // ── security/configScanner.ts ─────────────────────────────────────────────
  EXPO_INSECURE_PERMISSIONS: {
    title: "Dangerous permissions in Expo config",
    maswe: ["MASWE-0066"],
    mastg: ["MASTG-TEST-0254"],
    cwe: [250],
    platform: ["expo", "android"],
    confidence: "medium",
  },
  EXPO_UPDATES_INSECURE_URL: {
    title: "Expo updates URL over HTTP",
    maswe: ["MASWE-0026"],
    cwe: [319],
    platform: ["expo"],
    confidence: "high",
  },

  // ── security/credentialFilesScanner.ts ────────────────────────────────────
  COMMITTED_CREDENTIAL_FILE: {
    title: "Credential file committed to repo",
    maswe: ["MASWE-0004"],
    cwe: [540],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "Repository exposure rather than app-package exposure; MASWE-0004 is the closest hardcoded-secret weakness.",
  },

  // ── security/cryptoScanner.ts ─────────────────────────────────────────────
  CUSTOM_CRYPTO_IMPLEMENTATION: {
    title: "Custom crypto implementation",
    maswe: ["MASWE-0047"],
    masvs: ["MASVS-CRYPTO-1"], // MASWE-0047 also lists AUTH-1, CODE-3, NETWORK-1; only the crypto control applies here
    cwe: [1240],
    platform: ["cross-platform"],
    confidence: "low",
  },
  HARDCODED_ENCRYPTION_KEY: {
    title: "Hardcoded encryption key or IV",
    maswe: ["MASWE-0003", "MASWE-0004"],
    mastg: ["MASTG-TEST-0212", "MASTG-TEST-0213"],
    cwe: [321],
    platform: ["cross-platform"],
    confidence: "high",
    mappingNote: "The snapshot links MASTG-TEST-0212/0213 to MASWE-0014 (key derivation in the pinned MASWE); the pinned titles for 0003/0004 fit a hardcoded key better.",
  },
  WEAK_CIPHER_OR_MODE: {
    title: "Weak cipher or ECB mode",
    maswe: ["MASWE-0007"],
    mastg: ["MASTG-TEST-0210", "MASTG-TEST-0221", "MASTG-TEST-0232", "MASTG-TEST-0317"],
    cwe: [327],
    platform: ["cross-platform"],
    confidence: "high",
  },
  WEAK_HASH_ALGORITHM: {
    title: "Weak hash algorithm (MD5, SHA-1)",
    maswe: ["MASWE-0008"],
    mastg: ["MASTG-TEST-0211"],
    cwe: [328],
    platform: ["cross-platform"],
    confidence: "high",
    mappingNote: "The snapshot has no Android hashing test; MASTG-TEST-0211 is iOS.",
  },

  // ── security/debugScanner.ts ──────────────────────────────────────────────
  DEBUG_ENDPOINTS_EXPOSED: {
    title: "Debug endpoints in production code",
    maswe: ["MASWE-0061"],
    cwe: [489],
    platform: ["cross-platform"],
    confidence: "low",
    mappingNote: "URL-path heuristic only; it cannot tell a debug endpoint from a similarly named production route.",
  },
  REDUX_DEVTOOLS_ENABLED: {
    title: "Redux DevTools enabled in production",
    maswe: ["MASWE-0063"],
    cwe: [489],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  TEST_CREDENTIALS_IN_CODE: {
    title: "Test credentials in code",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["cross-platform"],
    confidence: "medium",
  },

  // ── security/expoConfigScanner.ts ─────────────────────────────────────────
  EAS_JSON_SECRET_IN_ENV: {
    title: "Secret in eas.json env",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["expo"],
    confidence: "medium",
    mappingNote: "Committed build config, not the shipped package; MASWE-0004 is the closest hardcoded-secret weakness.",
  },
  EXPO_PUBLIC_ENV_SECRET: {
    title: "Secret in EXPO_PUBLIC_ env variable",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["expo"],
    confidence: "medium",
    mappingNote: "EXPO_PUBLIC_ values are inlined into the shipped JS bundle; same weakness and mapping as BUNDLED_ENV_SECRET.",
  },
  EXPO_CONFIG_INSECURE_SETTINGS: {
    title: "Insecure setting in Expo app config",
    maswe: ["MASWE-0006", "MASWE-0026"],
    mastg: ["MASTG-TEST-0216", "MASTG-TEST-0237", "MASTG-TEST-0322"],
    cwe: [212, 319],
    platform: ["expo"],
    confidence: "medium",
    mappingNote: "Covers allowBackup (MASWE-0006), usesCleartextTraffic and ATS overrides (MASWE-0026).",
  },
  EXPO_SENSITIVE_CONFIG_EXPOSED: {
    title: "Secret in Expo app config",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["expo"],
    confidence: "high",
  },

  // ── security/loggingScanner.ts ────────────────────────────────────────────
  SENSITIVE_DATA_IN_ERROR_MESSAGES: {
    title: "Sensitive data in error messages",
    maswe: ["MASWE-0005"],
    cwe: [209],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  SENSITIVE_LOGGING: {
    title: "Sensitive data logged",
    maswe: ["MASWE-0005"],
    mastg: ["MASTG-TEST-0231", "MASTG-TEST-0297"],
    cwe: [532],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "JS console output reaches Logcat/OS log; the MASTG tests inspect the native logging APIs.",
  },

  // ── security/networkScanner.ts ────────────────────────────────────────────
  INSECURE_HTTP_URL: {
    title: "Insecure http:// URL",
    maswe: ["MASWE-0026"],
    mastg: ["MASTG-TEST-0233", "MASTG-TEST-0321"],
    cwe: [319],
    platform: ["cross-platform"],
    confidence: "high",
  },
  INSECURE_WEBSOCKET: {
    title: "Unencrypted ws:// WebSocket",
    maswe: ["MASWE-0026"],
    cwe: [319],
    platform: ["cross-platform"],
    confidence: "high",
  },
  INSECURE_WEBVIEW: {
    title: "WebView insecure configuration",
    maswe: ["MASWE-0035"],
    cwe: [79],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  WEAK_TLS_CONFIGURATION: {
    title: "Weak TLS configuration",
    maswe: ["MASWE-0026"],
    mastg: ["MASTG-TEST-0217"],
    cwe: [327],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "No MASWE in the pinned release is specifically about TLS versions; MASTG-TEST-0217 is the Android static check for explicitly allowed insecure protocols.",
  },

  // ── security/rnExtraScanner.ts ────────────────────────────────────────────
  HARDCODED_BASIC_AUTH_CREDENTIALS: {
    title: "Hardcoded basic-auth credentials",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["cross-platform"],
    confidence: "high",
  },
  JWT_INSECURE_SIGNING: {
    title: "JWT with hardcoded secret or alg none",
    maswe: ["MASWE-0004", "MASWE-0011"],
    cwe: [347, 798],
    platform: ["cross-platform"],
    confidence: "high",
  },

  // ── security/rnSecurityScanner.ts ─────────────────────────────────────────
  BUNDLED_ENV_SECRET: {
    title: "Secret from bundled env variable",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["cross-platform"],
    confidence: "high",
  },
  MMKV_UNENCRYPTED_SENSITIVE_DATA: {
    title: "Unencrypted MMKV or hardcoded MMKV key",
    maswe: ["MASWE-0001", "MASWE-0004"],
    cwe: [312, 321],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  OAUTH_INSECURE_FLOW: {
    title: "OAuth without PKCE/nonce or implicit grant",
    masvs: ["MASVS-AUTH-1"], // no MASWE for OAuth flow hardening
    platform: ["cross-platform"],
    confidence: "medium",
  },
  SQLITE_QUERY_INJECTION: {
    title: "SQL built by string interpolation",
    maswe: ["MASWE-0050"],
    cwe: [89],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  TLS_VALIDATION_DISABLED_ENV: {
    title: "TLS certificate validation disabled",
    maswe: ["MASWE-0027"],
    cwe: [295],
    platform: ["cross-platform"],
    confidence: "high",
  },

  // ── security/secretsScanner.ts ────────────────────────────────────────────
  API_KEY_EXPOSED: {
    title: "API key exposed in source",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["cross-platform"],
    confidence: "high",
  },
  ENV_FILE_COMMITTED: {
    title: "Env file committed",
    maswe: ["MASWE-0004"],
    cwe: [540],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "Repository exposure rather than app-package exposure; MASWE-0004 is the closest hardcoded-secret weakness.",
  },

  // ── security/storageScanner.ts ────────────────────────────────────────────
  ASYNCSTORAGE_PII_DATA: {
    title: "PII in AsyncStorage",
    maswe: ["MASWE-0001", "MASWE-0002"],
    cwe: [312, 359],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "No MASTG test targets AsyncStorage; it is unencrypted app-private storage (SharedPreferences/SQLite on Android, files on iOS).",
  },
  ASYNCSTORAGE_SENSITIVE_KEY: {
    title: "Sensitive key in AsyncStorage",
    maswe: ["MASWE-0001", "MASWE-0002"],
    cwe: [312, 922],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "No MASTG test targets AsyncStorage; it is unencrypted app-private storage (SharedPreferences/SQLite on Android, files on iOS).",
  },
  CLIPBOARD_SENSITIVE_DATA: {
    title: "Sensitive data copied to clipboard",
    maswe: ["MASWE-0030"],
    cwe: [200, 668],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "No MASTG test is linked: the snapshot has no static clipboard test for Android, and the iOS pasteboard test is filed upstream under MASWE-0036 (UI exposure), not MASWE-0030.",
  },
  EXPO_SECURE_STORE_WEAK_OPTIONS: {
    title: "SecureStore item readable while locked",
    maswe: ["MASWE-0016"],
    cwe: [284],
    platform: ["expo"],
    confidence: "medium",
  },
  HARDCODED_SECRETS: {
    title: "Hardcoded secrets in source",
    maswe: ["MASWE-0004"],
    cwe: [798],
    platform: ["cross-platform"],
    confidence: "high",
  },
  INSECURE_FILE_STORAGE: {
    title: "Files written to external storage",
    maswe: ["MASWE-0002"],
    mastg: ["MASTG-TEST-0202"],
    cwe: [921],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "MASTG-TEST-0202 is Android-only.",
  },
  MMKV_NO_ENCRYPTION: {
    title: "MMKV without encryption",
    maswe: ["MASWE-0001"],
    cwe: [312],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  REDUX_PERSIST_NO_ENCRYPTION: {
    title: "redux-persist without encryption",
    maswe: ["MASWE-0001"],
    cwe: [312],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  UNENCRYPTED_REALM_DATABASE: {
    title: "Realm database without encryption",
    maswe: ["MASWE-0001"],
    cwe: [312],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  UNENCRYPTED_SQLITE_DATABASE: {
    title: "SQLite database without encryption",
    maswe: ["MASWE-0001"],
    cwe: [312],
    platform: ["cross-platform"],
    confidence: "medium",
  },

  // ── security/webviewScanner.ts ────────────────────────────────────────────
  WEBVIEW_CACHING_ENABLED: {
    title: "WebView caching enabled",
    maswe: ["MASWE-0001"],
    platform: ["cross-platform"],
    confidence: "low",
    mappingNote: "Cached web content lands in unencrypted private storage; the rule only flags the setting, not sensitive content.",
  },
  WEBVIEW_FILE_ACCESS: {
    title: "WebView file access enabled",
    maswe: ["MASWE-0034"],
    mastg: ["MASTG-TEST-0252", "MASTG-TEST-0333"],
    cwe: [200],
    platform: ["cross-platform"],
    confidence: "high",
  },
  WEBVIEW_GEOLOCATION_ENABLED: {
    title: "WebView geolocation enabled",
    maswe: ["MASWE-0066"],
    platform: ["cross-platform"],
    confidence: "low",
  },
  WEBVIEW_JAVASCRIPT_INJECTION: {
    title: "WebView JS with dynamic content",
    maswe: ["MASWE-0035"],
    cwe: [79],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  WEBVIEW_MIXED_CONTENT: {
    title: "WebView allows mixed content",
    maswe: ["MASWE-0026"],
    cwe: [319],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  WEBVIEW_ORIGIN_WHITELIST_WILDCARD: {
    title: "WebView originWhitelist wildcard",
    maswe: ["MASWE-0035"],
    platform: ["cross-platform"],
    confidence: "medium",
  },
  WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK: {
    title: "WebView onMessage without origin check",
    maswe: ["MASWE-0033"],
    cwe: [346],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "MASTG-TEST-0334 and MASTG-TEST-0376 look for native bridge APIs in WebViews (upstream MASWE-0034), not for missing origin checks on onMessage, so they are not listed.",
  },
  WEBVIEW_UNVALIDATED_NAVIGATION: {
    title: "WebView navigation not validated",
    maswe: ["MASWE-0035"],
    mastg: ["MASTG-TEST-0398"],
    cwe: [601],
    platform: ["cross-platform"],
    confidence: "medium",
    mappingNote: "MASTG-TEST-0398 is Android-only.",
  },
  TLS_VALIDATION_DISABLED_NATIVE: {
    title: "TLS validation disabled in native code",
    maswe: ["MASWE-0027"],
    mastg: ["MASTG-TEST-0282", "MASTG-TEST-0283", "MASTG-TEST-0284", "MASTG-TEST-0396", "MASTG-TEST-0397"],
    cwe: [295],
    platform: ["android", "ios"],
    confidence: "high",
    mappingNote: "MASTG-TEST-0282/0283/0284 are Android (trust manager, host name verifier, WebView SSL errors); MASTG-TEST-0396/0397 are iOS (URLSessionDelegate, WKNavigationDelegate).",
  },
  GRADLE_INSECURE_REPOSITORY: {
    title: "Gradle repository over plain HTTP",
    maswe: ["MASWE-0048"],
    platform: ["android"],
    confidence: "medium",
    mappingNote: "No MASWE covers the build supply chain directly; an HTTP repository lets a network attacker inject code into the app (MASWE-0048), but no MASTG test targets it.",
  },
  ANDROID_FILEPROVIDER_BROAD_PATHS: {
    title: "FileProvider shares broad paths",
    maswe: ["MASWE-0018"],
    mastg: ["MASTG-TEST-0357"],
    cwe: [552],
    platform: ["android"],
    confidence: "medium",
  },
});

/** Rules with no sound MASVS fit: ruleId -> reason. Disjoint from RULE_STANDARDS. */
export const UNMAPPED_RULES: Record<string, string> = {
  FIREBASE_RULES_OPEN_ACCESS:
    "Firebase security rules are server-side access control for the backend; MASVS and MASWE cover the client app, not the rules that protect its backend.",
  HARDCODED_IP_ADDRESS:
    "Code hygiene (environment coupling); not a MASVS weakness unless the traffic is cleartext, which INSECURE_HTTP_URL covers.",
  IOS_BACKGROUND_MODES_UNNECESSARY:
    "Review/battery hygiene; no MASVS control or MASWE addresses unused background modes.",
  MISSING_SECURITY_HEADERS:
    "CSP and X-Frame-Options are server response headers; MASVS covers client-side controls only.",
  NO_REQUEST_TIMEOUT:
    "Availability/robustness concern; MASVS has no control for request timeouts.",
  SENSITIVE_NAVIGATION_PARAMS:
    "Params are in-memory JS state; no MASWE fits unless they are persisted or surface in deep-link URLs.",
  WEBVIEW_DOM_STORAGE_ENABLED:
    "DOM storage is a default-on web platform feature, not a weakness by itself; no MASWE or MASTG test targets it.",
};
