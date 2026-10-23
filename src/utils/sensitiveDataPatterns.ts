export const SENSITIVE_KEYWORDS = {
  PASSWORDS: [
    'password',
    'passwd',
    'pwd',
    'credential',
    'credentials',
  ],

  TOKENS: [
    'token',
    'jwt',
    'bearer',
    'accesstoken',
    'access_token',
    'refreshtoken',
    'refresh_token',
    'idtoken',
    'id_token',
    'authtoken',
    'auth_token',
    'sessiontoken',
    'session_token',
  ],

  API_KEYS_SECRETS: [
    'apikey',
    'api_key',
    'api-key',
    'secret',
    'secretkey',
    'secret_key',
    'privatekey',
    'private_key',
    'private-key',
    'publickey',
    'public_key',
    'clientsecret',
    'client_secret',
    'encryption_key',
    'encryptionkey',
  ],

  SESSION_AUTH: [
    'session',
    'sessionid',
    'session_id',
    'authentication',
    'authorization',
  ],

  PERSONAL_ID: [
    'ssn',
    'social_security',
    'passport',
    'passportno',
    'passport_number',
    'driverlicense',
    'driver_license',
    'license_number',
  ],

  PAYMENT: [
    'creditcard',
    'credit_card',
    'cardnumber',
    'card_number',
    'cardholder',
    'cvv',
    'cvc',
    'cvn',
    'pin',
    'pincode',
    'pin_code',
    'accountnumber',
    'account_number',
    'iban',
    'routing',
    'routingnumber',
    'bankaccount',
    'bank_account',
  ],

  CONTACT_INFO: [
    'email',
    'e-mail',
    'emailaddress',
    'email_address',
    'phonenumber',
    'phone_number',
    'mobilenumber',
    'mobile_number',
  ],

  HEALTH_BIOMETRIC: [
    'birthdate',
    'birth_date',
    'dateofbirth',
    'dob',
    'medical',
    'health',
    'biometric',
    'fingerprint',
  ],

  DOT_NOTATION: [
    '.password',
    '.token',
    '.secret',
    '.key',
    '.credential',
    '.email',
    '.phone',
    '.ssn',
    '.pin',
  ],
} as const;

export const ALL_SENSITIVE_KEYWORDS = [
  ...SENSITIVE_KEYWORDS.PASSWORDS,
  ...SENSITIVE_KEYWORDS.TOKENS,
  ...SENSITIVE_KEYWORDS.API_KEYS_SECRETS,
  ...SENSITIVE_KEYWORDS.SESSION_AUTH,
  ...SENSITIVE_KEYWORDS.PERSONAL_ID,
  ...SENSITIVE_KEYWORDS.PAYMENT,
  ...SENSITIVE_KEYWORDS.CONTACT_INFO,
  ...SENSITIVE_KEYWORDS.HEALTH_BIOMETRIC,
  ...SENSITIVE_KEYWORDS.DOT_NOTATION,
] as const;

export const SENSITIVE_DATA_CATEGORIES = {
  PASSWORD: 'Password/Credentials',
  TOKEN: 'Authentication Token',
  API_KEY: 'API Key/Secret',
  SESSION: 'Session Data',
  PII: 'Personal Identifiable Information (PII)',
  PAYMENT: 'Payment/Financial Data',
  USER_PROFILE: 'User Profile Data',
  CRYPTO_KEY: 'Cryptographic Key',
  SENSITIVE: 'Sensitive Data',
} as const;

export const SECRET_PATTERNS = {
  JWT: /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
  AWS_ACCESS_KEY: /^AKIA[0-9A-Z]{16}$/,
  AWS_SECRET_KEY: /^[A-Za-z0-9/+=]{40}$/,
  STRIPE_KEY: /^sk_(test|live)_[A-Za-z0-9]{24,}$/,
  GITHUB_TOKEN: /^gh[pousr]_[A-Za-z0-9]{36,}$/,
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  GENERIC_API_KEY: /^[A-Za-z0-9]{32,}$/,
  BASE64_SECRET: /^[A-Za-z0-9+/=_-]{40,}$/,
  HEX_SECRET: /^[a-fA-F0-9]{32,}$/,
  GENERIC_TOKEN: /^[a-z]{2,}_[A-Za-z0-9_-]{20,}$/,
} as const;

export const IDENTIFIER_PATTERNS = {
  KEBAB_CASE: /^[a-z][a-z0-9]*(-[a-z0-9]+)+$/,
  DOT_NOTATION: /^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)+$/,
  COLON_SEPARATED: /^[a-z]+:[a-z]+$/,
  SIMPLE_WORDS: /^[a-z][a-z\s]+$/i,
  CAMEL_SNAKE_CASE: /^[a-z][a-z0-9_]*$/i,
  CONSTANT_CASE: /^[A-Z][A-Z_]*$/,
} as const;

export const ENTROPY_THRESHOLDS = {
  GENERIC_KEY: 4.0,
  BASE64_SECRET: 4.5,
} as const;
import { Severity, type Confidence } from '../types/findings.js';

// ---------------------------------------------------------------------------
// Value helpers shared by the secret scanners
// ---------------------------------------------------------------------------

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Stopwords are applied to the captured secret value only (never to surrounding code),
// like gitleaks does, so a real key next to the word "example" is still reported.
const PLACEHOLDER_VALUE =
  /example|sample|dummy|placeholder|your[_\-]|yourkey|changeme|change[_\-]me|replace[_\-]?me|redacted|xxxx|\.\.\.|<[^<>]*>|\$\{|\{\{|process\.env/i;

/** Longest run of alphanumerics that each follow the previous one (1234, abcd, DCBA). */
function longestSequentialRun(value: string): number {
  let best = 1;
  let run = 1;
  let dir = 0;
  for (let i = 1; i < value.length; i++) {
    const diff = value.charCodeAt(i) - value.charCodeAt(i - 1);
    const alnum = /[0-9a-zA-Z]/.test(value[i]) && /[0-9a-zA-Z]/.test(value[i - 1]);
    if (alnum && (diff === 1 || diff === -1)) {
      run = dir === diff ? run + 1 : 2;
      dir = diff;
    } else {
      run = 1;
      dir = 0;
    }
    if (run > best) best = run;
  }
  return best;
}

/**
 * True when the value is obviously not a real secret: stopword inside the value,
 * a run of one repeated character, or (when `strict`) a long sequential run like 123456789.
 */
export function isPlaceholderValue(value: string, strict = false): boolean {
  if (!value) return true;
  if (PLACEHOLDER_VALUE.test(value)) return true;
  if (/(.)\1{7,}/.test(value)) return true;
  if (strict && longestSequentialRun(value) >= 8) return true;
  return false;
}

/** Looks like generated key material rather than an identifier or a sentence. */
export function looksRandom(value: string, minEntropy: number): boolean {
  if (/\s/.test(value)) return false;
  if (/^[a-z_\-]+$/.test(value) || /^[A-Z_\-]+$/.test(value)) return false;
  const classes =
    Number(/[a-z]/.test(value)) + Number(/[A-Z]/.test(value)) + Number(/[0-9]/.test(value));
  if (classes < 2) return false;
  return shannonEntropy(value) >= minEntropy;
}

// ---------------------------------------------------------------------------
// Identifier / storage key tokenisation
// ---------------------------------------------------------------------------

/** "authToken", "AUTH_TOKEN", "auth-token", "@app:authToken" -> ["auth", "token"] */
export function tokenizeIdentifier(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map(t => t.toLowerCase());
}

// Words that turn a sensitive-looking name into metadata about the secret, not the secret.
const NON_SECRET_QUALIFIERS = new Set([
  'expiry', 'expires', 'expire', 'expiration', 'expiresat', 'exp', 'timestamp', 'enabled',
  'disabled', 'count', 'version', 'type', 'hint', 'length', 'strength', 'required', 'verified',
  'confirmed', 'prompt', 'dismissed', 'shown', 'seen', 'reminder', 'notification', 'notifications',
  'pref', 'prefs', 'preference', 'preferences', 'subscribed', 'optin', 'status', 'valid', 'visible',
  'is', 'has', 'show', 'should', 'last', 'lastlogin',
]);

const CREDENTIAL_TOKENS = new Set([
  'password', 'passwd', 'pwd', 'passcode', 'secret', 'secrets', 'token', 'tokens', 'jwt', 'bearer',
  'credential', 'credentials', 'apikey', 'accesstoken', 'refreshtoken', 'idtoken', 'authtoken',
  'sessiontoken', 'bearertoken', 'apitoken', 'usertoken', 'privatekey', 'secretkey', 'clientsecret',
  'encryptionkey', 'cvv', 'cvc', 'cvn', 'iban', 'pincode', 'mnemonic', 'seedphrase',
]);
const CREDENTIAL_PAIRS: Array<[string, string]> = [
  ['api', 'key'], ['private', 'key'], ['secret', 'key'], ['client', 'secret'], ['access', 'key'],
  ['encryption', 'key'], ['signing', 'key'], ['pin', 'code'], ['account', 'number'],
  ['bank', 'account'], ['card', 'number'], ['routing', 'number'], ['seed', 'phrase'],
  ['recovery', 'phrase'], ['card', 'cvv'],
];
const SESSION_COMPANIONS = new Set(['id', 'token', 'key', 'cookie', 'data', 'secret']);

const PII_TOKENS = new Set([
  'email', 'emailaddress', 'phone', 'phonenumber', 'mobilenumber', 'ssn', 'socialsecurity', 'dob',
  'birthdate', 'dateofbirth', 'birthday', 'creditcard', 'cardnumber', 'passport', 'passportno',
  'passportnumber', 'driverlicense', 'licensenumber', 'medical', 'health', 'biometric',
  'fingerprint', 'iban',
]);
const PII_PAIRS: Array<[string, string]> = [
  ['social', 'security'], ['credit', 'card'], ['card', 'number'], ['date', 'of'], ['birth', 'date'],
  ['phone', 'number'], ['mobile', 'number'], ['driver', 'license'], ['passport', 'number'],
  ['email', 'address'], ['home', 'address'], ['street', 'address'], ['billing', 'address'],
  ['shipping', 'address'], ['mailing', 'address'], ['postal', 'address'],
];
const ADDRESS_QUALIFIERS = new Set(['home', 'street', 'billing', 'shipping', 'mailing', 'postal', 'user', 'residential']);

function hasPair(tokens: string[], pairs: Array<[string, string]>): boolean {
  for (let i = 0; i < tokens.length - 1; i++) {
    if (pairs.some(([a, b]) => tokens[i] === a && tokens[i + 1] === b)) return true;
  }
  return false;
}

/** Does the name end in a credential word (`last_token`, `last_api_key`)? */
function endsWithCredential(tokens: string[]): boolean {
  const n = tokens.length;
  return CREDENTIAL_TOKENS.has(tokens[n - 1]) || hasPair(tokens.slice(-2), CREDENTIAL_PAIRS);
}

/**
 * `credentialName`: the caller looks for credentials, so `last` only marks metadata
 * (`last_login`, `last_token_refresh`) when the name does not end in a credential word.
 */
export function hasNonSecretQualifier(tokens: string[], credentialName = false): boolean {
  const credentialEnd = credentialName && endsWithCredential(tokens);
  return tokens.some(t => NON_SECRET_QUALIFIERS.has(t) && !(credentialEnd && t === 'last'));
}

/**
 * Does a storage key name (e.g. an AsyncStorage key) name credentials or secrets?
 * Matches whole words of the tokenised name, so `auth_token` and `authToken` match but
 * `tokenizer_enabled`, `bypass` and `token_expiry` do not.
 */
export function isCredentialKeyName(name: string): boolean {
  const tokens = tokenizeIdentifier(name);
  if (tokens.length === 0 || hasNonSecretQualifier(tokens, true)) return false;
  if (tokens.some(t => CREDENTIAL_TOKENS.has(t))) return true;
  if (hasPair(tokens, CREDENTIAL_PAIRS)) return true;
  if (tokens.includes('auth') || tokens.includes('authentication') || tokens.includes('authorization')) return true;
  if (tokens.includes('session') && (tokens.length === 1 || tokens.some(t => SESSION_COMPANIONS.has(t)))) return true;
  if (tokens.includes('pin') && (tokens.length === 1 || tokens.includes('code') || tokens.includes('user'))) return true;
  return false;
}

/** Does a storage key name personal data (email, phone, SSN, address, health ...)? */
export function isPiiKeyName(name: string): boolean {
  const tokens = tokenizeIdentifier(name);
  if (tokens.length === 0 || hasNonSecretQualifier(tokens)) return false;
  if (tokens.some(t => PII_TOKENS.has(t))) return true;
  if (hasPair(tokens, PII_PAIRS)) return true;
  if (tokens.includes('address') && (tokens.length === 1 || tokens.some(t => ADDRESS_QUALIFIERS.has(t)))) return true;
  return false;
}

/** Words that mark an identifier as carrying sensitive data (clipboard / file writes). */
export function hasSensitiveWord(tokens: string[]): boolean {
  if (tokens.length === 0) return false;
  if (tokens.some(t => CREDENTIAL_TOKENS.has(t) && !['iban', 'cvv', 'cvc', 'cvn'].includes(t))) return true;
  if (hasPair(tokens, CREDENTIAL_PAIRS)) return true;
  return tokens.includes('ssn') || tokens.includes('creditcard') || tokens.includes('otp');
}

// ---------------------------------------------------------------------------
// Provider patterns
// ---------------------------------------------------------------------------

export interface PatternRefinement {
  severity?: Severity;
  confidence?: Confidence;
  /** Replaces the pattern description */
  description?: string;
  suggestion?: string;
}

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
  /** Missing = high */
  confidence?: Confidence;
  /** Capture group holding the secret itself (default: the whole match) */
  valueGroup?: number;
  /** Loose patterns lose to any overlapping provider-specific match */
  generic?: boolean;
  /** Loose patterns only count when this matches the line (or the line before) */
  contextKeyword?: RegExp;
  /** Loose patterns only count when the value has at least this Shannon entropy */
  minEntropy?: number;
  /** Intended to ship in client apps; only restrict it in the provider console */
  publicByDesign?: boolean;
  suggestion?: string;
  /** Return 'skip' to drop the match, a refinement to adjust it, or null to keep it as is */
  refine?: (value: string, surrounding: string) => PatternRefinement | 'skip' | null;
}

function decodeBase64Url(part: string): string | null {
  try {
    return Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch {
    return null;
  }
}

const RESTRICT_IN_CONSOLE =
  'This identifier is designed to be embedded in client apps. Restrict it in the provider console (app/bundle ID, referrer or API restrictions) instead of removing it from the code.';

export const API_SECRET_PATTERNS: SecretPattern[] = [
  {
    // One pattern for every `AIza...` key (Firebase, Maps, Gemini ...)
    name: 'Google API Key',
    pattern: /\bAIza[0-9A-Za-z\-_]{35}(?![0-9A-Za-z_\-])/g,
    severity: Severity.LOW,
    confidence: 'medium',
    description: 'Google/Firebase API key detected (public by design for Firebase and Maps, restrict it in the console)',
    publicByDesign: true,
    suggestion: RESTRICT_IN_CONSOLE,
    refine: (_value, surrounding) =>
      // Gemini / Generative Language keys use the same AIza format but are NOT safe in client code
      /gemini|generativelanguage|generative-ai|googleai/i.test(surrounding)
        ? {
            severity: Severity.HIGH,
            confidence: 'high',
            description: 'Google API key used for Gemini / Generative Language detected',
            suggestion:
              'Gemini API keys must not ship in a client app. Proxy the calls through your backend and keep the key server-side.',
          }
        : null,
  },
  {
    name: 'AWS Access Key',
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    severity: Severity.HIGH,
    description: 'AWS Access Key ID detected',
  },
  {
    name: 'AWS Secret Key',
    pattern: /aws[_\-]?secret[_\-]?access[_\-]?key["']?\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    valueGroup: 1,
    severity: Severity.HIGH,
    description: 'AWS Secret Access Key detected',
  },
  {
    name: 'Google OAuth Client ID',
    pattern: /\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b/g,
    severity: Severity.LOW,
    confidence: 'medium',
    description: 'Google OAuth client ID detected (public by design, restrict it in the console)',
    publicByDesign: true,
    suggestion: RESTRICT_IN_CONSOLE,
  },
  {
    name: 'Stripe Live API Key',
    pattern: /\bsk_live_[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Stripe Live Secret Key detected',
  },
  {
    name: 'Stripe Restricted API Key',
    pattern: /\brk_live_[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Stripe Restricted Key detected',
  },
  {
    name: 'Stripe Test Secret Key',
    pattern: /\bsk_test_[0-9a-zA-Z]{24,}/g,
    severity: Severity.LOW,
    confidence: 'medium',
    description: 'Stripe test-mode secret key detected (cannot move real money, but still should not ship in code)',
  },
  {
    name: 'Stripe Publishable Key',
    pattern: /\bpk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
    severity: Severity.LOW,
    confidence: 'medium',
    description: 'Stripe publishable key detected (public by design, safe to expose)',
    publicByDesign: true,
    suggestion: 'Stripe publishable keys are safe to ship in client code. Load them from config for easier rotation; never ship the secret key.',
  },
  {
    name: 'Sentry DSN',
    pattern: /https:\/\/[0-9a-f]{16,32}(?::[0-9a-f]{32})?@[a-z0-9.\-]*sentry\.io\/\d+/g,
    severity: Severity.LOW,
    confidence: 'medium',
    description: 'Sentry DSN detected (public by design, restrict it with allowed domains / rate limits)',
    publicByDesign: true,
    suggestion: RESTRICT_IN_CONSOLE,
  },
  {
    // Covers ghp_, gho_, ghu_, ghs_ and ghr_
    name: 'GitHub Token',
    pattern: /\bgh[pousr]_[0-9a-zA-Z]{36}\b/g,
    severity: Severity.HIGH,
    description: 'GitHub token detected',
  },
  {
    name: 'GitHub Fine-grained Token',
    pattern: /\bgithub_pat_[0-9A-Za-z_]{82}\b/g,
    severity: Severity.HIGH,
    description: 'GitHub fine-grained personal access token detected',
  },
  {
    name: 'Slack Token',
    pattern: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Slack Token detected',
  },
  {
    name: 'Slack Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
    severity: Severity.MEDIUM,
    description: 'Slack Webhook URL detected',
  },
  {
    name: 'SendGrid API Key',
    pattern: /\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}(?![0-9A-Za-z_\-])/g,
    severity: Severity.HIGH,
    description: 'SendGrid API Key detected',
  },
  {
    name: 'DigitalOcean Token',
    pattern: /\bdop_v1_[a-f0-9]{64}\b/g,
    severity: Severity.HIGH,
    description: 'DigitalOcean Personal Access Token detected',
  },
  {
    name: 'Mailchimp API Key',
    pattern: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g,
    severity: Severity.HIGH,
    description: 'Mailchimp API Key detected',
  },
  {
    // PEM headers of every private key flavour. The key body must follow, so code that only
    // compares against or documents a header (e.g. a PEM parser) is not reported.
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?=(?:\s|\\[nr]|['"`+,])*[A-Za-z0-9+/]{30,})/g,
    severity: Severity.HIGH,
    description: 'Private key detected in source code',
  },
  {
    name: 'Twilio API Key',
    pattern: /\bSK[0-9a-f]{32}\b/g,
    severity: Severity.HIGH,
    description: 'Twilio API Key detected',
    contextKeyword: /twilio|api[_\-]?(?:key|sid)|account[_\-]?sid|auth[_\-]?token/i,
    minEntropy: 3.0,
  },
  {
    name: 'Mailgun API Key',
    pattern: /(?<![A-Za-z0-9_\-])key-[0-9a-f]{32}\b/g,
    severity: Severity.HIGH,
    description: 'Mailgun API Key detected',
    contextKeyword: /mailgun|api[_\-]?key|apikey|secret|token|auth/i,
    minEntropy: 3.0,
  },
  {
    name: 'Heroku API Key',
    pattern: /\bheroku[\w .\-]{0,30}?(?:api[_\-]?key|token|auth\w*|key)["']?\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi,
    valueGroup: 1,
    severity: Severity.HIGH,
    description: 'Heroku API Key detected',
    minEntropy: 3.0,
  },
  {
    name: 'JWT Token',
    pattern: /\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}/g,
    severity: Severity.MEDIUM,
    confidence: 'medium',
    description: 'JWT detected in source (could be a sample token, review it)',
    refine: value => {
      const [header, payload] = value.split('.');
      let h: any;
      let p: any;
      try {
        h = JSON.parse(decodeBase64Url(header) ?? '');
        p = JSON.parse(decodeBase64Url(payload) ?? '');
      } catch {
        return 'skip';
      }
      if (!h || typeof h !== 'object' || !('alg' in h) || !p || typeof p !== 'object') return 'skip';
      // The jwt.io sample token that gets pasted into every tutorial
      if (p.sub === '1234567890' && p.name === 'John Doe') return 'skip';
      if (p.role === 'anon') {
        return {
          severity: Severity.LOW,
          description: 'Supabase-style anon JWT detected (public by design, protect data with row level security)',
          suggestion: 'Anon keys are meant for clients. Make sure row level security is enabled and never ship the service_role key.',
        };
      }
      return null;
    },
  },
  {
    name: 'Generic API Key',
    pattern: /api[_\-]?key["']?\s*[=:]\s*['"`]([0-9a-zA-Z\-_]{20,})['"`]/gi,
    valueGroup: 1,
    generic: true,
    severity: Severity.MEDIUM,
    confidence: 'medium',
    description: 'Generic API key pattern detected',
    minEntropy: 3.5,
  },
  {
    name: 'Generic Secret',
    pattern: /secret["']?\s*[=:]\s*['"`]([0-9a-zA-Z\-_!@#$%^&*()+=]{16,})['"`]/gi,
    valueGroup: 1,
    generic: true,
    severity: Severity.MEDIUM,
    confidence: 'medium',
    description: 'Generic secret pattern detected',
    minEntropy: 3.5,
  },
  {
    // The 20+ char token class rejects prose and `${...}` placeholders; keyword context and entropy do the rest
    name: 'Bearer Token',
    pattern: /\bBearer\s+([A-Za-z0-9\-._~+/]{20,}={0,2})/gi,
    valueGroup: 1,
    generic: true,
    severity: Severity.MEDIUM,
    confidence: 'medium',
    description: 'Bearer token detected',
    contextKeyword: /authori[sz]ation|\bauth|token|jwt|api[_\-]?key/i,
    minEntropy: 3.5,
  },
  {
    name: 'Basic Auth',
    pattern: /\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})/gi,
    valueGroup: 1,
    generic: true,
    severity: Severity.MEDIUM,
    confidence: 'medium',
    description: 'Basic Authentication credentials detected',
    contextKeyword: /authori[sz]ation|\bauth|credential/i,
    minEntropy: 3.0,
    refine: value => {
      // Real Basic credentials decode to "user:password"
      const decoded = decodeBase64Url(value);
      return decoded && /^[\x20-\x7e]+:[\x20-\x7e]+$/.test(decoded) ? null : 'skip';
    },
  },
];
