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

import { Severity } from '../types/findings.js';

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
}

export const API_SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'Firebase API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: Severity.HIGH,
    description: 'Firebase API key detected',
  },
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: Severity.HIGH,
    description: 'AWS Access Key ID detected',
  },
  {
    name: 'AWS Secret Key',
    pattern: /aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:][\s]*['"]?[A-Za-z0-9/+=]{40}['"]?/gi,
    severity: Severity.HIGH,
    description: 'AWS Secret Access Key detected',
  },
  {
    name: 'Google Cloud API Key',
    pattern: /AIza[0-9A-Za-z\\-_]{35}/g,
    severity: Severity.HIGH,
    description: 'Google Cloud API key detected',
  },
  {
    name: 'Google OAuth',
    pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    severity: Severity.MEDIUM,
    description: 'Google OAuth Client ID detected',
  },
  {
    name: 'Stripe Live API Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Stripe Live Secret Key detected',
  },
  {
    name: 'Stripe Restricted API Key',
    pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Stripe Restricted Key detected',
  },
  {
    name: 'Stripe Publishable Key',
    pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
    severity: Severity.LOW,
    description: 'Stripe Publishable Key detected (less sensitive but should be in env)',
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[0-9a-zA-Z]{36}/g,
    severity: Severity.HIGH,
    description: 'GitHub Personal Access Token detected',
  },
  {
    name: 'GitHub OAuth',
    pattern: /gho_[0-9a-zA-Z]{36}/g,
    severity: Severity.HIGH,
    description: 'GitHub OAuth Token detected',
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}/g,
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
    name: 'Twilio API Key',
    pattern: /SK[0-9a-fA-F]{32}/g,
    severity: Severity.HIGH,
    description: 'Twilio API Key detected',
  },
  {
    name: 'SendGrid API Key',
    pattern: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g,
    severity: Severity.HIGH,
    description: 'SendGrid API Key detected',
  },
  {
    name: 'Mailgun API Key',
    pattern: /key-[0-9a-zA-Z]{32}/g,
    severity: Severity.HIGH,
    description: 'Mailgun API Key detected',
  },
  {
    name: 'Mailchimp API Key',
    pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    severity: Severity.HIGH,
    description: 'Mailchimp API Key detected',
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g,
    severity: Severity.HIGH,
    description: 'Private Key detected in source code',
  },
  {
    name: 'RSA Private Key',
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    severity: Severity.HIGH,
    description: 'RSA Private Key detected',
  },
  {
    name: 'SSH Key',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
    severity: Severity.HIGH,
    description: 'SSH Private Key detected',
  },
  {
    name: 'PGP Private Key',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    severity: Severity.HIGH,
    description: 'PGP Private Key detected',
  },
  {
    name: 'Heroku API Key',
    pattern: /[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    severity: Severity.HIGH,
    description: 'Heroku API Key detected',
  },
  {
    name: 'DigitalOcean Token',
    pattern: /dop_v1_[a-f0-9]{64}/g,
    severity: Severity.HIGH,
    description: 'DigitalOcean Personal Access Token detected',
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*/g,
    severity: Severity.MEDIUM,
    description: 'JWT Token detected (could be test/example or real)',
  },
  {
    name: 'Generic API Key',
    pattern: /[aA][pP][iI][_\-]?[kK][eE][yY][\s]*[=:][\s]*['"][0-9a-zA-Z\-_]{20,}['"]/g,
    severity: Severity.MEDIUM,
    description: 'Generic API key pattern detected',
  },
  {
    name: 'Generic Secret',
    pattern: /[sS][eE][cC][rR][eE][tT][\s]*[=:][\s]*['"][0-9a-zA-Z\-_!@#$%^&*()+=]{16,}['"]/g,
    severity: Severity.MEDIUM,
    description: 'Generic secret pattern detected',
  },
  {
    name: 'Bearer Token',
    pattern: /[bB]earer[\s]+[a-zA-Z0-9\-._~+/]+=*/g,
    severity: Severity.MEDIUM,
    description: 'Bearer token detected',
  },
  {
    name: 'Basic Auth',
    pattern: /[bB]asic[\s]+[A-Za-z0-9+/=]{20,}/g,
    severity: Severity.MEDIUM,
    description: 'Basic Authentication credentials detected',
  },
];

