import {
  ALL_SENSITIVE_KEYWORDS,
  SECRET_PATTERNS,
  IDENTIFIER_PATTERNS,
  ENTROPY_THRESHOLDS,
} from "./sensitiveDataPatterns.js";

export function extractSnippet(
  content: string,
  line: number,
  contextLines: number = 2
): string {
  const lines = content.split("\n");
  const start = Math.max(0, line - contextLines - 1);
  const end = Math.min(lines.length, line + contextLines);
  return lines.slice(start, end).join("\n");
}

export function containsSensitiveKeyword(text: string): boolean {
  const lowerText = text.toLowerCase();

  return ALL_SENSITIVE_KEYWORDS.some((keyword) => {
    if (keyword.startsWith(".")) {
      return lowerText.includes(keyword);
    }

    const pattern = new RegExp(
      `(^|[^a-z])${keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}($|[^a-z])`,
      "i"
    );
    return pattern.test(text);
  });
}

export function isLikelyIdentifier(value: string): boolean {
  if (!value || value.length < 4) {
    return true;
  }

  if (IDENTIFIER_PATTERNS.KEBAB_CASE.test(value)) {
    return true;
  }

  if (IDENTIFIER_PATTERNS.DOT_NOTATION.test(value)) {
    return true;
  }

  if (IDENTIFIER_PATTERNS.COLON_SEPARATED.test(value)) {
    return true;
  }

  if (IDENTIFIER_PATTERNS.SIMPLE_WORDS.test(value)) {
    return true;
  }

  if (
    IDENTIFIER_PATTERNS.CAMEL_SNAKE_CASE.test(value) &&
    !/\d{3,}/.test(value)
  ) {
    return true;
  }

  if (IDENTIFIER_PATTERNS.CONSTANT_CASE.test(value) && !/[0-9]{3,}/.test(value)) {
    return true;
  }

  return false;
}

function calculateEntropy(str: string): number {
  const len = str.length;
  const frequencies: Record<string, number> = {};

  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in frequencies) {
    const probability = frequencies[char] / len;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

export function looksLikeSecret(value: string): boolean {
  if (isLikelyIdentifier(value)) {
    return false;
  }

  if (SECRET_PATTERNS.JWT.test(value)) {
    return true;
  }

  if (SECRET_PATTERNS.AWS_ACCESS_KEY.test(value)) {
    return true;
  }

  if (SECRET_PATTERNS.AWS_SECRET_KEY.test(value)) {
    return true;
  }

  if (SECRET_PATTERNS.STRIPE_KEY.test(value)) {
    return true;
  }

  if (
    SECRET_PATTERNS.GENERIC_API_KEY.test(value) &&
    calculateEntropy(value) > ENTROPY_THRESHOLDS.GENERIC_KEY
  ) {
    return true;
  }

  if (
    value.length > 40 &&
    SECRET_PATTERNS.BASE64_SECRET.test(value) &&
    calculateEntropy(value) > ENTROPY_THRESHOLDS.BASE64_SECRET
  ) {
    return true;
  }

  if (SECRET_PATTERNS.HEX_SECRET.test(value)) {
    return true;
  }

  if (SECRET_PATTERNS.UUID.test(value)) {
    return true;
  }

  if (SECRET_PATTERNS.GITHUB_TOKEN.test(value)) {
    return true;
  }

  if (SECRET_PATTERNS.GENERIC_TOKEN.test(value)) {
    return true;
  }

  return false;
}

export function isLikelySensitiveVariable(
  name: string,
  value: string
): boolean {
  if (isLikelyIdentifier(value)) {
    return false;
  }

  const lowerName = name.toLowerCase();

  const directSecretNames = [
    "apikey",
    "api_key",
    "secretkey",
    "secret_key",
    "privatekey",
    "private_key",
  ];
  if (
    directSecretNames.some((keyword) => lowerName.includes(keyword)) &&
    looksLikeSecret(value)
  ) {
    return true;
  }

  if (
    lowerName.includes("token") &&
    (value.length > 20 || looksLikeSecret(value))
  ) {
    return true;
  }

  if (
    lowerName.includes("password") &&
    value.length > 12 &&
    !isLikelyIdentifier(value)
  ) {
    return true;
  }

  if (
    (lowerName.includes("auth") || lowerName.includes("credential")) &&
    looksLikeSecret(value)
  ) {
    return true;
  }

  return false;
}

export function getLineNumber(content: string, position: number): number {
  const lines = content.substring(0, position).split("\n");
  return lines.length;
}
