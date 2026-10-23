import { Severity } from '../types/findings.js';

/** Split identifiers/strings into upper-case tokens on non-alphanumerics and camelCase boundaries. */
export function tokenizeName(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map(t => t.toUpperCase());
}

export function hasAdjacentTokens(tokens: string[], a: string, b: string): boolean {
  for (let i = 0; i < tokens.length - 1; i++) {
    if (tokens[i] === a && tokens[i + 1] === b) return true;
  }
  return false;
}

const BENIGN_SUFFIXES = new Set([
  'URL', 'URI', 'ENDPOINT', 'PATH', 'LENGTH', 'ENABLED', 'FLAG', 'NAME', 'LABEL', 'REGEX', 'PATTERN', 'TIMEOUT',
]);

/**
 * Severity for a variable/config key whose name says it holds a secret, or null
 * when it does not. Names are tokenised, so `SECRETARY` or `PASSWORD_MIN_LENGTH`
 * do not match, and `PUBLIC`/`PUBLISHABLE`/`ANON` names are never secrets.
 */
export function classifySecretName(name: string): Severity | null {
  const t = tokenizeName(name);
  if (t.length === 0) return null;
  if (t.some(x => x === 'PUBLISHABLE' || x === 'ANON' || x === 'PUBLIC')) return null;
  if (BENIGN_SUFFIXES.has(t[t.length - 1])) return null;

  const high =
    t.includes('SECRET') ||
    t.includes('PASSWORD') ||
    t.includes('PASSWD') ||
    hasAdjacentTokens(t, 'PRIVATE', 'KEY') ||
    hasAdjacentTokens(t, 'SERVICE', 'ROLE');
  if (high) return Severity.HIGH;

  const medium =
    t.includes('PRIVATE') ||
    hasAdjacentTokens(t, 'ADMIN', 'KEY') ||
    hasAdjacentTokens(t, 'MASTER', 'KEY') ||
    hasAdjacentTokens(t, 'SIGNING', 'KEY') ||
    hasAdjacentTokens(t, 'ENCRYPTION', 'KEY');
  return medium ? Severity.MEDIUM : null;
}
