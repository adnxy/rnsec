export function extractSnippet(content: string, line: number, contextLines: number = 2): string {
  const lines = content.split('\n');
  const start = Math.max(0, line - contextLines - 1);
  const end = Math.min(lines.length, line + contextLines);
  return lines.slice(start, end).join('\n');
}

export function containsSensitiveKeyword(text: string): boolean {
  const keywords = ['token', 'password', 'auth', 'secret', 'api_key', 'apikey', 'credentials'];
  const lowerText = text.toLowerCase();
  return keywords.some(keyword => lowerText.includes(keyword));
}

/**
 * Checks if a value is likely just an identifier/string constant, not a secret
 * These patterns indicate non-secret values:
 * - Kebab-case identifiers (change-password, view-subscription-details)
 * - Dot notation paths (screens.accountSettings.settings)
 * - Colon-separated paths (persist:tickets)
 * - Simple lowercase/camelCase words without random characters
 */
export function isLikelyIdentifier(value: string): boolean {
  // Empty or very short strings are not secrets
  if (!value || value.length < 4) {
    return true;
  }
  
  // Kebab-case identifiers (edit-profile, change-password)
  if (/^[a-z][a-z0-9]*(-[a-z0-9]+)+$/.test(value)) {
    return true;
  }
  
  // Dot notation paths (screens.accountSettings.settings.confirmationEmailError)
  if (/^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)+$/.test(value)) {
    return true;
  }
  
  // Colon-separated paths (persist:tickets, store:auth)
  if (/^[a-z]+:[a-z]+$/.test(value)) {
    return true;
  }
  
  // Simple words without special chars or numbers (just plain text)
  if (/^[a-z][a-z\s]+$/i.test(value)) {
    return true;
  }
  
  // CamelCase or snake_case identifiers (updateProfile, user_settings)
  if (/^[a-z][a-z0-9_]*$/i.test(value) && !/\d{3,}/.test(value)) {
    return true;
  }
  
  // All caps constants (VIEW_PROFILE, EDIT_USER) without random looking parts
  if (/^[A-Z][A-Z_]*$/.test(value) && !/[0-9]{3,}/.test(value)) {
    return true;
  }
  
  return false;
}

/**
 * Calculates Shannon entropy to detect random-looking strings
 * Higher entropy = more random = more likely to be a secret
 */
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

/**
 * Improved secret detection - checks for actual API keys, tokens, and secrets
 * Returns true only for values that look like real secrets, not identifiers
 */
export function looksLikeSecret(value: string): boolean {
  // Skip obvious non-secrets
  if (isLikelyIdentifier(value)) {
    return false;
  }
  
  // JWT tokens (three base64 parts separated by dots)
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    return true;
  }
  
  // AWS Access Key ID format
  if (/^AKIA[0-9A-Z]{16}$/.test(value)) {
    return true;
  }
  
  // AWS Secret Key format (40 chars, base64-like)
  if (/^[A-Za-z0-9/+=]{40}$/.test(value)) {
    return true;
  }
  
  // Stripe API keys
  if (/^sk_(test|live)_[A-Za-z0-9]{24,}$/.test(value)) {
    return true;
  }
  
  // Generic API key patterns (mixed case + numbers, no clear word pattern)
  if (/^[A-Za-z0-9]{32,}$/.test(value) && calculateEntropy(value) > 4.0) {
    return true;
  }
  
  // Base64 encoded secrets (long, high entropy)
  if (value.length > 40 && /^[A-Za-z0-9+/=_-]+$/.test(value) && calculateEntropy(value) > 4.5) {
    return true;
  }
  
  // Hex-encoded secrets (32+ hex chars)
  if (/^[a-fA-F0-9]{32,}$/.test(value)) {
    return true;
  }
  
  // UUID format (not necessarily a secret, but could be sensitive)
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
    return true;
  }
  
  // GitHub/GitLab tokens
  if (/^gh[pousr]_[A-Za-z0-9]{36,}$/.test(value)) {
    return true;
  }
  
  // Generic token pattern (prefix + underscore + random chars)
  if (/^[a-z]{2,}_[A-Za-z0-9_-]{20,}$/.test(value)) {
    return true;
  }
  
  return false;
}

/**
 * Enhanced check for variable names that might contain secrets
 * More strict than containsSensitiveKeyword
 */
export function isLikelySensitiveVariable(name: string, value: string): boolean {
  // If the value is clearly just an identifier, it's not sensitive regardless of name
  if (isLikelyIdentifier(value)) {
    return false;
  }
  
  const lowerName = name.toLowerCase();
  
  // Direct secret-related names with actual secret-like values
  const directSecretNames = ['apikey', 'api_key', 'secretkey', 'secret_key', 'privatekey', 'private_key'];
  if (directSecretNames.some(keyword => lowerName.includes(keyword)) && looksLikeSecret(value)) {
    return true;
  }
  
  // Token names with token-like values
  if (lowerName.includes('token') && (value.length > 20 || looksLikeSecret(value))) {
    return true;
  }
  
  // Password variables with non-trivial values
  if (lowerName.includes('password') && value.length > 12 && !isLikelyIdentifier(value)) {
    return true;
  }
  
  // Auth/credential related with suspicious values
  if ((lowerName.includes('auth') || lowerName.includes('credential')) && looksLikeSecret(value)) {
    return true;
  }
  
  return false;
}

export function getLineNumber(content: string, position: number): number {
  const lines = content.substring(0, position).split('\n');
  return lines.length;
}

