import {
  ALL_SENSITIVE_KEYWORDS,
  SECRET_PATTERNS,
  IDENTIFIER_PATTERNS,
  ENTROPY_THRESHOLDS,
} from "./sensitiveDataPatterns.js";

let indexedContent: string | undefined;
let lineStarts: number[] = [];

/** Offsets where each line begins; cached for the most recent content, since callers query one file many times. */
function getLineStarts(content: string): number[] {
  if (content !== indexedContent) {
    const starts = [0];
    for (let i = content.indexOf("\n"); i !== -1; i = content.indexOf("\n", i + 1)) {
      starts.push(i + 1);
    }
    lineStarts = starts;
    indexedContent = content;
  }
  return lineStarts;
}

export function extractSnippet(
  content: string,
  line: number,
  contextLines: number = 2
): string {
  const starts = getLineStarts(content);
  const start = Math.max(0, line - contextLines - 1);
  const end = Math.min(starts.length, line + contextLines);
  if (start >= end) return "";
  const to = end < starts.length ? starts[end] - 1 : content.length;
  return content.substring(starts[start], to);
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

  // Filter out common false positives
  const lowerValue = value.toLowerCase();
  
  // Common character sets and alphabets
  const commonPatterns = [
    /^[a-z]+$/i,                           // Just letters (alphabet, etc)
    /^[0-9]+$/,                            // Just numbers
    /^[a-f0-9]+$/i,                        // Hex characters only
    /^[a-z0-9]{1,10}$/i,                   // Very short alphanumeric
    /^(abc|xyz|test|demo|sample)/i,        // Test patterns
    /^(\w)\1{3,}/,                         // Repeated characters (aaaa, 1111)
    /^(01234|12345|abcde|qwerty)/i,        // Sequential patterns
  ];

  // Check for common non-secret patterns
  if (commonPatterns.some(pattern => pattern.test(value))) {
    return false;
  }

  // Common variable/constant names that aren't secrets
  const commonNames = [
    'characters', 'alphabet', 'digits', 'letters', 'charset',
    'config', 'options', 'settings', 'constants', 'defaults'
  ];
  
  if (value.length < 20 && commonNames.some(name => lowerValue.includes(name))) {
    return false;
  }

  // Check for actual secret patterns (specific formats)
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

  if (SECRET_PATTERNS.GITHUB_TOKEN.test(value)) {
    return true;
  }

  if (SECRET_PATTERNS.GENERIC_TOKEN.test(value)) {
    return true;
  }

  // Only flag as generic API key if high entropy AND long enough
  if (
    value.length >= 32 &&
    SECRET_PATTERNS.GENERIC_API_KEY.test(value) &&
    calculateEntropy(value) > ENTROPY_THRESHOLDS.GENERIC_KEY
  ) {
    return true;
  }

  // Only flag as base64 secret if very long and high entropy
  if (
    value.length > 40 &&
    SECRET_PATTERNS.BASE64_SECRET.test(value) &&
    calculateEntropy(value) > ENTROPY_THRESHOLDS.BASE64_SECRET
  ) {
    return true;
  }

  // Hex secrets must be long enough to be real secrets (not just colors, etc)
  if (value.length >= 40 && SECRET_PATTERNS.HEX_SECRET.test(value)) {
    return true;
  }

  // UUIDs are typically not secrets by themselves
  // if (SECRET_PATTERNS.UUID.test(value)) {
  //   return true;
  // }

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
  const lowerValue = value.toLowerCase();

  // Exclude common non-sensitive variable names
  const nonSensitiveNames = [
    'characters', 'charset', 'alphabet', 'letters', 'digits',
    'config', 'options', 'settings', 'constants', 'defaults',
    'format', 'pattern', 'template', 'schema', 'allowed'
  ];

  if (nonSensitiveNames.some(name => lowerName.includes(name))) {
    return false;
  }

  // Exclude form field names and UI state variables
  const isFormFieldPattern = 
    lowerName.includes("input") ||
    lowerName.includes("field") ||
    lowerName.includes("form") ||
    lowerName.includes("state") ||
    lowerName.includes("value") ||
    lowerName === "password" ||        // Just "password" is often a form field
    lowerName === "username" ||        // Just "username" is often a form field
    lowerName === "email" ||           // Just "email" is often a form field
    lowerName === "token" ||           // Just "token" might be a variable name
    lowerName.includes("ref") ||       // React refs
    lowerName.includes("current") ||   // Current values in forms
    lowerName.includes("new") ||       // New password fields
    lowerName.includes("old") ||       // Old password fields
    lowerName.includes("confirm") ||   // Password confirmation
    lowerName.includes("repeat");      // Password repeat
  
  if (isFormFieldPattern && value.length < 50) {
    // Short values in form contexts are likely not secrets
    return false;
  }

  // Exclude error messages, UI text, validation messages
  const isErrorOrValidationMessage = 
    lowerName.includes("error") ||
    lowerName.includes("message") ||
    lowerName.includes("label") ||
    lowerName.includes("text") ||
    lowerName.includes("title") ||
    lowerName.includes("description") ||
    lowerName.includes("placeholder") ||
    lowerName.includes("hint") ||
    lowerName.includes("help") ||
    lowerName.includes("tooltip") ||
    lowerValue.includes("must be") ||
    lowerValue.includes("required") ||
    lowerValue.includes("invalid") ||
    lowerValue.includes("please") ||
    lowerValue.includes("enter") ||
    lowerValue.includes("at least") ||
    lowerValue.includes("characters long") ||
    lowerValue.includes("does not match") ||
    lowerValue.includes("went wrong") ||
    lowerValue.includes("try again") ||
    lowerValue.includes("cannot") ||
    lowerValue.includes("should") ||
    value.endsWith(".") ||
    value.endsWith("!") ||
    value.endsWith("?");

  if (isErrorOrValidationMessage) {
    return false;
  }

  // Only flag if BOTH name AND value look sensitive
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

  // Tokens must be long AND look like actual tokens
  if (
    lowerName.includes("token") &&
    value.length > 32 &&
    looksLikeSecret(value)
  ) {
    return true;
  }

  // Passwords must be long, not identifiers, and look like secrets
  if (
    lowerName.includes("password") &&
    value.length > 16 &&
    !isLikelyIdentifier(value) &&
    looksLikeSecret(value)
  ) {
    return true;
  }

  // Auth credentials must actually look like secrets
  if (
    (lowerName.includes("auth") || lowerName.includes("credential")) &&
    value.length > 20 &&
    looksLikeSecret(value)
  ) {
    return true;
  }

  return false;
}

/** 1-based line of `position`: 1 + number of newlines strictly before it (binary search over cached line starts). */
export function getLineNumber(content: string, position: number): number {
  if (!(position > 0)) return 1;
  const starts = getLineStarts(content);
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= position) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/**
 * Checks if a code line/snippet is in a form validation or UI context
 * These contexts often have password/username variables that are NOT credentials
 */
export function isInFormValidationContext(lineContext: string): boolean {
  const lowerContext = lineContext.toLowerCase();
  
  return (
    // React state and hooks
    lowerContext.includes('const [') ||
    lowerContext.includes('usestate') ||
    lowerContext.includes('setpassword') ||
    lowerContext.includes('setusername') ||
    lowerContext.includes('setemail') ||
    lowerContext.includes('settoken') ||
    
    // Form libraries
    lowerContext.includes('formik') ||
    lowerContext.includes('react-hook-form') ||
    lowerContext.includes('register(') ||
    lowerContext.includes('useform') ||
    
    // Form elements and UI
    lowerContext.includes('placeholder') ||
    lowerContext.includes('label') ||
    lowerContext.includes('input') ||
    lowerContext.includes('textinput') ||
    lowerContext.includes('field') ||
    
    // Validation and errors
    lowerContext.includes('error') ||
    lowerContext.includes('validation') ||
    lowerContext.includes('validate') ||
    lowerContext.includes('formdata') ||
    lowerContext.includes('formstate') ||
    lowerContext.includes('formvalues') ||
    
    // Event handlers
    lowerContext.includes('handlechange') ||
    lowerContext.includes('onchange') ||
    lowerContext.includes('onsubmit') ||
    lowerContext.includes('handlesubmit') ||
    
    // Props and state
    lowerContext.includes('props.') ||
    lowerContext.includes('state.') ||
    
    // Comments
    lowerContext.trim().startsWith('//') ||
    lowerContext.trim().startsWith('/*') ||
    lowerContext.trim().startsWith('*')
  );
}

/**
 * Detects if code is within a debug/development context
 * Checks for common patterns like __DEV__, NODE_ENV checks, DEBUG flags, etc.
 */
export function isInDebugContext(content: string, snippet?: string, filePath?: string): boolean {
  // Check file path for debug indicators
  if (filePath) {
    const lowerPath = filePath.toLowerCase();
    if (
      // Debug directories and files
      lowerPath.includes('/debug/') ||
      lowerPath.includes('/debugoptimized/') ||
      lowerPath.includes('__debug') ||
      lowerPath.includes('.debug.') ||
      lowerPath.includes('/dev/') ||
      lowerPath.includes('.dev.') ||
      
      // Test files and directories
      lowerPath.includes('/__tests__/') ||
      lowerPath.includes('/__mocks__/') ||
      lowerPath.includes('/test/') ||
      lowerPath.includes('/tests/') ||
      lowerPath.includes('.test.') ||
      lowerPath.includes('.spec.') ||
      lowerPath.includes('jestsetup') ||
      lowerPath.includes('jest.setup') ||
      lowerPath.includes('jest.config') ||
      lowerPath.includes('setuptest') ||
      
      // Config and setup files
      lowerPath.includes('storybook') ||
      lowerPath.includes('.storybook') ||
      
      // Third-party and vendor
      lowerPath.includes('node_modules') ||
      lowerPath.includes('/vendor/') ||
      lowerPath.includes('/assets/') ||
      lowerPath.includes('/android/app/src/main/assets/') ||
      lowerPath.includes('/ios/build/')
    ) {
      return true;
    }
  }

  // Combine content and snippet for analysis
  const codeToAnalyze = snippet ? `${content}\n${snippet}` : content;
  const lines = codeToAnalyze.split('\n');
  
  // Look for debug context patterns in surrounding code
  const debugPatterns = [
    // __DEV__ checks
    /if\s*\(\s*__DEV__\s*\)/,
    /\?\s*__DEV__\s*[?:]/,
    /__DEV__\s*&&/,
    /&&\s*__DEV__/,
    
    // NODE_ENV checks
    /process\.env\.NODE_ENV\s*===?\s*['"]development['"]/,
    /process\.env\.NODE_ENV\s*!==?\s*['"]production['"]/,
    /NODE_ENV\s*===?\s*['"]development['"]/,
    /NODE_ENV\s*!==?\s*['"]production['"]/,
    
    // DEBUG flag checks
    /if\s*\(\s*DEBUG\s*\)/,
    /\?\s*DEBUG\s*[?:]/,
    /DEBUG\s*&&/,
    /&&\s*DEBUG/,
    /process\.env\.DEBUG/,
    
    // Development mode checks
    /if\s*\(\s*['"]development['"]\s*===?\s*process\.env\.NODE_ENV\s*\)/,
    /isDevelopment\s*&&/,
    /isDebug\s*&&/,
    /\.development\s*\?/,
    
    // React Native __DEV__ global
    /typeof\s+__DEV__\s*!==?\s*['"]undefined['"]\s*&&\s*__DEV__/,
    
    // Console/logging that only runs in dev
    /if\s*\(\s*__DEV__\s*\)\s*\{?\s*console\./,
    
    // Expo development mode
    /Constants\.manifest\.?packagerOpts\.?dev/,
    /expo-constants.*development/,
    
    // webpack/bundler dev mode
    /webpack_require.*development/,
    /WEBPACK_DEV/,
  ];

  for (const line of lines) {
    for (const pattern of debugPatterns) {
      if (pattern.test(line)) {
        return true;
      }
    }
  }

  // Check for debug-specific imports or requires
  const debugImportPatterns = [
    /require\(['"].*\.debug['"]\)/,
    /require\(['"].*\/debug['"]\)/,
    /import.*from\s+['"].*\.debug['"]/,
    /import.*from\s+['"].*\/debug['"]/,
  ];

  for (const pattern of debugImportPatterns) {
    if (pattern.test(codeToAnalyze)) {
      return true;
    }
  }

  return false;
}
