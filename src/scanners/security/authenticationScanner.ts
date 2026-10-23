import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { identifierHasTerm, identifierEndsWithTerm, identifierTokens, blankComments } from '../../utils/identifierUtils.js';

// Names of values that must be unpredictable. Matched as whole identifier words, anywhere in the name.
const RANDOM_SENSITIVE_TERMS: ReadonlySet<string> = new Set([
  'token', 'accesstoken', 'refreshtoken', 'csrf', 'xsrf', 'nonce', 'otp', 'salt', 'session', 'sessionid',
  'secret', 'password', 'passwd', 'passcode', 'pwd', 'uuid', 'guid',
  'apikey', 'secretkey', 'privatekey', 'encryptionkey', 'cryptokey', 'signingkey', 'masterkey', 'authkey',
  'verificationcode', 'resetcode', 'securitycode', 'authcode', 'otpcode', 'smscode', 'activationcode', 'confirmationcode',
]);

// `tokenExpiresAt = Date.now() + ttl`, `otpDelay = Math.random() * 500`: timing/size values, not secrets.
const NON_SECRET_TERMS: ReadonlySet<string> = new Set([
  'time', 'timestamp', 'at', 'start', 'end', 'expires', 'expiry', 'expiration', 'expire', 'date', 'duration',
  'delay', 'ms', 'interval', 'timeout', 'ttl', 'count', 'length', 'size', 'index', 'last', 'created', 'updated',
]);

const UUID_TERMS: ReadonlySet<string> = new Set(['uuid', 'guid']);
const GENERATOR_VERBS: ReadonlySet<string> = new Set(['generate', 'gen', 'create', 'make', 'new', 'random', 'build', 'next']);
const GENERIC_SINK_NAMES = new Set([
  'r', 'res', 'result', 'out', 'output', 'str', 's', 'value', 'val', 'ret', 'id', 'chars', 'buf', 'buffer',
  'text', 'rand', 'random', 'randomstring', 'string', 'acc', 'code', 'bytes', 'arr',
]);

/** `generateToken`, `createSessionId`, `uuid`: a function whose job is to mint a secret value. */
function isRandomGeneratorName(name: string): boolean {
  if (identifierHasTerm(name, UUID_TERMS)) return true;
  return identifierHasTerm(name, GENERATOR_VERBS) && isSecurityRandomName(name);
}

function isSecurityRandomName(name: string | null): boolean {
  return !!name && identifierHasTerm(name, RANDOM_SENSITIVE_TERMS) && !identifierHasTerm(name, NON_SECRET_TERMS);
}

function targetName(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' && !node.computed) return node.property?.name ?? null;
  if (node.type === 'StringLiteral') return node.value;
  return null;
}

function calleeName(callee: any): string | null {
  if (callee?.type === 'Identifier') return callee.name;
  if (callee?.type === 'MemberExpression' && !callee.computed) return callee.property?.name ?? null;
  return null;
}

function functionName(fnPath: any): string | null {
  const node = fnPath.node;
  if (node.id?.name) return node.id.name;
  if (node.key?.name) return node.key.name;
  const parent = fnPath.parent;
  if (parent?.type === 'VariableDeclarator') return targetName(parent.id);
  if (parent?.type === 'ObjectProperty') return targetName(parent.key);
  if (parent?.type === 'AssignmentExpression') return targetName(parent.left);
  return null;
}

/**
 * Follow where a random value ends up: through arithmetic, string building and method chains
 * (`Math.random().toString(36).slice(2)`, `'t-' + Math.random()`) until it is stored in a variable,
 * property, argument or returned. Returns the receiving name when it is security-related.
 */
function randomSinkName(start: any): string | null {
  let child: any = start;
  let path: any = start.parentPath;

  while (path) {
    const node = path.node;
    switch (node.type) {
      case 'VariableDeclarator':
        return node.init === child.node ? targetName(node.id) : null;
      case 'AssignmentExpression':
        return node.right === child.node ? targetName(node.left) : null;
      case 'ObjectProperty':
        return node.value === child.node ? targetName(node.key) : null;
      case 'ReturnStatement': {
        const fn = path.getFunctionParent();
        return fn ? functionName(fn) : null;
      }
      case 'ArrowFunctionExpression':
        // expression-bodied arrow: `const makeToken = () => Math.random()...`
        return node.body === child.node ? functionName(path) : null;
      case 'CallExpression': {
        if (node.callee !== child.node) {
          // used as an argument: `setToken(Math.random())`, `storage.set('token', ...)`
          const callee = calleeName(node.callee);
          if (isSecurityRandomName(callee)) return callee;
          const label = node.arguments[0];
          if (label?.type === 'StringLiteral' && label !== child.node && isSecurityRandomName(label.value)) return label.value;
        }
        break;
      }
      case 'MemberExpression':
      case 'OptionalMemberExpression':
      case 'BinaryExpression':
      case 'LogicalExpression':
      case 'UnaryExpression':
      case 'ConditionalExpression':
      case 'TemplateLiteral':
      case 'ParenthesizedExpression':
      case 'TSAsExpression':
      case 'TSNonNullExpression':
      case 'AwaitExpression':
      case 'SequenceExpression':
      case 'ArrayExpression':
        break;
      default:
        return null; // statement boundary, JSX, class property, ...
    }
    child = path;
    path = path.parentPath;
  }
  return null;
}

const insecureRandomRule: Rule = {
  id: 'INSECURE_RANDOM',
  description: 'Math.random() used in security-sensitive context (token/key generation)',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        const callee = node.callee;
        if (callee.type !== 'MemberExpression' || callee.object.type !== 'Identifier' || callee.property.type !== 'Identifier') return;

        const isMathRandom = callee.object.name === 'Math' && callee.property.name === 'random';
        const isDateNow = callee.object.name === 'Date' && callee.property.name === 'now';
        if (!isMathRandom && !isDateNow) return;

        const sink = randomSinkName(path);
        let name = isSecurityRandomName(sink) ? sink : null;

        // The value was built up in a throwaway variable (`r += chars[Math.floor(Math.random() * n)]`) or an
        // anonymous callback (`Array.from({ length }, () => ...)`): judge by the generator function around it.
        const sinkIsAnonymous = sink === null || GENERIC_SINK_NAMES.has(sink.toLowerCase());
        if (!name && isMathRandom && sinkIsAnonymous) {
          let fn = path.getFunctionParent();
          while (fn && !name) {
            const fnName = functionName(fn);
            if (fnName && isRandomGeneratorName(fnName)) name = fnName;
            fn = fn.parentPath?.getFunctionParent();
          }
        }
        if (!name) return;

        const line = getLineNumber(context.fileContent, node.start || 0);
        findings.push({
          ruleId: 'INSECURE_RANDOM',
          description: isMathRandom
            ? `Math.random() used for security-sensitive random value generation ("${name}")`
            : `Date.now() used as a predictable value for "${name}"`,
          severity: isMathRandom ? Severity.HIGH : Severity.MEDIUM,
          ...(isMathRandom ? {} : { confidence: 'medium' as const }),
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Use expo-random or crypto.getRandomValues() for cryptographically secure random values. Math.random() and timestamps are predictable.',
        });
      },
    });

    return findings;
  },
};

const jwtNoExpiryCheckRule: Rule = {
  id: 'JWT_NO_EXPIRY_CHECK',
  description: 'JWT token retrieved from storage without expiration validation',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    // Any sign that expiry is handled: jwt-decode / jsonwebtoken, or identifiers like `exp`, `expiresAt`, `isTokenExpired`
    let hasJwtDecode = false;
    traverse(context.ast, {
      Identifier(path: any) {
        const tokens = identifierTokens(path.node.name);
        if (tokens.some(t => t === 'exp' || t.startsWith('expir')) || (tokens.includes('jwt') && tokens.includes('decode'))) {
          hasJwtDecode = true;
        }
      },
      StringLiteral(path: any) {
        if (/^(?:jwt[-_]?decode|jsonwebtoken|jose)$/i.test(path.node.value)) hasJwtDecode = true;
      },
    });

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          (node.callee.object.name === 'AsyncStorage' || node.callee.object.name === 'SecureStore') &&
          node.callee.property.type === 'Identifier' &&
          (node.callee.property.name === 'getItem' || node.callee.property.name === 'getItemAsync')
        ) {
          const keyArg = node.arguments[0];
          if (keyArg && keyArg.type === 'StringLiteral') {
            const key = keyArg.value.toLowerCase();
            // push/device/CSRF tokens are opaque identifiers, not JWTs with an `exp` claim
            const opaqueToken = /fcm|apns|push|device|notification|csrf|xsrf|firebase/.test(key);
            
            if ((key.includes('jwt') || key.includes('token')) && !opaqueToken && !hasJwtDecode) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'JWT_NO_EXPIRY_CHECK',
                description: `JWT token retrieved from storage without expiration validation: "${keyArg.value}"`,
                severity: Severity.MEDIUM,
                confidence: 'medium',
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Install and use jwt-decode to validate token expiration before use. Check the "exp" claim and refresh token if expired.',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const textInputNoSecureRule: Rule = {
  id: 'TEXT_INPUT_NO_SECURE',
  description: 'Password or sensitive input field without secureTextEntry property',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      JSXElement(path: any) {
        const { node } = path;
        
        if (
          node.openingElement.name.type === 'JSXIdentifier' &&
          node.openingElement.name.name === 'TextInput'
        ) {
          let hasSecureTextEntry = false;
          let hasSensitivePlaceholder = false;
          let sensitiveType = '';
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'secureTextEntry') {
                hasSecureTextEntry = true;
              }
              
              if (attr.name.name === 'placeholder' || attr.name.name === 'label') {
                if (attr.value && attr.value.type === 'StringLiteral') {
                  const value = attr.value.value.toLowerCase();
                  const sensitiveKeywords = ['password', 'pin', 'ssn', 'cvv', 'credit card', 'security code'];
                  
                  for (const keyword of sensitiveKeywords) {
                    // Whole words only: "Passwordless sign-in" and "Passport" are not password fields
                    if (new RegExp(`(?:^|[^a-z0-9])${keyword}(?![a-z0-9])`).test(value)) {
                      hasSensitivePlaceholder = true;
                      sensitiveType = keyword;
                      break;
                    }
                  }
                }
              }
              
              if (attr.name.name === 'textContentType') {
                if (attr.value && attr.value.type === 'StringLiteral') {
                  const value = attr.value.value;
                  if (value === 'password' || value === 'newPassword') {
                    hasSensitivePlaceholder = true;
                    sensitiveType = 'password';
                  }
                }
              }
              
              if (attr.name.name === 'autoCompleteType' || attr.name.name === 'autoComplete') {
                if (attr.value && attr.value.type === 'StringLiteral') {
                  const value = attr.value.value;
                  if (['password', 'password-new', 'current-password', 'new-password'].includes(value)) {
                    hasSensitivePlaceholder = true;
                    sensitiveType = 'password';
                  }
                }
              }
            }
          });
          
          // A props spread may carry secureTextEntry; we cannot tell, so stay quiet
          const hasSpread = node.openingElement.attributes.some((a: any) => a.type === 'JSXSpreadAttribute');

          if (hasSensitivePlaceholder && !hasSecureTextEntry && !hasSpread) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'TEXT_INPUT_NO_SECURE',
              description: `TextInput for ${sensitiveType} without secureTextEntry property`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Add secureTextEntry={true} to hide sensitive input and prevent screen recording/screenshots of this field',
            });
          }
        }
      },
    });

    return findings;
  },
};

// A URL-like string: `scheme://...` or a rooted path. Prose that merely mentions "http" does not count.
const URL_LIKE = /^\s*(?:[a-z][a-z0-9+.-]*:\/\/|\/)/i;
const TOKEN_IN_QUERY = /[?&](token|access_token|auth_token|api_key)=/i;

const oauthTokenInUrlRule: Rule = {
  id: 'OAUTH_TOKEN_IN_URL',
  description: 'OAuth/access token passed in URL query parameters',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      StringLiteral(path: any) {
        const { node } = path;
        const value = node.value;
        
        if (URL_LIKE.test(value)) {
          const hasTokenInUrl = TOKEN_IN_QUERY.test(value);
          
          if (hasTokenInUrl) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'OAUTH_TOKEN_IN_URL',
              description: 'Authentication token passed as URL query parameter - visible in logs',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use Authorization header instead of URL parameters for tokens to prevent exposure in logs',
            });
          }
        }
      },
      
      TemplateLiteral(path: any) {
        const { node } = path;
        
        if (node.quasis && node.quasis.length > 0) {
          const templateText = node.quasis.map((q: any) => q.value.raw).join('');
          
          if (URL_LIKE.test(templateText) && TOKEN_IN_QUERY.test(templateText)) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'OAUTH_TOKEN_IN_URL',
              description: 'Authentication token passed as URL query parameter in template',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use Authorization header instead of URL parameters for tokens',
            });
          }
        }
      },
    });

    return findings;
  },
};

/** Options object of a react-native-ssl-pinning call: has `sslPinning`, or the file imports the library. */
function isSslPinningOptions(objectNode: any): boolean {
  if (!objectNode || objectNode.type !== 'ObjectExpression') return false;
  return objectNode.properties.some(
    (p: any) =>
      p.type === 'ObjectProperty' &&
      ((p.key.type === 'Identifier' && p.key.name === 'sslPinning') ||
        (p.key.type === 'StringLiteral' && p.key.value === 'sslPinning'))
  );
}

const certPinningDisabledRule: Rule = {
  id: 'CERT_PINNING_DISABLED',
  description: 'SSL certificate pinning disabled or bypassed',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const usesSslPinningLib = /['"]react-native-ssl-pinning['"]/.test(context.fileContent);

    traverse(context.ast, {
      ObjectProperty(path: any) {
        const { node } = path;
        
        if (
          (node.key.type === 'Identifier' || node.key.type === 'StringLiteral') &&
          node.value.type === 'BooleanLiteral'
        ) {
          const keyName = node.key.type === 'Identifier' ? node.key.name : node.key.value;
          
          // trustAllCerts is the inverse switch: `true` trusts everything, `false` is the safe setting
          if (
            ((keyName === 'rejectUnauthorized' || keyName === 'validateCertificate') && node.value.value === false) ||
            (keyName === 'trustAllCerts' && node.value.value === true) ||
            // react-native-ssl-pinning: fetch(url, { sslPinning: {...}, disableAllSecurity: true })
            (keyName === 'disableAllSecurity' && node.value.value === true && (usesSslPinningLib || isSslPinningOptions(path.parent)))
          ) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'CERT_PINNING_DISABLED',
              description: `SSL certificate validation disabled: ${keyName}=${node.value.value}`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Enable certificate validation and implement certificate pinning for production environments',
            });
          }
        }
      },
    });

    return findings;
  },
};

const FALLBACK_CREDENTIAL_TERMS: ReadonlySet<string> = new Set(['pin', 'password', 'passcode', 'passwd']);

const improperBiometricFallbackRule: Rule = {
  id: 'IMPROPER_BIOMETRIC_FALLBACK',
  description: 'Biometric authentication with insecure fallback mechanism',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    // Comments ("TODO: add fallback", "password = ...") are not code
    const content = blankComments(context.fileContent, context.ast).toLowerCase();
    
    // Check if biometric auth is used
    const hasBiometricAuth = 
      content.includes('biometric') ||
      content.includes('touchid') ||
      content.includes('faceid') ||
      content.includes('fingerprint') ||
      content.includes('authenticateasync');

    if (!hasBiometricAuth) {
      return findings;
    }

    const fallbackFinding = (line: number | undefined, confidence: 'medium' | 'low'): Finding => ({
      ruleId: 'IMPROPER_BIOMETRIC_FALLBACK',
      description: 'Biometric authentication falls back to insecurely stored credentials',
      severity: Severity.MEDIUM,
      confidence,
      filePath: context.filePath,
      line: line ?? 1,
      snippet: line ? extractSnippet(context.fileContent, line) : undefined,
      suggestion: 'Use proper fallback: require device passcode/pattern, or store fallback credentials in secure keychain/keystore, never in plaintext or AsyncStorage.',
    });

    // A PIN or password held as a string literal: `const pin = '1234'`, `{ password: 'hunter2' }`.
    // Whole-word match on the identifier (`spin`, `shipping`, `mapping` do not count).
    let literalCredentialLine: number | undefined;
    const checkLiteral = (node: any, name: string | null, value: any) => {
      if (literalCredentialLine || !name || value?.type !== 'StringLiteral' || !value.value) return;
      // label dictionaries: `{ pin: 'PIN', password: 'Enter your password' }`
      if (/\s/.test(value.value) || value.value.toLowerCase() === name.toLowerCase()) return;
      if (identifierEndsWithTerm(name, FALLBACK_CREDENTIAL_TERMS)) {
        literalCredentialLine = getLineNumber(context.fileContent, node.start || 0);
      }
    };
    traverse(context.ast, {
      VariableDeclarator(path: any) { checkLiteral(path.node, targetName(path.node.id), path.node.init); },
      ObjectProperty(path: any) { if (!path.node.computed) checkLiteral(path.node, targetName(path.node.key), path.node.value); },
      AssignmentExpression(path: any) { checkLiteral(path.node, targetName(path.node.left), path.node.right); },
    });

    if (literalCredentialLine) {
      findings.push(fallbackFinding(literalCredentialLine, 'medium'));
    } else if (
      /\b(?:pin|password)\b.*asyncstorage/.test(content) ||
      /\basyncstorage\b.*\b(?:pin|password)\b/.test(content) ||
      /\bfallback\w*\s*=\s*true/.test(content)
    ) {
      findings.push(fallbackFinding(undefined, 'low'));
    }

    // No "missing fallback" finding: expo-local-authentication and react-native-biometrics fall back to the
    // device passcode by default, and a file that merely mentions "biometric" says nothing about a weakness.

    return findings;
  },
};

const missingSessionTimeoutRule: Rule = {
  id: 'MISSING_SESSION_TIMEOUT',
  description: 'Authentication session without timeout or inactivity expiry',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.ast) {
      return findings;
    }

    // Only check auth-related files
    const filePath = context.filePath.toLowerCase();
    const isAuthFile =
      filePath.includes('auth') ||
      filePath.includes('session') ||
      filePath.includes('login');

    if (!isAuthFile) {
      return findings;
    }

    const content = context.fileContent.toLowerCase();

    // Check if file handles authentication/sessions
    const hasAuth =
      content.includes('login') ||
      content.includes('authenticate') ||
      content.includes('signin') ||
      content.includes('sign_in');

    const hasTokenStorage =
      content.includes('setitem') && (content.includes('token') || content.includes('session')) ||
      content.includes('securestore') && content.includes('setitem');

    if (!hasAuth && !hasTokenStorage) {
      return findings;
    }

    // Check for session timeout/expiry mechanisms
    const hasTimeout =
      content.includes('timeout') ||
      content.includes('expir') ||
      content.includes('ttl') ||
      content.includes('maxage') ||
      content.includes('max_age') ||
      content.includes('inactivity') ||
      content.includes('sessionduration') ||
      content.includes('session_duration') ||
      content.includes('autologout') ||
      content.includes('auto_logout') ||
      content.includes('idle');

    if (!hasTimeout) {
      findings.push({
        ruleId: 'MISSING_SESSION_TIMEOUT',
        description: 'Authentication session without timeout or inactivity expiry',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line: 1,
        suggestion: 'Implement session timeout for authentication. Auto-logout users after inactivity period. Set token expiration and validate on each request.',
      });
    }

    return findings;
  },
};

export const authenticationRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [
    insecureRandomRule,
    jwtNoExpiryCheckRule,
    textInputNoSecureRule,
    oauthTokenInUrlRule,
    certPinningDisabledRule,
    improperBiometricFallbackRule,
    missingSessionTimeoutRule,
  ],
};
