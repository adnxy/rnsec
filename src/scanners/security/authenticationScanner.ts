import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';

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

    const filePath = context.filePath.toLowerCase();
    if (
      filePath.includes('node_modules') ||
      filePath.includes('/vendor/') ||
      filePath.includes('/assets/') ||
      filePath.includes('/modules/') ||
      filePath.includes('chart') ||
      filePath.includes('graph') ||
      filePath.includes('visualization') ||
      filePath.includes('/lib/') ||
      filePath.includes('.min.') ||
      filePath.endsWith('.test.ts') ||
      filePath.endsWith('.test.tsx') ||
      filePath.endsWith('.test.js') ||
      filePath.endsWith('.test.jsx')
    ) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Math' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'random'
        ) {
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 200),
            Math.min(context.fileContent.length, (node.end || 0) + 200)
          ).toLowerCase();
          
          const nonSecurityPatterns = [
            'chart', 'graph', 'animation', 'color', 'rgb', 'position',
            'coordinate', 'marker', 'cluster', 'plot', 'axis',
            'shuffle', 'demo', 'example', 'test', 'mock',
            'randomcolor', 'randomposition', 'delay'
          ];
          
          if (nonSecurityPatterns.some(pattern => surroundingCode.includes(pattern))) {
            return;
          }
          
          const securityPatterns = [
            /generate.*token/,
            /create.*token/,
            /token.*generat/,
            /session.*id/,
            /access.*token/,
            /refresh.*token/,
            /api.*key/,
            /secret.*key/,
            /encryption.*key/,
            /auth.*token/,
            /csrf.*token/,
            /\bnonce\b/,
            /\bsalt\b/,
            /\botp\b/,
            /verification.*code/,
            /reset.*code/,
            /\bpin\b.*generat/,
            /generat.*\bpin\b/,
            /random.*password/,
            /password.*random/,
            /\buuid\b/,
            /unique.*identifier/,
            /security.*code/
          ];
          
          const hasSecurity = securityPatterns.some(pattern => 
            pattern.test(surroundingCode)
          );
          
          if (hasSecurity) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'INSECURE_RANDOM',
              description: 'Math.random() used for security-sensitive random value generation',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use expo-random or crypto.getRandomValues() for cryptographically secure random values. Math.random() is not cryptographically secure.',
            });
          }
        }
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

    const hasJwtDecode = context.fileContent.toLowerCase().includes('jwt') && 
                        (context.fileContent.includes('decode') || context.fileContent.includes('jwtDecode'));

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
            
            if ((key.includes('jwt') || key.includes('token')) && !hasJwtDecode) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'JWT_NO_EXPIRY_CHECK',
                description: `JWT token retrieved from storage without expiration validation: "${keyArg.value}"`,
                severity: Severity.MEDIUM,
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
                    if (value.includes(keyword)) {
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
              
              if (attr.name.name === 'autoCompleteType') {
                if (attr.value && attr.value.type === 'StringLiteral') {
                  const value = attr.value.value;
                  if (value === 'password' || value === 'password-new') {
                    hasSensitivePlaceholder = true;
                    sensitiveType = 'password';
                  }
                }
              }
            }
          });
          
          if (hasSensitivePlaceholder && !hasSecureTextEntry) {
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
        
        if (value.includes('://') || value.includes('http')) {
          const hasTokenInUrl = /[?&](token|access_token|auth_token|api_key)=/i.test(value);
          
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
          
          if ((templateText.includes('://') || templateText.includes('http')) && 
              /[?&](token|access_token|auth_token|api_key)=/i.test(templateText)) {
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

    traverse(context.ast, {
      ObjectProperty(path: any) {
        const { node } = path;
        
        if (
          (node.key.type === 'Identifier' || node.key.type === 'StringLiteral') &&
          node.value.type === 'BooleanLiteral'
        ) {
          const keyName = node.key.type === 'Identifier' ? node.key.name : node.key.value;
          
          if (
            (keyName === 'rejectUnauthorized' || 
             keyName === 'validateCertificate' ||
             keyName === 'trustAllCerts') &&
            node.value.value === false
          ) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'CERT_PINNING_DISABLED',
              description: `SSL certificate validation disabled: ${keyName}=false`,
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

    const content = context.fileContent.toLowerCase();
    
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

    // Check for insecure fallback patterns
    const insecureFallbackPatterns = [
      /pin\s*=\s*['"`]/i,                    // PIN stored as string
      /password\s*=\s*['"`]/i,               // Password as string
      /\bpin\b.*asyncstorage/i,              // PIN in AsyncStorage
      /\bpassword\b.*asyncstorage/i,         // Password in AsyncStorage
      /fallback.*=.*true/i,                  // Generic fallback without proper auth
    ];

    for (const pattern of insecureFallbackPatterns) {
      if (pattern.test(content)) {
        findings.push({
          ruleId: 'IMPROPER_BIOMETRIC_FALLBACK',
          description: 'Biometric authentication falls back to insecurely stored credentials',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: 1,
          suggestion: 'Use proper fallback: require device passcode/pattern, or store fallback credentials in secure keychain/keystore, never in plaintext or AsyncStorage.',
        });
        break;
      }
    }

    // Check if there's any fallback at all
    const hasFallback = 
      content.includes('fallback') ||
      content.includes('passcode') ||
      content.includes('device') && content.includes('credential') ||
      content.includes('keychain') ||
      content.includes('securestore');

    if (hasBiometricAuth && !hasFallback && content.includes('auth')) {
      findings.push({
        ruleId: 'IMPROPER_BIOMETRIC_FALLBACK',
        description: 'Biometric authentication without proper fallback mechanism',
        severity: Severity.LOW,
        filePath: context.filePath,
        line: 1,
        suggestion: 'Implement secure fallback when biometrics fail: device passcode, secure keychain, or re-authentication.',
      });
    }

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
