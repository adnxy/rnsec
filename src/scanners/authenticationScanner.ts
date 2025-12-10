import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

const insecureRandomRule: Rule = {
  id: 'INSECURE_RANDOM',
  description: 'Math.random() used for generating security-sensitive values (tokens, IDs, keys)',
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
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Math' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'random'
        ) {
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 150),
            Math.min(context.fileContent.length, (node.end || 0) + 150)
          ).toLowerCase();
          
          const securityKeywords = [
            'token', 'key', 'id', 'uuid', 'secret', 
            'nonce', 'salt', 'session', 'auth', 'otp',
            'code', 'pin', 'verification'
          ];
          
          const hasSecurity = securityKeywords.some(keyword => surroundingCode.includes(keyword));
          
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

const biometricNoFallbackRule: Rule = {
  id: 'BIOMETRIC_NO_FALLBACK',
  description: 'Biometric authentication without PIN/password fallback',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          (node.callee.property.name === 'authenticateAsync' || 
           node.callee.property.name === 'isEnrolledAsync' ||
           node.callee.property.name === 'authenticate')
        ) {
          const start = Math.max(0, (node.start || 0) - 300);
          const end = Math.min(context.fileContent.length, (node.end || 0) + 500);
          const surroundingCode = context.fileContent.substring(start, end).toLowerCase();
          
          const hasFallback = /fallback|pin|password|passcode|alternative|catch.*error/i.test(surroundingCode);
          
          if (!hasFallback) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'BIOMETRIC_NO_FALLBACK',
              description: 'Biometric authentication without PIN/password fallback mechanism',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Implement fallback authentication (PIN/password) for when biometrics fail or are unavailable',
            });
          }
        }
      },
    });

    return findings;
  },
};

const sessionTimeoutMissingRule: Rule = {
  id: 'SESSION_TIMEOUT_MISSING',
  description: 'No session timeout or inactivity logout detected',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const filePath = context.filePath.toLowerCase();
    
    if (
      filePath.includes('node_modules') ||
      filePath.includes('/config/') ||
      filePath.includes('/constants/') ||
      filePath.includes('/utils/') ||
      filePath.includes('/helpers/') ||
      filePath.includes('/types/') ||
      filePath.includes('/models/') ||
      filePath.includes('_layout.') ||
      filePath.includes('layout.') ||
      filePath.includes('.config.') ||
      filePath.endsWith('.test.tsx') ||
      filePath.endsWith('.test.ts')
    ) {
      return findings;
    }

    const isAuthFile = 
      filePath.includes('/auth/') ||
      filePath.includes('/authentication/') ||
      filePath.includes('/session/') ||
      filePath.match(/auth.*context/i) ||
      filePath.match(/auth.*provider/i) ||
      filePath.match(/session.*manager/i) ||
      filePath.match(/login.*screen/i) ||
      filePath.match(/signin.*screen/i);

    if (!isAuthFile) {
      return findings;
    }

    let hasAuthStateManagement = false;
    let hasLoginFunction = false;
    let hasLogoutFunction = false;
    
    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (node.callee.type === 'Identifier') {
          const name = node.callee.name.toLowerCase();
          if (name === 'createcontext' || name === 'usecontext') {
            hasAuthStateManagement = true;
          }
        }
      },
      
      FunctionDeclaration(path: any) {
        const { node } = path;
        if (node.id && node.id.name) {
          const name = node.id.name.toLowerCase();
          if (name.includes('login') || name.includes('signin')) {
            hasLoginFunction = true;
          }
          if (name.includes('logout') || name.includes('signout')) {
            hasLogoutFunction = true;
          }
        }
      },
      
      ArrowFunctionExpression(path: any) {
        const parent = path.parent;
        if (parent && parent.type === 'VariableDeclarator' && parent.id && parent.id.name) {
          const name = parent.id.name.toLowerCase();
          if (name.includes('login') || name.includes('signin')) {
            hasLoginFunction = true;
          }
          if (name.includes('logout') || name.includes('signout')) {
            hasLogoutFunction = true;
          }
        }
      },
    });

    if (!hasLoginFunction || !hasLogoutFunction) {
      return findings;
    }

    let hasSessionTimeout = false;
    let hasInactivityLogic = false;
    
    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.name === 'AppState' &&
          (node.callee.property.name === 'addEventListener' || node.callee.property.name === 'add')
        ) {
          hasInactivityLogic = true;
        }
        
        if (node.callee.type === 'Identifier') {
          const name = node.callee.name;
          if (name === 'setTimeout' || name === 'setInterval') {
            const codeContext = context.fileContent.substring(
              Math.max(0, (node.start || 0) - 200),
              Math.min(context.fileContent.length, (node.end || 0) + 200)
            ).toLowerCase();
            
            if (codeContext.includes('logout') || codeContext.includes('session') || codeContext.includes('inactivity')) {
              hasSessionTimeout = true;
            }
          }
        }
      },
      
      VariableDeclarator(path: any) {
        const { node } = path;
        if (node.id.type === 'Identifier') {
          const name = node.id.name.toLowerCase();
          if (
            name.includes('sessiontimeout') ||
            name.includes('inactivitytimeout') ||
            name.includes('autologout') ||
            name.includes('sessionduration')
          ) {
            hasSessionTimeout = true;
          }
        }
      },
    });

    if (hasAuthStateManagement && !hasSessionTimeout && !hasInactivityLogic) {
      findings.push({
        ruleId: 'SESSION_TIMEOUT_MISSING',
        description: 'Authentication provider/context without session timeout or inactivity logout',
        severity: Severity.LOW,
        filePath: context.filePath,
        line: 1,
        suggestion: 'Implement session timeout and automatic logout after period of inactivity to protect user data',
      });
    }

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
  severity: Severity.HIGH,
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
              severity: Severity.HIGH,
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

export const authenticationRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [
    insecureRandomRule, 
    jwtNoExpiryCheckRule, 
    textInputNoSecureRule,
    biometricNoFallbackRule,
    sessionTimeoutMissingRule,
    oauthTokenInUrlRule,
    certPinningDisabledRule,
  ],
};
