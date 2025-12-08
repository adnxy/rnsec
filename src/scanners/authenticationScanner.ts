/**
 * Authentication & Authorization security scanner
 * Detects authentication vulnerabilities
 */

import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

/**
 * Rule: INSECURE_RANDOM
 * Detects Math.random() used for security-sensitive operations
 */
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
        
        // Check for Math.random()
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Math' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'random'
        ) {
          // Get surrounding code context
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 150),
            Math.min(context.fileContent.length, (node.end || 0) + 150)
          ).toLowerCase();
          
          // Security-related keywords that indicate this is for security purposes
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

/**
 * Rule: JWT_NO_EXPIRY_CHECK
 * Detects JWT usage without expiration validation
 */
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

    // Check if jwt-decode is used in the file
    const hasJwtDecode = context.fileContent.toLowerCase().includes('jwt') && 
                        (context.fileContent.includes('decode') || context.fileContent.includes('jwtDecode'));

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for AsyncStorage.getItem with 'jwt' or 'token' in key
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

/**
 * Rule: TEXT_INPUT_NO_SECURE
 * Detects password/sensitive input fields without secureTextEntry
 */
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
        
        // Check if it's a TextInput component
        if (
          node.openingElement.name.type === 'JSXIdentifier' &&
          node.openingElement.name.name === 'TextInput'
        ) {
          let hasSecureTextEntry = false;
          let hasSensitivePlaceholder = false;
          let sensitiveType = '';
          
          // Check attributes
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              // Check for secureTextEntry
              if (attr.name.name === 'secureTextEntry') {
                hasSecureTextEntry = true;
              }
              
              // Check placeholder or label for sensitive keywords
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
              
              // Check textContentType (iOS)
              if (attr.name.name === 'textContentType') {
                if (attr.value && attr.value.type === 'StringLiteral') {
                  const value = attr.value.value;
                  if (value === 'password' || value === 'newPassword') {
                    hasSensitivePlaceholder = true;
                    sensitiveType = 'password';
                  }
                }
              }
              
              // Check autoCompleteType (Android)
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
          
          // If it looks like a sensitive input but doesn't have secureTextEntry
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

export const authenticationRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [insecureRandomRule, jwtNoExpiryCheckRule, textInputNoSecureRule],
};

