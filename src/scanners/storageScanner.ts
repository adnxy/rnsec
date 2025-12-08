/**
 * Storage security scanner
 * Detects insecure storage patterns
 */

import _traverse from '@babel/traverse';
// Handle ESM/CommonJS interop
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { containsSensitiveKeyword, looksLikeSecret, getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

/**
 * Rule: ASYNCSTORAGE_SENSITIVE_KEY
 * Detects AsyncStorage.setItem with sensitive key names
 */
const asyncStorageSensitiveKeyRule: Rule = {
  id: 'ASYNCSTORAGE_SENSITIVE_KEY',
  description: 'AsyncStorage used with sensitive key names (token, password, auth, secret)',
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
        
        // Check for AsyncStorage.setItem
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'AsyncStorage' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'setItem'
        ) {
          // Check first argument (key)
          const keyArg = node.arguments[0];
          if (keyArg && keyArg.type === 'StringLiteral') {
            const key = keyArg.value;
            
            if (containsSensitiveKeyword(key)) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'ASYNCSTORAGE_SENSITIVE_KEY',
                description: `AsyncStorage storing sensitive key: "${key}"`,
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Use encrypted storage like expo-secure-store or react-native-keychain for sensitive data',
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
 * Rule: HARDCODED_SECRETS
 * Detects hardcoded secrets in constants
 */
const hardcodedSecretsRule: Rule = {
  id: 'HARDCODED_SECRETS',
  description: 'Hardcoded secrets or tokens detected in source code',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      VariableDeclarator(path: any) {
        const { node } = path;
        
        // Check variable name and value
        if (node.id.type === 'Identifier') {
          const varName = node.id.name;
          
          // Skip test-related variables
          if (varName.toLowerCase().includes('test') || 
              varName.toLowerCase().includes('mock') ||
              varName.toLowerCase().includes('fixture')) {
            return;
          }
          
          const hasSecretsInName = containsSensitiveKeyword(varName);
          
          // Check if the value looks like a secret
          if (node.init && node.init.type === 'StringLiteral') {
            const value = node.init.value;
            
            if ((hasSecretsInName && value.length > 10) || looksLikeSecret(value)) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'HARDCODED_SECRETS',
                description: `Potential hardcoded secret in variable "${varName}"`,
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Move secrets to environment variables or secure config management',
              });
            }
          }
        }
      },
      
      ObjectProperty(path: any) {
        const { node } = path;
        
        // Check object properties like { apiKey: "secret" }
        if (
          (node.key.type === 'Identifier' || node.key.type === 'StringLiteral') &&
          node.value.type === 'StringLiteral'
        ) {
          const keyName = node.key.type === 'Identifier' ? node.key.name : node.key.value;
          const value = node.value.value;
          
          if (containsSensitiveKeyword(keyName) && (value.length > 10 || looksLikeSecret(value))) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'HARDCODED_SECRETS',
              description: `Potential hardcoded secret in property "${keyName}"`,
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Move secrets to environment variables or secure config management',
            });
          }
        }
      },
    });

    return findings;
  },
};

export const storageRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [asyncStorageSensitiveKeyRule, hardcodedSecretsRule],
};

