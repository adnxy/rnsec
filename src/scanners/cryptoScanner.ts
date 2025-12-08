/**
 * Cryptography security scanner
 * Detects weak or insecure cryptographic practices
 */

import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

/**
 * Rule: WEAK_HASH_ALGORITHM
 * Detects usage of weak hashing algorithms like MD5, SHA1
 */
const weakHashAlgorithmRule: Rule = {
  id: 'WEAK_HASH_ALGORITHM',
  description: 'Weak or deprecated cryptographic hash algorithm detected (MD5, SHA1)',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      // Check for crypto-js or similar library usage
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for CryptoJS.MD5() or similar
        if (node.callee.type === 'MemberExpression') {
          const objectName = node.callee.object.name;
          const propertyName = node.callee.property?.name;
          
          const weakAlgorithms = ['MD5', 'SHA1', 'md5', 'sha1'];
          
          if (
            (objectName === 'CryptoJS' || objectName === 'crypto') &&
            propertyName && weakAlgorithms.includes(propertyName)
          ) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'WEAK_HASH_ALGORITHM',
              description: `Weak hash algorithm detected: ${propertyName}`,
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use SHA-256 or stronger algorithms (SHA-384, SHA-512) instead of MD5 or SHA-1',
            });
          }
        }
      },
      
      // Check for string literals mentioning weak algorithms
      StringLiteral(path: any) {
        const { node } = path;
        const value = node.value.toLowerCase();
        
        if (value === 'md5' || value === 'sha1' || value === 'sha-1') {
          // Check if this is used in a crypto context
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 100),
            Math.min(context.fileContent.length, (node.end || 0) + 100)
          ).toLowerCase();
          
          if (
            surroundingCode.includes('hash') ||
            surroundingCode.includes('digest') ||
            surroundingCode.includes('crypto') ||
            surroundingCode.includes('algorithm')
          ) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'WEAK_HASH_ALGORITHM',
              description: `Weak hash algorithm specified: "${node.value}"`,
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use SHA-256 or stronger algorithms instead of MD5 or SHA-1',
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Rule: HARDCODED_ENCRYPTION_KEY
 * Detects hardcoded encryption keys or IVs
 */
const hardcodedEncryptionKeyRule: Rule = {
  id: 'HARDCODED_ENCRYPTION_KEY',
  description: 'Hardcoded encryption key or initialization vector (IV) detected',
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
        
        if (node.id.type === 'Identifier') {
          const varName = node.id.name.toLowerCase();
          
          // Check for variable names related to encryption
          const encryptionKeywords = ['key', 'iv', 'salt', 'cipher'];
          const hasEncryptionKeyword = encryptionKeywords.some(keyword => varName.includes(keyword));
          
          if (hasEncryptionKeyword && node.init && node.init.type === 'StringLiteral') {
            const value = node.init.value;
            
            // If it's a longish string, it's likely an encryption key
            if (value.length > 8) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'HARDCODED_ENCRYPTION_KEY',
                description: `Hardcoded encryption key or IV in variable "${node.id.name}"`,
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Encryption keys should be generated dynamically or stored in secure environment variables, not hardcoded',
              });
            }
          }
        }
      },
      
      ObjectProperty(path: any) {
        const { node } = path;
        
        if (
          (node.key.type === 'Identifier' || node.key.type === 'StringLiteral') &&
          node.value.type === 'StringLiteral'
        ) {
          const keyName = node.key.type === 'Identifier' ? node.key.name : node.key.value;
          const lowerKeyName = keyName.toLowerCase();
          const value = node.value.value;
          
          // Skip Redux persist keys and other configuration keys
          // These are typically short string identifiers, not encryption keys
          const isConfigKey = value.length < 20 && /^[a-z][a-zA-Z0-9_-]*$/.test(value);
          
          // Skip if it's likely a Redux persist key or storage identifier
          if (lowerKeyName === 'key' && isConfigKey) {
            return;
          }
          
          // Check for encryption-related property names with actual long values
          if (
            (lowerKeyName.includes('key') || lowerKeyName.includes('iv') || lowerKeyName.includes('salt')) &&
            value.length > 20 &&
            !isConfigKey
          ) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'HARDCODED_ENCRYPTION_KEY',
              description: `Hardcoded encryption key or IV in property "${keyName}"`,
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Encryption keys should be generated dynamically or stored in secure environment variables',
            });
          }
        }
      },
    });

    return findings;
  },
};

export const cryptoRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [weakHashAlgorithmRule, hardcodedEncryptionKeyRule],
};

