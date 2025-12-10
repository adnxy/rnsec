import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { containsSensitiveKeyword, looksLikeSecret, getLineNumber, extractSnippet, isLikelySensitiveVariable, isLikelyIdentifier } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

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
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'AsyncStorage' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'setItem'
        ) {
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
        
        if (node.id.type === 'Identifier') {
          const varName = node.id.name;
          
          if (varName.toLowerCase().includes('test') || 
              varName.toLowerCase().includes('mock') ||
              varName.toLowerCase().includes('fixture') ||
              varName.toLowerCase().includes('example')) {
            return;
          }
          
          if (node.init && node.init.type === 'StringLiteral') {
            const value = node.init.value;
            
            if (isLikelyIdentifier(value)) {
              return;
            }
            
            if (isLikelySensitiveVariable(varName, value) || looksLikeSecret(value)) {
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
        
        if (
          (node.key.type === 'Identifier' || node.key.type === 'StringLiteral') &&
          node.value.type === 'StringLiteral'
        ) {
          const keyName = node.key.type === 'Identifier' ? node.key.name : node.key.value;
          const value = node.value.value;
          
          if (isLikelyIdentifier(value)) {
            return;
          }
          
          if (isLikelySensitiveVariable(keyName, value) || looksLikeSecret(value)) {
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

const asyncStoragePiiDataRule: Rule = {
  id: 'ASYNCSTORAGE_PII_DATA',
  description: 'AsyncStorage storing PII (email, phone, SSN) without encryption',
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
          node.callee.object.name === 'AsyncStorage' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'setItem'
        ) {
          const keyArg = node.arguments[0];
          if (keyArg && keyArg.type === 'StringLiteral') {
            const key = keyArg.value.toLowerCase();
            
            const piiKeywords = ['email', 'phone', 'phonenumber', 'ssn', 'socialsecurity', 'address', 'birthdate', 'dob', 'creditcard', 'passport'];
            const containsPii = piiKeywords.some(keyword => key.includes(keyword));
            
            if (containsPii) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'ASYNCSTORAGE_PII_DATA',
                description: `AsyncStorage storing PII data with key: "${keyArg.value}"`,
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Use encrypted storage (expo-secure-store, react-native-keychain, or MMKV with encryption) for PII data',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const reduxPersistNoEncryptionRule: Rule = {
  id: 'REDUX_PERSIST_NO_ENCRYPTION',
  description: 'Redux persist configuration without encryption transform for sensitive data',
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
          node.callee.type === 'Identifier' &&
          (node.callee.name === 'persistStore' || node.callee.name === 'persistReducer')
        ) {
          const configArg = node.arguments[0];
          if (configArg && configArg.type === 'ObjectExpression') {
            let hasTransforms = false;
            let hasWhitelist = false;
            let whitelistContainsSensitive = false;
            
            configArg.properties.forEach((prop: any) => {
              if (prop.key && prop.key.name === 'transforms') {
                hasTransforms = true;
              }
              
              if (prop.key && prop.key.name === 'whitelist' && prop.value.type === 'ArrayExpression') {
                hasWhitelist = true;
                prop.value.elements.forEach((el: any) => {
                  if (el && el.type === 'StringLiteral') {
                    const reducer = el.value.toLowerCase();
                    if (reducer.includes('auth') || reducer.includes('user') || reducer.includes('payment')) {
                      whitelistContainsSensitive = true;
                    }
                  }
                });
              }
            });
            
            if (hasWhitelist && whitelistContainsSensitive && !hasTransforms) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'REDUX_PERSIST_NO_ENCRYPTION',
                description: 'Redux persist storing sensitive reducers without encryption transforms',
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Add encryption transform (redux-persist-sensitive-storage) to persistConfig for sensitive data',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const clipboardSensitiveDataRule: Rule = {
  id: 'CLIPBOARD_SENSITIVE_DATA',
  description: 'Sensitive data copied to clipboard (accessible by other apps)',
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
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Clipboard' &&
          node.callee.property.type === 'Identifier' &&
          (node.callee.property.name === 'setString' || node.callee.property.name === 'setStringAsync')
        ) {
          const start = Math.max(0, (node.start || 0) - 200);
          const end = Math.min(context.fileContent.length, (node.end || 0) + 100);
          const surroundingCode = context.fileContent.substring(start, end).toLowerCase();
          
          const sensitivePatterns = ['password', 'token', 'secret', 'apikey', 'creditcard', 'ssn', 'auth'];
          const hasSensitiveData = sensitivePatterns.some(pattern => surroundingCode.includes(pattern));
          
          if (hasSensitiveData) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'CLIPBOARD_SENSITIVE_DATA',
              description: 'Sensitive data copied to clipboard - accessible by other apps',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Avoid copying sensitive data to clipboard. If necessary, clear clipboard after short timeout and notify user',
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
  rules: [
    asyncStorageSensitiveKeyRule, 
    hardcodedSecretsRule,
    asyncStoragePiiDataRule,
    reduxPersistNoEncryptionRule,
    clipboardSensitiveDataRule,
  ],
};
