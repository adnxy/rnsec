import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { containsSensitiveKeyword, looksLikeSecret, getLineNumber, extractSnippet, isLikelySensitiveVariable, isLikelyIdentifier } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';

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
          const lowerVarName = varName.toLowerCase();
          
          const testPatterns = ['test', 'mock', 'fixture', 'example', 'dummy', 'sample'];
          if (testPatterns.some(pattern => lowerVarName.includes(pattern))) {
            return;
          }

          const utilityPatterns = [
            'characters', 'charset', 'alphabet', 'letters', 'digits',
            'allowed', 'valid', 'format', 'pattern', 'template'
          ];
          if (utilityPatterns.some(pattern => lowerVarName.includes(pattern))) {
            return;
          }
          
          if (node.init && node.init.type === 'StringLiteral') {
            const value = node.init.value;
            
            if (value.length < 16) {
              return;
            }
            
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
          const lowerKeyName = keyName.toLowerCase();

          const utilityPatterns = [
            'characters', 'charset', 'alphabet', 'letters', 'digits',
            'allowed', 'valid', 'format', 'pattern', 'template',
            'test', 'mock', 'example', 'sample', 'dummy'
          ];
          if (utilityPatterns.some(pattern => lowerKeyName.includes(pattern))) {
            return;
          }

          if (value.length < 16) {
            return;
          }
          
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

const insecureFileStorageRule: Rule = {
  id: 'INSECURE_FILE_STORAGE',
  description: 'Files written to insecure storage locations',
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
        
        // Check for FileSystem writeFile operations
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.name === 'FileSystem' &&
          (node.callee.property.name === 'writeAsStringAsync' || 
           node.callee.property.name === 'writeFile')
        ) {
          const pathArg = node.arguments[0];
          
          if (pathArg) {
            const pathStr = context.fileContent.substring(
              pathArg.start || 0,
              pathArg.end || 0
            ).toLowerCase();
            
            // Check for external/shared storage
            const isInsecureLocation = 
              pathStr.includes('externaldir') ||
              pathStr.includes('cachedir') ||
              pathStr.includes('downloaddir') ||
              pathStr.includes('picturesdir') ||
              pathStr.includes('documentsdir') ||
              pathStr.includes('/external') ||
              pathStr.includes('/sdcard') ||
              pathStr.includes('/downloads');
            
            if (isInsecureLocation) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'INSECURE_FILE_STORAGE',
                description: 'File written to external/shared storage - accessible by other apps',
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Use FileSystem.documentDirectory for app-private files. Encrypt sensitive data before writing to any storage.',
              });
            }
            
            // Check if sensitive data is being written
            const surroundingCode = context.fileContent.substring(
              Math.max(0, (node.start || 0) - 300),
              Math.min(context.fileContent.length, (node.end || 0) + 100)
            ).toLowerCase();
            
            const sensitivePatterns = ['password', 'token', 'secret', 'apikey', 'credential', 'auth'];
            const hasSensitiveData = sensitivePatterns.some(pattern => surroundingCode.includes(pattern));
            
            // Check if encryption is used
            const hasEncryption = 
              surroundingCode.includes('encrypt') ||
              surroundingCode.includes('cipher') ||
              surroundingCode.includes('crypto') ||
              surroundingCode.includes('securestore');
            
            if (hasSensitiveData && !hasEncryption) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'INSECURE_FILE_STORAGE',
                description: 'Sensitive data written to file without encryption',
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Encrypt sensitive data before writing to files. Use expo-secure-store for credentials.',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const mmkvNoEncryptionRule: Rule = {
  id: 'MMKV_NO_ENCRYPTION',
  description: 'MMKV used without encryption for sensitive data',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    // Track MMKV instances created without encryption
    const unencryptedMmkvInstances = new Set<string>();

    // Helper function to check if createMMKV has encryption
    const hasEncryption = (configArg: any): boolean => {
      if (!configArg || configArg.type !== 'ObjectExpression') {
        return false;
      }
      
      return configArg.properties.some((prop: any) => {
        if (!prop.key) return false;
        const keyName = prop.key.name || (prop.key.type === 'StringLiteral' ? prop.key.value : null);
        return keyName === 'encryptionKey';
      });
    };

    // First traversal: Collect all unencrypted MMKV instances
    traverse(context.ast, {
      VariableDeclarator(path: any) {
        const { node } = path;
        
        // Check if this is a variable declaration with createMMKV()
        if (
          node.init &&
          node.init.type === 'CallExpression' &&
          node.init.callee.type === 'Identifier' &&
          node.init.callee.name === 'createMMKV'
        ) {
          const configArg = node.init.arguments[0];
          
          // If no encryption and variable is an identifier, track it
          if (!hasEncryption(configArg) && node.id.type === 'Identifier') {
            unencryptedMmkvInstances.add(node.id.name);
          }
        }
      },
    });

    // Second traversal: Find MMKV.set() calls with sensitive data
    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for direct createMMKV().set() calls without encryption
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'CallExpression' &&
          node.callee.object.callee.type === 'Identifier' &&
          node.callee.object.callee.name === 'createMMKV' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'set'
        ) {
          const configArg = node.callee.object.arguments[0];
          
          if (!hasEncryption(configArg)) {
            const keyArg = node.arguments[0];
            
            if (keyArg && keyArg.type === 'StringLiteral') {
              const key = keyArg.value;
              
              if (containsSensitiveKeyword(key)) {
                const line = getLineNumber(context.fileContent, node.start || 0);
                
                findings.push({
                  ruleId: 'MMKV_NO_ENCRYPTION',
                  description: `MMKV storing sensitive key "${key}" without encryption`,
                  severity: Severity.HIGH,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Use MMKV with encryption: createMMKV({ encryptionKey: "your-encryption-key" }) or use expo-secure-store/react-native-keychain for sensitive data',
                });
              }
            }
          }
        }
        
        // Check for MMKV.set() calls on tracked unencrypted instances
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'set'
        ) {
          const mmkvVarName = node.callee.object.name;
          
          // Check if this MMKV instance was created without encryption
          if (unencryptedMmkvInstances.has(mmkvVarName)) {
            const keyArg = node.arguments[0];
            
            // Check if key contains sensitive keywords
            if (keyArg && keyArg.type === 'StringLiteral') {
              const key = keyArg.value;
              
              if (containsSensitiveKeyword(key)) {
                const line = getLineNumber(context.fileContent, node.start || 0);
                
                findings.push({
                  ruleId: 'MMKV_NO_ENCRYPTION',
                  description: `MMKV storing sensitive key "${key}" without encryption`,
                  severity: Severity.HIGH,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Use MMKV with encryption: createMMKV({ encryptionKey: "your-encryption-key" }) or use expo-secure-store/react-native-keychain for sensitive data',
                });
              }
            }
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
    insecureFileStorageRule,
    mmkvNoEncryptionRule,
  ],
};
