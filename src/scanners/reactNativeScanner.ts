/**
 * React Native specific security scanner
 * Detects React Native framework-specific vulnerabilities
 */

import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

/**
 * Rule: JAVASCRIPT_ENABLED_BRIDGE
 * Detects exposed JavaScript bridge that could allow code injection
 */
const javascriptEnabledBridgeRule: Rule = {
  id: 'JAVASCRIPT_ENABLED_BRIDGE',
  description: 'Native module exposed to JavaScript without proper input validation',
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
        
        // Check for NativeModules usage without validation
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'MemberExpression' &&
          node.callee.object.object.type === 'Identifier' &&
          node.callee.object.object.name === 'NativeModules'
        ) {
          const moduleName = node.callee.object.property?.name;
          
          // Check if parameters are passed directly without validation
          if (node.arguments.length > 0) {
            const surroundingCode = context.fileContent.substring(
              Math.max(0, (node.start || 0) - 200),
              Math.min(context.fileContent.length, (node.end || 0) + 100)
            );
            
            // Look for validation keywords
            const hasValidation = /validate|sanitize|check|verify/i.test(surroundingCode);
            
            if (!hasValidation) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'JAVASCRIPT_ENABLED_BRIDGE',
                description: `Native module "${moduleName}" called without input validation`,
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Always validate and sanitize inputs before passing to native modules to prevent code injection',
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
 * Rule: DEBUGGER_ENABLED_PRODUCTION
 * Detects debug mode or debugger statements that shouldn't be in production
 */
const debuggerEnabledProductionRule: Rule = {
  id: 'DEBUGGER_ENABLED_PRODUCTION',
  description: 'Debugger statement or debug mode enabled in production code',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      DebuggerStatement(path: any) {
        const { node } = path;
        const line = getLineNumber(context.fileContent, node.start || 0);
        
        findings.push({
          ruleId: 'DEBUGGER_ENABLED_PRODUCTION',
          description: 'Debugger statement found in code',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Remove debugger statements before production deployment or use conditional: if (__DEV__) debugger;',
        });
      },
      
      // Check for console.log without __DEV__ check
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'console'
        ) {
          // Check if it's wrapped in __DEV__ check
          let parent = path.parent;
          let hasDevCheck = false;
          
          // Simple check for __DEV__ in surrounding code
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 100),
            Math.min(context.fileContent.length, (node.end || 0) + 50)
          );
          
          if (surroundingCode.includes('__DEV__')) {
            hasDevCheck = true;
          }
          
          if (!hasDevCheck && ['log', 'debug', 'info'].includes(node.callee.property.name)) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'DEBUGGER_ENABLED_PRODUCTION',
              description: `console.${node.callee.property.name}() without __DEV__ check`,
              severity: Severity.LOW,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Wrap console logs in if (__DEV__) to prevent them in production builds',
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Rule: INSECURE_DEEPLINK_HANDLER
 * Detects deep links handled without proper validation
 */
const insecureDeeplinkHandlerRule: Rule = {
  id: 'INSECURE_DEEPLINK_HANDLER',
  description: 'Deep link or URL scheme handled without validation',
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
        
        // Check for Linking.addEventListener or useEffect with Linking
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Linking' &&
          node.callee.property.type === 'Identifier' &&
          (node.callee.property.name === 'addEventListener' || node.callee.property.name === 'getInitialURL')
        ) {
          // Check if there's validation in the callback
          const callbackArg = node.arguments[1] || node.arguments[0];
          
          if (callbackArg) {
            const callbackCode = context.fileContent.substring(
              callbackArg.start || 0,
              Math.min(context.fileContent.length, (callbackArg.end || 0) + 200)
            );
            
            const hasValidation = /validate|sanitize|whitelist|allowed|check|verify/i.test(callbackCode);
            
            if (!hasValidation) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'INSECURE_DEEPLINK_HANDLER',
                description: 'Deep link handled without URL validation',
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Validate deep link URLs against a whitelist of allowed schemes and paths before navigation',
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
 * Rule: FLATLIST_SENSITIVE_DATA
 * Detects FlatList rendering sensitive data without proper security measures
 */
const flatlistSensitiveDataRule: Rule = {
  id: 'FLATLIST_SENSITIVE_DATA',
  description: 'FlatList rendering potentially sensitive data without removeClippedSubviews',
  severity: Severity.LOW,
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
          node.openingElement.name.name === 'FlatList'
        ) {
          let hasRemoveClippedSubviews = false;
          let dataSource = '';
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'removeClippedSubviews') {
                hasRemoveClippedSubviews = true;
              }
              
              if (attr.name.name === 'data') {
                if (attr.value && attr.value.type === 'JSXExpressionContainer') {
                  dataSource = context.fileContent.substring(
                    attr.value.start || 0,
                    attr.value.end || 0
                  ).toLowerCase();
                }
              }
            }
          });
          
          // Check if data source contains sensitive keywords
          const sensitiveKeywords = ['user', 'account', 'transaction', 'payment', 'credit', 'password'];
          const hasSensitiveData = sensitiveKeywords.some(keyword => dataSource.includes(keyword));
          
          if (hasSensitiveData && !hasRemoveClippedSubviews) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'FLATLIST_SENSITIVE_DATA',
              description: 'FlatList with sensitive data should use removeClippedSubviews for security',
              severity: Severity.LOW,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Add removeClippedSubviews={true} to prevent sensitive data from being held in memory for off-screen items',
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Rule: EXPO_SECURE_STORE_FALLBACK
 * Detects SecureStore usage without fallback for unsupported devices
 */
const expoSecureStoreFallbackRule: Rule = {
  id: 'EXPO_SECURE_STORE_FALLBACK',
  description: 'Expo SecureStore used without checking availability or fallback',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    // Check if SecureStore is imported
    const hasSecureStore = context.fileContent.includes('SecureStore');
    
    if (!hasSecureStore) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for SecureStore.setItemAsync or getItemAsync
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'SecureStore' &&
          (node.callee.property.name === 'setItemAsync' || node.callee.property.name === 'getItemAsync')
        ) {
          // Check if there's a try-catch or availability check nearby
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 300),
            Math.min(context.fileContent.length, (node.end || 0) + 100)
          );
          
          const hasTryCatch = /try\s*{|catch\s*\(/.test(surroundingCode);
          const hasAvailabilityCheck = /isAvailableAsync|available/i.test(surroundingCode);
          
          if (!hasTryCatch && !hasAvailabilityCheck) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'EXPO_SECURE_STORE_FALLBACK',
              description: 'SecureStore used without error handling or availability check',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Check SecureStore.isAvailableAsync() before use and provide AsyncStorage fallback for unsupported devices',
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Rule: ANIMATED_TIMING_SENSITIVE
 * Detects animations that might expose sensitive data during transitions
 */
const animatedTimingSensitiveRule: Rule = {
  id: 'ANIMATED_TIMING_SENSITIVE',
  description: 'Sensitive data visible during animations or transitions',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    // Check for Animated.timing with sensitive data
    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Animated' &&
          (node.callee.property.name === 'timing' || node.callee.property.name === 'spring')
        ) {
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 200),
            Math.min(context.fileContent.length, (node.end || 0) + 200)
          ).toLowerCase();
          
          const sensitiveKeywords = ['password', 'pin', 'ssn', 'cvv', 'credit', 'card'];
          const hasSensitiveData = sensitiveKeywords.some(keyword => surroundingCode.includes(keyword));
          
          if (hasSensitiveData) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'ANIMATED_TIMING_SENSITIVE',
              description: 'Sensitive data may be visible during animation transitions',
              severity: Severity.LOW,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use immediate transitions (duration: 0) for screens with sensitive data to prevent exposure',
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Rule: TOUCHABLEOPACITY_SENSITIVE_ACTION
 * Detects sensitive actions without confirmation
 */
const touchableOpacitySensitiveActionRule: Rule = {
  id: 'TOUCHABLEOPACITY_SENSITIVE_ACTION',
  description: 'Sensitive action (delete, payment) without confirmation dialog',
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
        
        const touchableComponents = ['TouchableOpacity', 'TouchableHighlight', 'TouchableWithoutFeedback', 'Pressable', 'Button'];
        
        if (
          node.openingElement.name.type === 'JSXIdentifier' &&
          touchableComponents.includes(node.openingElement.name.name)
        ) {
          let onPressHandler = null;
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'onPress' && attr.value) {
                onPressHandler = attr.value;
              }
            }
          });
          
          if (onPressHandler) {
            const start = (onPressHandler as any).start || 0;
            const end = (onPressHandler as any).end || 0;
            const handlerCode = context.fileContent.substring(
              start,
              Math.min(context.fileContent.length, end + 300)
            ).toLowerCase();
            
            const sensitiveActions = ['delete', 'remove', 'payment', 'transfer', 'send', 'buy', 'purchase'];
            const hasSensitiveAction = sensitiveActions.some(action => handlerCode.includes(action));
            const hasConfirmation = /alert|confirm|modal|dialog/i.test(handlerCode);
            
            if (hasSensitiveAction && !hasConfirmation) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'TOUCHABLEOPACITY_SENSITIVE_ACTION',
                description: 'Sensitive action triggered without user confirmation',
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Add confirmation dialog (Alert.alert) before executing sensitive actions like delete or payment',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

export const reactNativeRules: RuleGroup = {
  category: RuleCategory.NETWORK,
  rules: [
    javascriptEnabledBridgeRule,
    debuggerEnabledProductionRule,
    insecureDeeplinkHandlerRule,
    flatlistSensitiveDataRule,
    expoSecureStoreFallbackRule,
    animatedTimingSensitiveRule,
    touchableOpacitySensitiveActionRule,
  ],
};

