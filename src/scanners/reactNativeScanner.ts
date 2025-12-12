import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

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
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'MemberExpression' &&
          node.callee.object.object.type === 'Identifier' &&
          node.callee.object.object.name === 'NativeModules'
        ) {
          const moduleName = node.callee.object.property?.name;
          
          if (node.arguments.length > 0) {
            const surroundingCode = context.fileContent.substring(
              Math.max(0, (node.start || 0) - 200),
              Math.min(context.fileContent.length, (node.end || 0) + 100)
            );
            
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

const debuggerEnabledProductionRule: Rule = {
  id: 'DEBUGGER_ENABLED_PRODUCTION',
  description: 'Debugger statement found in production code',
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
    });

    return findings;
  },
};

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
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Linking' &&
          node.callee.property.type === 'Identifier' &&
          (node.callee.property.name === 'addEventListener' || node.callee.property.name === 'getInitialURL')
        ) {
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

const flatlistSensitiveDataRule: Rule = {
  id: 'FLATLIST_SENSITIVE_DATA',
  description: 'FlatList rendering sensitive financial or PII data without removeClippedSubviews',
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
          
          const financialDataKeywords = [
            'transactions',
            'paymenthistory', 'payment_history',
            'creditcards', 'credit_cards',
            'banktransfers', 'bank_transfers',
            'cardnumbers', 'card_numbers'
          ];
          
          const hasFinancialData = financialDataKeywords.some(keyword => dataSource.includes(keyword));
          
          if (!hasFinancialData) {
            return;
          }
          
          const renderItemCode = context.fileContent.substring(
            node.start || 0,
            node.end || 0
          ).toLowerCase();
          
          const rendersSensitiveFields = 
            (renderItemCode.includes('cardnumber') || renderItemCode.includes('card.number')) ||
            (renderItemCode.includes('accountnumber') || renderItemCode.includes('account.number')) ||
            renderItemCode.includes('ssn') ||
            renderItemCode.includes('amount') && renderItemCode.includes('balance');
          
          if (hasFinancialData && rendersSensitiveFields && !hasRemoveClippedSubviews) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'FLATLIST_SENSITIVE_DATA',
              description: 'FlatList rendering financial transaction or card data without removeClippedSubviews',
              severity: Severity.LOW,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Add removeClippedSubviews={true} to prevent sensitive financial data from being held in memory for off-screen items',
            });
          }
        }
      },
    });

    return findings;
  },
};

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

    const hasSecureStore = context.fileContent.includes('SecureStore');
    
    if (!hasSecureStore) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'SecureStore' &&
          (node.callee.property.name === 'setItemAsync' || node.callee.property.name === 'getItemAsync')
        ) {
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

    let hasSecureTextEntry = false;
    
    traverse(context.ast, {
      JSXElement(path: any) {
        const { node } = path;
        const elementName = node.openingElement?.name?.name;
        
        if (elementName === 'TextInput') {
          node.openingElement.attributes.forEach((attr: any) => {
            if (
              attr.type === 'JSXAttribute' && 
              attr.name?.name === 'secureTextEntry' &&
              attr.value?.expression?.value === true
            ) {
              hasSecureTextEntry = true;
            }
          });
        }
      },
    });

    if (!hasSecureTextEntry) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Animated' &&
          (node.callee.property.name === 'timing' || node.callee.property.name === 'spring')
        ) {
          const firstArg = node.arguments[0];
          if (!firstArg || firstArg.type !== 'Identifier') {
            return;
          }
          
          const animatedVarName = firstArg.name.toLowerCase();
          
          const isVisibilityAnimation = 
            animatedVarName.includes('opacity') ||
            animatedVarName.includes('visible') ||
            animatedVarName.includes('show') ||
            animatedVarName.includes('fade');
          
          if (!isVisibilityAnimation) {
            return;
          }
          
          const closeContext = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 80),
            Math.min(context.fileContent.length, (node.end || 0) + 80)
          );
          
          const isPasswordToggle = 
            (closeContext.includes('showPassword') || closeContext.includes('setShowPassword')) ||
            (closeContext.includes('passwordVisible') || closeContext.includes('setPasswordVisible'));
          
          if (isPasswordToggle) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'ANIMATED_TIMING_SENSITIVE',
              description: 'Password visibility toggle with animation may expose sensitive data during transition',
              severity: Severity.LOW,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use immediate transitions (duration: 0) for password visibility toggles to prevent exposure',
            });
          }
        }
      },
    });

    return findings;
  },
};

const touchableOpacitySensitiveActionRule: Rule = {
  id: 'TOUCHABLEOPACITY_SENSITIVE_ACTION',
  description: 'Destructive or financial action without confirmation dialog',
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
            
            const destructiveActions = [
              'deleteaccount', 'delete_account', 'removeaccount', 'remove_account',
              'deleteuser', 'delete_user', 'closeaccount', 'close_account',
              'deletesubscription', 'delete_subscription', 'cancelsubscription', 'cancel_subscription',
              'deletepaymentmethod', 'delete_payment', 'removepaymentmethod', 'remove_payment',
            ];
            
            const financialActions = [
              'makepayment', 'make_payment', 'processpayment', 'process_payment',
              'chargepayment', 'charge_payment', 'createcharge', 'create_charge',
              'purchaseticket', 'purchase_ticket', 'buyticket', 'buy_ticket',
              'transferfunds', 'transfer_funds', 'sendmoney', 'send_money',
              'refundpayment', 'refund_payment', 'processrefund', 'process_refund',
            ];
            
            const handlerCodeNoSpaces = handlerCode.replace(/\s+/g, '');
            
            const hasDestructiveAction = destructiveActions.some(action => handlerCodeNoSpaces.includes(action));
            const hasFinancialAction = financialActions.some(action => handlerCodeNoSpaces.includes(action));
            
            const hasConfirmation = /alert\.alert|confirm|showmodal|setmodal.*true|dialog|confirmationmodal/i.test(handlerCode);
            
            const contextStart = Math.max(0, start - 500);
            const contextEnd = Math.min(context.fileContent.length, end + 500);
            const contextCode = context.fileContent.substring(contextStart, contextEnd).toLowerCase();
            
            const isInDeleteContext = /delete.*account|delete.*subscription|delete.*payment|remove.*account/i.test(contextCode);
            const isInPaymentContext = /payment.*process|make.*payment|purchase|buy.*ticket|charge.*customer/i.test(contextCode);
            
            const isTrulySensitive = (hasDestructiveAction && isInDeleteContext) || (hasFinancialAction && isInPaymentContext);
            
            if (isTrulySensitive && !hasConfirmation) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              let actionType = 'destructive';
              if (hasFinancialAction) {
                actionType = 'payment';
              } else if (handlerCodeNoSpaces.includes('deleteaccount') || handlerCodeNoSpaces.includes('closeaccount')) {
                actionType = 'account deletion';
              } else if (handlerCodeNoSpaces.includes('delete') || handlerCodeNoSpaces.includes('remove')) {
                actionType = 'deletion';
              }
              
              findings.push({
                ruleId: 'TOUCHABLEOPACITY_SENSITIVE_ACTION',
                description: `Critical ${actionType} action triggered without user confirmation`,
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Add confirmation dialog (Alert.alert) before executing destructive or financial actions',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const screenshotProtectionMissingRule: Rule = {
  id: 'SCREENSHOT_PROTECTION_MISSING',
  description: 'Sensitive screen without screenshot/screen recording protection',
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
      filePath.includes('metro.config') ||
      filePath.includes('babel.config') ||
      filePath.includes('jest.config') ||
      filePath.includes('webpack.config') ||
      filePath.includes('.config.') ||
      filePath.includes('/scripts/') ||
      filePath.includes('/config/') ||
      filePath.includes('/utils/') ||
      filePath.includes('/helpers/') ||
      filePath.includes('/constants/') ||
      filePath.includes('/lib/') ||
      filePath.includes('/hooks/') ||
      filePath.includes('/store/') ||
      filePath.includes('/redux/') ||
      filePath.includes('/slices/') ||
      filePath.includes('/api/') ||
      filePath.includes('/services/') ||
      filePath.includes('/types/') ||
      filePath.includes('/models/') ||
      filePath.includes('index.') ||
      filePath.endsWith('.test.tsx') ||
      filePath.endsWith('.test.ts') ||
      filePath.endsWith('.spec.tsx') ||
      filePath.endsWith('.spec.ts')
    ) {
      return findings;
    }

    const isLikelyScreen = 
      filePath.includes('/screens/') ||
      filePath.includes('/pages/') ||
      filePath.includes('/views/') ||
      filePath.match(/screen\.(tsx|jsx)$/) ||
      filePath.match(/page\.(tsx|jsx)$/);

    if (!isLikelyScreen) {
      return findings;
    }

    let hasJSXReturn = false;
    let isReactComponent = false;
    
    traverse(context.ast, {
      ImportDeclaration(path: any) {
        const { node } = path;
        if (node.source && node.source.value === 'react') {
          isReactComponent = true;
        }
      },
      
      ReturnStatement(path: any) {
        const { node } = path;
        if (node.argument && (node.argument.type === 'JSXElement' || node.argument.type === 'JSXFragment')) {
          hasJSXReturn = true;
        }
      },
    });

    if (!isReactComponent || !hasJSXReturn) {
      return findings;
    }

    let hasSensitiveInput = false;
    let sensitiveType = '';
    
    traverse(context.ast, {
      JSXElement(path: any) {
        const { node } = path;
        const elementName = node.openingElement?.name?.name;
        
        if (elementName === 'TextInput') {
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name?.name) {
              const attrName = attr.name.name.toLowerCase();
              const attrValue = attr.value?.value?.toLowerCase() || '';
              
              if (
                attrName === 'securetextentry' ||
                (attrName === 'placeholder' && (
                  attrValue.includes('password') ||
                  attrValue.includes('pin code') ||
                  attrValue.includes('cvv') ||
                  attrValue.includes('credit card') ||
                  attrValue.includes('card number') ||
                  attrValue.includes('ssn') ||
                  attrValue.includes('social security')
                )) ||
                (attrName === 'autocomplete' && (
                  attrValue === 'password' ||
                  attrValue === 'password-new' ||
                  attrValue.startsWith('cc-') ||
                  attrValue === 'credit-card-number'
                ))
              ) {
                hasSensitiveInput = true;
                sensitiveType = attrValue || 'secure input';
              }
            }
          });
        }
        
        const paymentComponents = ['CreditCardForm', 'CardForm', 'PaymentForm', 'CardInput', 'StripeCardField', 'CardField'];
        if (paymentComponents.includes(elementName)) {
          hasSensitiveInput = true;
          sensitiveType = 'payment form';
        }
      },
      
      VariableDeclarator(path: any) {
        const { node } = path;
        if (node.id.type === 'Identifier') {
          const varName = node.id.name.toLowerCase();
          
          if (
            (varName === 'password' || varName === 'pin' || varName === 'cvv' || varName === 'cardnumber') &&
            node.init &&
            node.init.type === 'CallExpression' &&
            node.init.callee.name === 'useState'
          ) {
            hasSensitiveInput = true;
            sensitiveType = varName + ' field';
          }
        }
      },
    });

    if (!hasSensitiveInput) {
      return findings;
    }

    let hasScreenshotProtection = false;
    
    traverse(context.ast, {
      ImportDeclaration(path: any) {
        const { node } = path;
        if (node.source && node.source.value) {
          const importSource = node.source.value.toLowerCase();
          if (
            importSource.includes('screen-capture') || 
            importSource.includes('screenshot-prevent') ||
            importSource.includes('expo-screen-capture')
          ) {
            hasScreenshotProtection = true;
          }
        }
      },
      
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.name === 'ScreenCapture' &&
          node.callee.property.name === 'preventScreenCaptureAsync'
        ) {
          hasScreenshotProtection = true;
        }
      },
    });

    if (!hasScreenshotProtection) {
      findings.push({
        ruleId: 'SCREENSHOT_PROTECTION_MISSING',
        description: `Sensitive screen with ${sensitiveType} without screenshot protection`,
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line: 1,
        suggestion: 'Use expo-screen-capture or react-native-screenshot-prevent to block screenshots on sensitive screens',
      });
    }

    return findings;
  },
};

const rootDetectionMissingRule: Rule = {
  id: 'ROOT_DETECTION_MISSING',
  description: 'No root/jailbreak detection for sensitive application',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    if (!context.filePath.match(/App\.(tsx|ts|jsx|js)$/) && !context.filePath.includes('index.')) {
      return findings;
    }

    const fileContent = context.fileContent.toLowerCase();
    const isSensitiveApp = 
      fileContent.includes('payment') || 
      fileContent.includes('banking') ||
      fileContent.includes('finance') ||
      fileContent.includes('auth');
    
    if (!isSensitiveApp) {
      return findings;
    }

    let hasRootDetection = false;
    
    traverse(context.ast, {
      ImportDeclaration(path: any) {
        const { node } = path;
        if (node.source && node.source.value) {
          const importSource = node.source.value.toLowerCase();
          if (
            importSource.includes('jailbreak') || 
            importSource.includes('rootdetection') ||
            importSource.includes('jail-monkey')
          ) {
            hasRootDetection = true;
          }
        }
      },
    });

    if (!hasRootDetection) {
      findings.push({
        ruleId: 'ROOT_DETECTION_MISSING',
        description: 'Sensitive app without root/jailbreak detection',
        severity: Severity.LOW,
        filePath: context.filePath,
        line: 1,
        suggestion: 'Implement root/jailbreak detection using jail-monkey or similar library to protect sensitive data',
      });
    }

    return findings;
  },
};

const unsafeDangerouslySetInnerHtmlRule: Rule = {
  id: 'UNSAFE_DANGEROUSLY_SET_INNER_HTML',
  description: 'dangerouslySetInnerHTML used with potentially unsafe content',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      JSXAttribute(path: any) {
        const { node } = path;
        
        if (
          node.name.type === 'JSXIdentifier' &&
          node.name.name === 'dangerouslySetInnerHTML'
        ) {
          if (node.value && node.value.type === 'JSXExpressionContainer') {
            const start = Math.max(0, (node.start || 0) - 200);
            const end = Math.min(context.fileContent.length, (node.end || 0) + 200);
            const surroundingCode = context.fileContent.substring(start, end).toLowerCase();
            
            const hasSanitization = /sanitize|dompurify|xss|escape/i.test(surroundingCode);
            
            if (!hasSanitization) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'UNSAFE_DANGEROUSLY_SET_INNER_HTML',
                description: 'dangerouslySetInnerHTML without HTML sanitization - XSS risk',
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Sanitize HTML content with DOMPurify or similar library before rendering to prevent XSS attacks',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const networkLoggerInProductionRule: Rule = {
  id: 'NETWORK_LOGGER_IN_PRODUCTION',
  description: 'Network request/response logging enabled - may expose sensitive data',
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
          node.callee.property.name === 'use'
        ) {
          const start = (node.start || 0);
          const end = Math.min(context.fileContent.length, (node.end || 0) + 500);
          const code = context.fileContent.substring(start, end).toLowerCase();
          
          const hasInterceptor = /interceptor|request|response/i.test(code);
          const hasLogging = /console\.log|logger|debug|\.data|\.headers/i.test(code);
          const hasDevCheck = /__DEV__|process\.env\.NODE_ENV.*development/i.test(code);
          
          if (hasInterceptor && hasLogging && !hasDevCheck) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'NETWORK_LOGGER_IN_PRODUCTION',
              description: 'Network interceptor with logging not wrapped in __DEV__ check',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Wrap network logging in __DEV__ check or disable in production to prevent sensitive data exposure',
            });
          }
        }
      },
    });

    return findings;
  },
};

const evalUsageRule: Rule = {
  id: 'EVAL_USAGE',
  description: 'eval() used - code injection risk',
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
          node.callee.type === 'Identifier' &&
          (node.callee.name === 'eval' || node.callee.name === 'Function')
        ) {
          const line = getLineNumber(context.fileContent, node.start || 0);
          
          findings.push({
            ruleId: 'EVAL_USAGE',
            description: `Dangerous ${node.callee.name}() usage detected - code injection risk`,
            severity: Severity.HIGH,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Avoid eval() and Function() constructor. Use JSON.parse() for JSON data or refactor code',
          });
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
    screenshotProtectionMissingRule,
    rootDetectionMissingRule,
    unsafeDangerouslySetInnerHtmlRule,
    networkLoggerInProductionRule,
    evalUsageRule,
  ],
};
