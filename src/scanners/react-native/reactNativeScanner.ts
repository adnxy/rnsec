import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';

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
          const hasLogging = /console\.(log|warn|error|info|debug)|logger\.|debug\(/i.test(code);
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

/**
 * Supply chain: detect eval(Buffer.from(...).toString('utf-8')) pattern used in
 * obfuscated malicious install scripts (e.g. preinstall.js / postinstall payloads).
 */
const obfuscatedEvalExecutionRule: Rule = {
  id: 'OBFUSCATED_EVAL_EXECUTION',
  description: 'eval() with Buffer.from decode - likely supply chain malware',
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
          node.callee.name === 'eval' &&
          node.arguments.length > 0
        ) {
          const arg = node.arguments[0];
          // Match: eval(Buffer.from(...).toString('utf-8')) or similar
          if (arg.type === 'CallExpression' && arg.callee.type === 'MemberExpression') {
            const member = arg.callee;
            const obj = member.object;
            const prop = member.property;
            if (
              prop.type === 'Identifier' &&
              prop.name === 'toString' &&
              obj.type === 'CallExpression' &&
              obj.callee.type === 'MemberExpression' &&
              obj.callee.object.type === 'Identifier' &&
              obj.callee.object.name === 'Buffer' &&
              obj.callee.property.type === 'Identifier' &&
              obj.callee.property.name === 'from'
            ) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              findings.push({
                ruleId: 'OBFUSCATED_EVAL_EXECUTION',
                description: 'eval() with Buffer.from().toString() - obfuscated execution, common in supply chain / malicious install scripts',
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Remove this pattern. Decoding and eval-ing content is a common malware technique. If this is in a lifecycle script (preinstall/postinstall), treat as compromise and remove the script.',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const rootJailbreakDetectionAbsentRule: Rule = {
  id: 'ROOT_JAILBREAK_DETECTION_ABSENT',
  description: 'Sensitive app without root/jailbreak detection',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.filePath.match(/App\.(tsx|ts|jsx|js)$/) && !context.filePath.includes('index.')) {
      return findings;
    }

    const content = context.fileContent.toLowerCase();
    
    // Check if app handles sensitive data
    const sensitiveIndicators = [
      'payment', 'banking', 'financial', 'fintech', 'healthcare', 'health',
      'medical', 'crypto', 'wallet', 'insurance', 'credit card', 'debit'
    ];
    
    const isSensitiveApp = sensitiveIndicators.some(indicator => content.includes(indicator));
    
    if (!isSensitiveApp) {
      return findings;
    }

    // Check for root/jailbreak detection libraries
    const hasRootDetection = content.includes('jailmonkey') ||
                             content.includes('jail-monkey') ||
                             content.includes('rootdetection') ||
                             content.includes('isrooted') ||
                             content.includes('isjailbroken') ||
                             content.includes('jailbreaktest');

    if (!hasRootDetection) {
      findings.push({
        ruleId: 'ROOT_JAILBREAK_DETECTION_ABSENT',
        description: 'Sensitive app (banking/fintech/healthcare) without root/jailbreak detection',
        severity: Severity.HIGH,
        filePath: context.filePath,
        line: 1,
        suggestion: 'Implement root/jailbreak detection using jail-monkey or similar library. Warn users or restrict functionality on compromised devices.',
      });
    }

    return findings;
  },
};

const missingRuntimeIntegrityChecksRule: Rule = {
  id: 'MISSING_RUNTIME_INTEGRITY_CHECKS',
  description: 'No runtime integrity or tamper detection implemented',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.filePath.match(/App\.(tsx|ts|jsx|js)$/) && !context.filePath.includes('index.')) {
      return findings;
    }

    const content = context.fileContent.toLowerCase();
    
    // Check if app handles sensitive operations
    const sensitiveOperations = [
      'payment', 'transaction', 'banking', 'fintech', 'crypto',
      'authentication', 'biometric', 'securestore'
    ];
    
    const hasSensitiveOps = sensitiveOperations.some(op => content.includes(op));
    
    if (!hasSensitiveOps) {
      return findings;
    }

    // Check for integrity checks
    const hasIntegrityChecks = 
      content.includes('playintegrity') ||           // Google Play Integrity API
      content.includes('safetynet') ||               // Legacy SafetyNet
      content.includes('appattest') ||               // iOS App Attest
      content.includes('devicecheck') ||             // iOS DeviceCheck
      content.includes('tamperdetection') ||
      content.includes('checksignature') ||
      content.includes('verifysignature') ||
      content.includes('checksum') ||
      content.includes('bundleidentifier') && content.includes('verify');

    if (!hasIntegrityChecks) {
      findings.push({
        ruleId: 'MISSING_RUNTIME_INTEGRITY_CHECKS',
        description: 'Sensitive app without runtime integrity or tamper detection',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line: 1,
        suggestion: 'Implement runtime integrity checks: Play Integrity API (Android), App Attest (iOS), or signature verification to detect tampering.',
      });
    }

    return findings;
  },
};

const insecureDeserializationRule: Rule = {
  id: 'INSECURE_DESERIALIZATION',
  description: 'Unsafe deserialization of untrusted data',
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
        
        // Check for JSON.parse with potentially untrusted input
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.name === 'JSON' &&
          node.callee.property.name === 'parse'
        ) {
          const arg = node.arguments[0];
          
          // Check if the argument comes from external sources
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 300),
            Math.min(context.fileContent.length, (node.end || 0) + 100)
          ).toLowerCase();
          
          const isUntrustedSource = 
            surroundingCode.includes('response') ||
            surroundingCode.includes('request') ||
            surroundingCode.includes('fetch') ||
            surroundingCode.includes('axios') ||
            surroundingCode.includes('api') ||
            surroundingCode.includes('url') ||
            surroundingCode.includes('params') ||
            surroundingCode.includes('query');
          
          const hasValidation = 
            surroundingCode.includes('validate') ||
            surroundingCode.includes('sanitize') ||
            surroundingCode.includes('schema') ||
            surroundingCode.includes('zod') ||
            surroundingCode.includes('yup') ||
            surroundingCode.includes('joi');
          
          if (isUntrustedSource && !hasValidation) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'INSECURE_DESERIALIZATION',
              description: 'JSON.parse() on potentially untrusted data without validation',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Validate JSON structure and data types before parsing untrusted input. Use schema validation libraries like Zod or Yup.',
            });
          }
        }
        
        // Check for eval-like deserialization
        if (
          node.callee.type === 'Identifier' &&
          (node.callee.name === 'eval' || node.callee.name === 'Function')
        ) {
          const line = getLineNumber(context.fileContent, node.start || 0);
          
          findings.push({
            ruleId: 'INSECURE_DESERIALIZATION',
            description: `${node.callee.name}() enables arbitrary code execution from data`,
            severity: Severity.HIGH,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Never use eval() or Function() constructor with untrusted data. Use safe alternatives like JSON.parse().',
          });
        }
      },
    });

    return findings;
  },
};

const thirdPartySdkRiskRule: Rule = {
  id: 'THIRD_PARTY_SDK_RISK',
  description: 'Potentially risky third-party SDK detected',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    const content = context.fileContent.toLowerCase();
    
    // Check if this is a sensitive app
    const isSensitiveApp = 
      content.includes('payment') ||
      content.includes('banking') ||
      content.includes('healthcare') ||
      content.includes('medical') ||
      content.includes('financial');

    if (!isSensitiveApp && !context.filePath.includes('package.json')) {
      return findings;
    }

    // Risky SDKs for sensitive apps
    const riskySDKs = [
      { name: 'smartlook', risk: 'Session replay - records user interactions including sensitive input' },
      { name: 'hotjar', risk: 'Session recording and heatmaps - may capture sensitive data' },
      { name: 'fullstory', risk: 'Session replay - captures all user interactions' },
      { name: 'logrocket', risk: 'Session replay with console logs - may expose sensitive data' },
      { name: 'mouseflow', risk: 'Session replay and form analytics' },
      { name: 'crazyegg', risk: 'Heatmaps and session recording' },
      { name: 'appsflyer', risk: 'Attribution tracking - extensive data collection' },
      { name: 'adjust', risk: 'Mobile attribution - tracks user behavior' },
      { name: 'segment', risk: 'Analytics aggregator - forwards data to multiple services' },
    ];

    for (const { name, risk } of riskySDKs) {
      if (content.includes(name)) {
        findings.push({
          ruleId: 'THIRD_PARTY_SDK_RISK',
          description: `Risky SDK detected in sensitive app: ${name} - ${risk}`,
          severity: Severity.LOW,
          filePath: context.filePath,
          line: 1,
          suggestion: `Review ${name} usage in sensitive app. Ensure it doesn't capture/transmit sensitive user data. Consider alternatives or strict configuration.`,
        });
      }
    }

    return findings;
  },
};

export const reactNativeRules: RuleGroup = {
  category: RuleCategory.NETWORK,
  rules: [
    javascriptEnabledBridgeRule,
    insecureDeeplinkHandlerRule,
    screenshotProtectionMissingRule,
    unsafeDangerouslySetInnerHtmlRule,
    networkLoggerInProductionRule,
    evalUsageRule,
    obfuscatedEvalExecutionRule,
    rootJailbreakDetectionAbsentRule,
    missingRuntimeIntegrityChecksRule,
    insecureDeserializationRule,
    thirdPartySdkRiskRule,
  ],
};
