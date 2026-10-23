import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';

/** Package name of an import specifier ("lodash/fp" -> "lodash", "@a/b/c" -> "@a/b"); null for relative/absolute paths */
function packageNameOf(specifier: string): string | null {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/')) return null;
  const parts = specifier.split('/');
  return specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

/** Package names a JS/TS file imports, requires or dynamically imports */
function collectImportedPackages(ast: any): Set<string> {
  const found = new Set<string>();
  const add = (spec: unknown) => {
    if (typeof spec !== 'string') return;
    const name = packageNameOf(spec);
    if (name) found.add(name);
  };
  traverse(ast, {
    ImportDeclaration(path: any) {
      add(path.node.source?.value);
    },
    ExportNamedDeclaration(path: any) {
      add(path.node.source?.value);
    },
    ExportAllDeclaration(path: any) {
      add(path.node.source?.value);
    },
    CallExpression(path: any) {
      const { node } = path;
      const isRequire = node.callee.type === 'Identifier' && node.callee.name === 'require';
      if ((isRequire || node.callee.type === 'Import') && node.arguments[0]?.type === 'StringLiteral') {
        add(node.arguments[0].value);
      }
    },
  });
  return found;
}

/** A string literal or a template literal without interpolation */
function isStaticString(node: any): boolean {
  return !!node && (node.type === 'StringLiteral' || (node.type === 'TemplateLiteral' && node.expressions.length === 0));
}

/** eval("...") / new Function("...") where every argument is a constant string */
function hasOnlyLiteralArguments(node: any): boolean {
  return node.arguments.length > 0 && node.arguments.every((arg: any) => isStaticString(arg));
}

/** Split an identifier into lowercase words: "checkUrl" -> [check, url], "is_valid" -> [is, valid] */
function identifierWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map(w => w.toLowerCase());
}

/**
 * Libraries (declared in package.json or imported by the entry file) that already perform
 * root/jailbreak detection. react-native-device-info is deliberately NOT here: it only
 * reports emulators, not rooted/jailbroken devices.
 */
const ROOT_JAILBREAK_DETECTION_LIBS = new Set([
  'jail-monkey',
  'jail-monkey-fork',
  'react-native-jail-monkey',
  '@freerasp/react-native',
  'freerasp-react-native',
  'expo-device',
  'rn-root-detection',
  'react-native-root-detection',
  'react-native-root-check',
  'react-native-root-beer',
  'react-native-jailbreak-detect',
  'jail-monkey-plus',
  'react-native-ios-jailbreak-detection',
  'react-native-ios-jailbreak-detector',
  'react-native-device-integrity',
  '@approov/react-native-approov',
  'react-native-talsec',
]);

/** Libraries providing runtime integrity / attestation / tamper detection */
const RUNTIME_INTEGRITY_LIBS = new Set([
  '@freerasp/react-native',
  'freerasp-react-native',
  'react-native-talsec',
  'jail-monkey',
  'jail-monkey-fork',
  'react-native-jail-monkey',
  'react-native-play-integrity',
  'react-native-google-play-integrity',
  '@react-native-google-signin/play-integrity',
  'react-native-app-attest',
  '@expo/app-integrity',
  'expo-app-integrity',
  'react-native-device-check',
  'react-native-safetynet',
  'react-native-google-safetynet',
  '@react-native-firebase/app-check',
  '@approov/react-native-approov',
  'react-native-device-integrity',
]);

/** Packages whose presence is a strong signal of a payments/banking/health/crypto-wallet app */
const HIGH_RISK_DOMAIN_LIBS = new Set([
  'stripe',
  '@stripe/stripe-react-native',
  '@stripe/stripe-js',
  'react-native-plaid-link-sdk',
  'plaid',
  'react-native-iap',
  'react-native-payments',
  'react-native-google-pay',
  '@paypal/react-native-paypal',
  'react-native-paypal',
  'braintree-web',
  'react-native-braintree-dropin-ui',
  '@adyen/react-native',
  'ethers',
  'web3',
  '@solana/web3.js',
  '@walletconnect/client',
  '@walletconnect/web3-provider',
  '@walletconnect/react-native-compat',
  '@web3modal/ethers5-react-native',
  'react-native-health',
  'react-native-health-connect',
  '@kingstinct/react-native-healthkit',
  'react-native-google-fit',
  'expo-health',
]);

const isEntryFile = (filePath: string, rootDir?: string): boolean => {
  let rel = filePath.replace(/\\/g, '/');
  if (rootDir) {
    const root = rootDir.replace(/\\/g, '/').replace(/\/$/, '');
    if (rel.startsWith(root + '/')) rel = rel.slice(root.length + 1);
    return /^(src\/)?(index|App)\.(js|jsx|ts|tsx)$/.test(rel);
  }
  // No root known: basename only
  return /(^|\/)(index|App)\.(js|jsx|ts|tsx)$/.test(rel);
};

/** Shared gate for the two "absence" rules: entry file of an app that signals a high-risk domain */
function analyseAbsenceContext(context: RuleContext, protectiveLibs: Set<string>) {
  if (!context.ast || !isEntryFile(context.filePath, context.project?.rootDir)) {
    return { applicable: false, protectedByLib: false };
  }
  const imported = collectImportedPackages(context.ast);
  const declared = context.project?.dependencies ?? new Set<string>();
  const has = (set: Set<string>) =>
    [...set].some(lib => declared.has(lib) || imported.has(lib));
  return {
    applicable: has(HIGH_RISK_DOMAIN_LIBS),
    protectedByLib: has(protectiveLibs),
  };
}

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

/** Words that indicate a deep-link URL is being validated (matched against identifier words, never comments) */
const DEEPLINK_VALIDATION_WORDS = new Set([
  'validate', 'validated', 'validation', 'valid', 'sanitize', 'sanitized',
  'whitelist', 'allowlist', 'allowed', 'trusted', 'verify', 'verified', 'check', 'safe',
]);
/** Reading these from a parsed URL means the code looks at scheme/host before acting */
const URL_PART_PROPERTIES = new Set(['hostname', 'host', 'protocol', 'origin']);

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

    const isLinkingCall = (callee: any, names: string[]) =>
      callee.type === 'MemberExpression' &&
      callee.object.type === 'Identifier' &&
      callee.object.name === 'Linking' &&
      callee.property.type === 'Identifier' &&
      names.includes(callee.property.name);

    const report = (node: any, confidence: 'high' | 'low') => {
      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'INSECURE_DEEPLINK_HANDLER',
        description: confidence === 'low'
          ? 'Deep link handler could not be inspected (defined elsewhere) - verify it validates the URL'
          : 'Deep link handled without URL validation',
        severity: Severity.HIGH,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Validate deep link URLs against a whitelist of allowed schemes and paths before navigation',
        ...(confidence === 'low' ? { confidence: 'low' as const } : {}),
      });
    };

    /** Inspect a handler expression. Returns true when it validates, false when not, null when unknown */
    const handlerValidates = (handlerPath: any): boolean | null => {
      let target = handlerPath;
      if (target.isIdentifier()) {
        const binding = target.scope.getBinding(target.node.name);
        if (!binding) return null;
        const bp = binding.path;
        if (bp.isFunctionDeclaration()) target = bp;
        else if (bp.isVariableDeclarator() && bp.get('init').node &&
                 (bp.get('init').isArrowFunctionExpression() || bp.get('init').isFunctionExpression())) {
          target = bp.get('init');
        } else return null;
      }
      if (!target.isFunction()) return null;
      let validated = false;
      target.traverse({
        Identifier(p: any) {
          if (identifierWords(p.node.name).some(w => DEEPLINK_VALIDATION_WORDS.has(w))) validated = true;
        },
        MemberExpression(p: any) {
          const prop = p.node.property;
          if (!p.node.computed && prop.type === 'Identifier' && URL_PART_PROPERTIES.has(prop.name)) validated = true;
        },
      });
      // Parameters are Identifiers visited by the traversal only for nested nodes; check own name too
      return validated;
    };

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;

        if (isLinkingCall(node.callee, ['addEventListener'])) {
          const handler = path.get('arguments.1');
          if (!handler || !handler.node) return;
          const result = handlerValidates(handler);
          if (result === null) report(node, 'low');
          else if (!result) report(node, 'high');
          return;
        }

        // Linking.getInitialURL().then(handler)
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'then' &&
          node.callee.object.type === 'CallExpression' &&
          isLinkingCall(node.callee.object.callee, ['getInitialURL'])
        ) {
          const handler = path.get('arguments.0');
          if (!handler || !handler.node) return;
          const result = handlerValidates(handler);
          if (result === null) report(node, 'low');
          else if (!result) report(node, 'high');
        }
      },
    });

    return findings;
  },
};

const screenshotProtectionMissingRule: Rule = {
  id: 'SCREENSHOT_PROTECTION_MISSING',
  description: 'Sensitive screen without screenshot/screen recording protection',
  severity: Severity.MEDIUM,
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

/** Callee names/members that sanitize HTML */
const HTML_SANITIZER_CALLEES = /^(DOMPurify\.sanitize|purify\.sanitize|sanitizeHtml|sanitize|xss|filterXSS|escapeHtml)$/;
const HTML_SANITIZER_PACKAGES = new Set(['dompurify', 'isomorphic-dompurify', 'sanitize-html', 'xss', 'insane', 'escape-html']);

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

    const sanitizerPackages = new Set<string>();
    traverse(context.ast, {
      ImportDeclaration(path: any) {
        const name = packageNameOf(path.node.source.value);
        if (name && HTML_SANITIZER_PACKAGES.has(name)) {
          path.node.specifiers.forEach((sp: any) => sanitizerPackages.add(sp.local.name));
        }
      },
    });

    const calleeText = (callee: any): string | null => {
      if (callee.type === 'Identifier') return callee.name;
      if (callee.type === 'MemberExpression' && !callee.computed &&
          callee.object.type === 'Identifier' && callee.property.type === 'Identifier') {
        return `${callee.object.name}.${callee.property.name}`;
      }
      return null;
    };

    const isSanitizerCall = (node: any): boolean => {
      if (!node || node.type !== 'CallExpression') return false;
      const text = calleeText(node.callee);
      if (!text) return false;
      if (HTML_SANITIZER_CALLEES.test(text)) return true;
      const root = text.split('.')[0];
      return sanitizerPackages.has(root);
    };

    /** 'literal' | 'sanitized' | 'unknown' for the __html value expression */
    const classify = (valuePath: any, depth = 0): 'literal' | 'sanitized' | 'unknown' => {
      const node = valuePath.node;
      if (isStaticString(node)) return 'literal';
      if (isSanitizerCall(node)) return 'sanitized';
      if (node.type === 'Identifier' && depth < 3) {
        const binding = valuePath.scope.getBinding(node.name);
        if (binding && binding.constant && binding.path.isVariableDeclarator() && binding.path.node.init) {
          return classify(binding.path.get('init'), depth + 1);
        }
      }
      return 'unknown';
    };

    traverse(context.ast, {
      JSXAttribute(path: any) {
        const { node } = path;
        
        if (
          node.name.type === 'JSXIdentifier' &&
          node.name.name === 'dangerouslySetInnerHTML'
        ) {
          if (node.value && node.value.type === 'JSXExpressionContainer') {
            let verdict: 'literal' | 'sanitized' | 'unknown' = 'unknown';
            const expr = path.get('value.expression');
            if (expr.node.type === 'ObjectExpression') {
              const htmlProp = expr.get('properties').find((pp: any) =>
                pp.isObjectProperty() && !pp.node.computed &&
                ((pp.node.key.type === 'Identifier' && pp.node.key.name === '__html') ||
                 (pp.node.key.type === 'StringLiteral' && pp.node.key.value === '__html'))
              );
              if (htmlProp) verdict = classify(htmlProp.get('value'));
            }

            const start = Math.max(0, (node.start || 0) - 200);
            const end = Math.min(context.fileContent.length, (node.end || 0) + 200);
            const nearbySanitizer = /sanitize|dompurify|xss|escape/i.test(context.fileContent.substring(start, end));

            const line = getLineNumber(context.fileContent, node.start || 0);
            if (verdict === 'literal' || verdict === 'sanitized') {
              findings.push({
                ruleId: 'UNSAFE_DANGEROUSLY_SET_INNER_HTML',
                description: verdict === 'literal'
                  ? 'dangerouslySetInnerHTML with a constant string - no injection path, but prefer plain components'
                  : 'dangerouslySetInnerHTML with sanitized content - verify the sanitizer configuration',
                severity: Severity.LOW,
                confidence: 'medium',
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Keep the sanitizer allow-list strict and avoid dangerouslySetInnerHTML where plain components work',
              });
            } else if (nearbySanitizer) {
              // A sanitizer is mentioned nearby but we cannot prove it feeds __html
              findings.push({
                ruleId: 'UNSAFE_DANGEROUSLY_SET_INNER_HTML',
                description: 'dangerouslySetInnerHTML - a sanitizer appears nearby but could not be linked to the rendered value',
                severity: Severity.LOW,
                confidence: 'low',
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Pass the value through DOMPurify.sanitize (or similar) directly in the __html expression',
              });
            } else {
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

    const report = (node: any, name: string) => {
      // A constant string cannot carry attacker-controlled input
      if (hasOnlyLiteralArguments(node)) return;
      const line = getLineNumber(context.fileContent, node.start || 0);
      
      findings.push({
        ruleId: 'EVAL_USAGE',
        description: `Dangerous ${name}() usage detected - code injection risk`,
        severity: Severity.HIGH,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Avoid eval() and Function() constructor. Use JSON.parse() for JSON data or refactor code',
      });
    };

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'Identifier' &&
          (node.callee.name === 'eval' || node.callee.name === 'Function')
        ) {
          report(node, node.callee.name);
        }
      },
      NewExpression(path: any) {
        const { node } = path;
        if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
          report(node, 'new Function');
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
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    // Decided per project: only the app entry file, only for a high-risk domain
    // (payments/banking/health/crypto wallet), and only without a detection library.
    const { applicable, protectedByLib } = analyseAbsenceContext(context, ROOT_JAILBREAK_DETECTION_LIBS);
    if (!applicable || protectedByLib) {
      return findings;
    }

    // Hand-rolled checks in the entry file count too
    if (/\b(jailmonkey|isJailBroken|isRooted|isJailbroken|jailbreakTest|rootDetection)\b/i.test(context.fileContent)) {
      return findings;
    }

    findings.push({
      ruleId: 'ROOT_JAILBREAK_DETECTION_ABSENT',
      description: 'Payments/banking/health/crypto-wallet app without a root/jailbreak detection library',
      severity: Severity.LOW,
      confidence: 'low',
      filePath: context.filePath,
      line: 1,
      suggestion: 'Consider root/jailbreak detection (jail-monkey, freeRASP) and warn or restrict functionality on compromised devices. Detection is bypassable, so treat it as defence in depth.',
    });

    return findings;
  },
};

const missingRuntimeIntegrityChecksRule: Rule = {
  id: 'MISSING_RUNTIME_INTEGRITY_CHECKS',
  description: 'No runtime integrity or tamper detection implemented',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    const { applicable, protectedByLib } = analyseAbsenceContext(context, RUNTIME_INTEGRITY_LIBS);
    if (!applicable || protectedByLib) {
      return findings;
    }

    if (/playintegrity|safetynet|appattest|devicecheck|tamperdetection|checksignature|verifysignature/i.test(context.fileContent)) {
      return findings;
    }

    findings.push({
      ruleId: 'MISSING_RUNTIME_INTEGRITY_CHECKS',
      description: 'Payments/banking/health/crypto-wallet app without runtime integrity or tamper detection',
      severity: Severity.LOW,
      confidence: 'low',
      filePath: context.filePath,
      line: 1,
      suggestion: 'Consider Play Integrity API (Android), App Attest (iOS) or freeRASP to detect tampering, and verify attestation on your backend.',
    });

    return findings;
  },
};

const insecureDeserializationRule: Rule = {
  id: 'INSECURE_DESERIALIZATION',
  description: 'Unsafe deserialization of untrusted data (eval/Function on dynamic input)',
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
        
        // JSON.parse is not reported: it cannot execute code, and a keyword-near-the-call heuristic
        // ("api", "url", "response") fired on virtually every parse of a network response.

        // Check for eval-like deserialization
        if (
          node.callee.type === 'Identifier' &&
          (node.callee.name === 'eval' || node.callee.name === 'Function') &&
          !hasOnlyLiteralArguments(node)
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

/** Risky SDKs, matched against package names (never against file text) */
const RISKY_SDKS: Array<{ name: string; pattern: RegExp; risk: string }> = [
  { name: 'smartlook', pattern: /^(smartlook-client|react-native-smartlook.*|@smartlook\/.+)$/, risk: 'Session replay - records user interactions including sensitive input' },
  { name: 'hotjar', pattern: /^(@hotjar\/.+|react-native-hotjar.*)$/, risk: 'Session recording and heatmaps - may capture sensitive data' },
  { name: 'fullstory', pattern: /^(@fullstory\/.+|react-native-fullstory.*)$/, risk: 'Session replay - captures all user interactions' },
  { name: 'logrocket', pattern: /^(logrocket|logrocket-.+|@logrocket\/.+)$/, risk: 'Session replay with console logs - may expose sensitive data' },
  { name: 'mouseflow', pattern: /^(mouseflow.*|react-native-mouseflow.*)$/, risk: 'Session replay and form analytics' },
  { name: 'crazyegg', pattern: /^(crazyegg.*|react-native-crazyegg.*)$/, risk: 'Heatmaps and session recording' },
  { name: 'appsflyer', pattern: /^(react-native-appsflyer|appsflyer-.+|@appsflyer\/.+)$/, risk: 'Attribution tracking - extensive data collection' },
  { name: 'adjust', pattern: /^(react-native-adjust|@adjust\/.+|adjust-.+-sdk)$/, risk: 'Mobile attribution - tracks user behavior' },
  { name: 'segment', pattern: /^(@segment\/.+|analytics-react-native|react-native-segment.*)$/, risk: 'Analytics aggregator - forwards data to multiple services' },
];

const thirdPartySdkRiskRule: Rule = {
  id: 'THIRD_PARTY_SDK_RISK',
  description: 'Potentially risky third-party SDK detected',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    const make = (sdk: { name: string; risk: string }, line: number): Finding => ({
      ruleId: 'THIRD_PARTY_SDK_RISK',
      description: `Risky SDK detected: ${sdk.name} - ${sdk.risk}`,
      severity: Severity.LOW,
      confidence: 'medium',
      filePath: context.filePath,
      line,
      suggestion: `Review ${sdk.name} usage in sensitive app. Ensure it doesn't capture/transmit sensitive user data. Consider alternatives or strict configuration.`,
    });

    // package.json: report each declared SDK once, at its declaration
    if (context.config && context.filePath.endsWith('package.json')) {
      const declared = new Set<string>();
      for (const section of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
        const deps = context.config[section];
        if (deps && typeof deps === 'object') Object.keys(deps).forEach(d => declared.add(d));
      }
      const lines = context.fileContent.split('\n');
      const reported = new Set<string>(); // one finding per SDK even if it ships several packages
      for (const pkg of declared) {
        const sdk = RISKY_SDKS.find(s => s.pattern.test(pkg));
        if (!sdk || reported.has(sdk.name)) continue;
        reported.add(sdk.name);
        const idx = lines.findIndex(l => l.includes(`"${pkg}"`));
        findings.push(make(sdk, idx === -1 ? 1 : idx + 1));
      }
      return findings;
    }

    // Source files: fallback for SDKs not declared in the root package.json (monorepo packages,
    // no manifest). Only when the file also talks about a sensitive domain.
    if (!context.ast) {
      return findings;
    }
    if (!/\b(payments?|banking|healthcare|medical|financial)\b/i.test(context.fileContent)) {
      return findings;
    }
    const declaredRoot = context.project?.dependencies ?? new Set<string>();
    const reported = new Set<string>();
    for (const pkg of collectImportedPackages(context.ast)) {
      if (declaredRoot.has(pkg)) continue; // reported on package.json instead
      const sdk = RISKY_SDKS.find(s => s.pattern.test(pkg));
      if (!sdk || reported.has(sdk.name)) continue;
      reported.add(sdk.name);
      findings.push(make(sdk, 1));
    }

    return findings;
  },
};

const expoUpdatesNoCodeSigningRule: Rule = {
  id: 'EXPO_UPDATES_NO_CODE_SIGNING',
  description: 'Expo OTA updates configured without code signing verification',
  severity: Severity.HIGH,
  fileTypes: ['.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.config || !context.filePath.includes('app.json')) {
      return findings;
    }

    const expo = context.config.expo;
    if (!expo) {
      return findings;
    }

    const hasUpdates = expo.updates || expo.runtimeVersion;
    const hasExpoUpdatesPlugin = expo.plugins?.some((p: any) =>
      (typeof p === 'string' && p === 'expo-updates') ||
      (Array.isArray(p) && p[0] === 'expo-updates')
    );

    if (hasUpdates || hasExpoUpdatesPlugin) {
      const updatesConfig = expo.updates || {};
      const hasCodeSigning = updatesConfig.codeSigningCertificate ||
                             updatesConfig.codeSigningMetadata;

      if (!hasCodeSigning) {
        findings.push({
          ruleId: 'EXPO_UPDATES_NO_CODE_SIGNING',
          description: 'Expo OTA updates enabled without code signing - updates can be tampered with',
          severity: Severity.HIGH,
          filePath: context.filePath,
          suggestion: 'Enable code signing for Expo updates to prevent tampered OTA updates. Configure codeSigningCertificate in updates config.',
        });
      }
    }

    return findings;
  },
};

const insecureLinkingOpenRule: Rule = {
  id: 'INSECURE_LINKING_OPEN',
  description: 'Linking.openURL called with unvalidated user-controlled input',
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
          node.callee.property.name === 'openURL'
        ) {
          const arg = node.arguments[0];

          // Only flag dynamic/variable URLs, not string literals
          if (arg && arg.type !== 'StringLiteral') {
            const surroundingCode = context.fileContent.substring(
              Math.max(0, (node.start || 0) - 300),
              Math.min(context.fileContent.length, (node.end || 0) + 100)
            );

            const hasValidation = /validate|sanitize|whitelist|allowedSchemes|allowedDomains|canOpenURL|startsWith\s*\(\s*['"]https/i.test(surroundingCode);

            if (!hasValidation) {
              const line = getLineNumber(context.fileContent, node.start || 0);

              findings.push({
                ruleId: 'INSECURE_LINKING_OPEN',
                description: 'Linking.openURL with unvalidated URL - may open malicious schemes (tel:, sms:, custom://)',
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Validate URL scheme against an allowlist before calling Linking.openURL. Use Linking.canOpenURL() first and restrict to https:// URLs.',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const sensitiveNavigationParamsRule: Rule = {
  id: 'SENSITIVE_NAVIGATION_PARAMS',
  description: 'Sensitive data passed through React Navigation params',
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

        // Match navigation.navigate('Screen', { ... }) or navigation.push('Screen', { ... })
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          (node.callee.property.name === 'navigate' || node.callee.property.name === 'push')
        ) {
          const paramsArg = node.arguments[1];

          if (paramsArg && paramsArg.type === 'ObjectExpression') {
            for (const prop of paramsArg.properties) {
              if (prop.type !== 'ObjectProperty' || !prop.key) continue;

              const keyName = prop.key.type === 'Identifier' ? prop.key.name :
                             (prop.key.type === 'StringLiteral' ? prop.key.value : '');
              const lowerKey = keyName.toLowerCase();

              const sensitiveKeys = ['password', 'token', 'secret', 'apikey', 'api_key', 'accesstoken',
                                     'access_token', 'refreshtoken', 'refresh_token', 'pin', 'cvv', 'ssn',
                                     'creditcard', 'cardnumber'];

              if (sensitiveKeys.some(k => lowerKey.includes(k))) {
                const line = getLineNumber(context.fileContent, node.start || 0);

                findings.push({
                  ruleId: 'SENSITIVE_NAVIGATION_PARAMS',
                  description: `Sensitive data "${keyName}" passed via navigation params - persisted in navigation state`,
                  severity: Severity.MEDIUM,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Avoid passing sensitive data through navigation params as they are serialized and may persist in navigation state. Use secure storage or context/state management instead.',
                });
                break;
              }
            }
          }
        }
      },
    });

    return findings;
  },
};

const pushNotificationSensitiveDataRule: Rule = {
  id: 'PUSH_NOTIFICATION_SENSITIVE_DATA',
  description: 'Push notification handler processing sensitive data without protection',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.ast) {
      return findings;
    }

    // Check if file imports push notification libraries
    let hasPushImport = false;

    traverse(context.ast, {
      ImportDeclaration(path: any) {
        const { node } = path;
        if (node.source && node.source.value) {
          const source = node.source.value.toLowerCase();
          if (
            source.includes('expo-notifications') ||
            source.includes('react-native-push-notification') ||
            source.includes('@react-native-firebase/messaging') ||
            source.includes('react-native-firebase') && source.includes('messaging') ||
            source.includes('@notifee')
          ) {
            hasPushImport = true;
          }
        }
      },
    });

    if (!hasPushImport) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;

        // Check for notification listeners that log or store sensitive data
        const isNotificationListener =
          (node.callee.type === 'MemberExpression' &&
           node.callee.property.type === 'Identifier' &&
           (node.callee.property.name === 'addNotificationReceivedListener' ||
            node.callee.property.name === 'addNotificationResponseReceivedListener' ||
            node.callee.property.name === 'onMessage' ||
            node.callee.property.name === 'onNotification'));

        if (isNotificationListener && node.arguments.length > 0) {
          const callback = node.arguments[0];
          if (callback) {
            const callbackCode = context.fileContent.substring(
              callback.start || 0,
              Math.min(context.fileContent.length, (callback.end || 0) + 200)
            ).toLowerCase();

            const logsSensitiveData = /console\.(log|info|debug|warn)/.test(callbackCode) &&
              /notification\.request\.content\.data|notification\.data|remoteMessage\.data/i.test(callbackCode);

            const storesInsecurely = /asyncstorage/i.test(callbackCode) &&
              (callbackCode.includes('token') || callbackCode.includes('password') || callbackCode.includes('secret'));

            if (logsSensitiveData || storesInsecurely) {
              const line = getLineNumber(context.fileContent, node.start || 0);

              findings.push({
                ruleId: 'PUSH_NOTIFICATION_SENSITIVE_DATA',
                description: 'Push notification data logged or stored insecurely - notifications may contain sensitive payloads',
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Avoid sending sensitive data in push notification payloads. If required, encrypt payloads and store securely. Never log notification data in production.',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const expoAuthSessionNoPkceRule: Rule = {
  id: 'EXPO_AUTH_SESSION_NO_PKCE',
  description: 'Expo AuthSession used without PKCE (Proof Key for Code Exchange)',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.ast) {
      return findings;
    }

    let hasAuthSessionImport = false;

    traverse(context.ast, {
      ImportDeclaration(path: any) {
        const { node } = path;
        const source = node.source?.value;
        if (typeof source === 'string' && (source === 'expo-auth-session' || source.startsWith('expo-auth-session/'))) {
          hasAuthSessionImport = true;
        }
      },
    });

    if (!hasAuthSessionImport) {
      return findings;
    }

    // Any `usePKCE: false` option in a file that uses expo-auth-session (useAuthRequest, startAsync,
    // new AuthRequest, a config object passed on later). Reported on the property's own line.
    traverse(context.ast, {
      ObjectProperty(path: any) {
        const { node } = path;
        if (
          !node.computed &&
          node.key &&
          (node.key.name === 'usePKCE' || node.key.value === 'usePKCE') &&
          node.value && node.value.type === 'BooleanLiteral' && node.value.value === false
        ) {
          const line = getLineNumber(context.fileContent, node.start || 0);

          findings.push({
            ruleId: 'EXPO_AUTH_SESSION_NO_PKCE',
            description: 'AuthSession with PKCE explicitly disabled - vulnerable to authorization code interception',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Enable PKCE (usePKCE: true) for OAuth flows. PKCE prevents authorization code interception attacks on mobile apps.',
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
    expoUpdatesNoCodeSigningRule,
    insecureLinkingOpenRule,
    sensitiveNavigationParamsRule,
    pushNotificationSensitiveDataRule,
    expoAuthSessionNoPkceRule,
  ],
};
