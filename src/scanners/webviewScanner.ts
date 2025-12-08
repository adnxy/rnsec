import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

const webviewJavascriptInjectionRule: Rule = {
  id: 'WEBVIEW_JAVASCRIPT_INJECTION',
  description: 'WebView with JavaScript enabled loading dynamic or user-controlled content',
  severity: Severity.HIGH,
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
          node.openingElement.name.name === 'WebView'
        ) {
          let hasJavaScriptEnabled = false;
          let hasDynamicSource = false;
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'javaScriptEnabled') {
                if (
                  attr.value?.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'BooleanLiteral' &&
                  attr.value.expression.value === true
                ) {
                  hasJavaScriptEnabled = true;
                }
              }
              
              if (attr.name.name === 'source') {
                if (attr.value?.type === 'JSXExpressionContainer') {
                  const expr = attr.value.expression;
                  
                  if (
                    expr.type === 'Identifier' ||
                    expr.type === 'MemberExpression' ||
                    expr.type === 'CallExpression'
                  ) {
                    hasDynamicSource = true;
                  }
                  
                  if (expr.type === 'TemplateLiteral' || expr.type === 'BinaryExpression') {
                    hasDynamicSource = true;
                  }
                }
              }
            }
          });
          
          if (hasJavaScriptEnabled && hasDynamicSource) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'WEBVIEW_JAVASCRIPT_INJECTION',
              description: 'WebView with JavaScript enabled loading dynamic content - potential XSS vulnerability',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Validate and sanitize URLs before loading, use originWhitelist to restrict allowed domains, or disable JavaScript if not needed',
            });
          }
        }
      },
    });

    return findings;
  },
};

const webviewFileAccessRule: Rule = {
  id: 'WEBVIEW_FILE_ACCESS',
  description: 'WebView with file access enabled - allows access to local files',
  severity: Severity.HIGH,
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
          node.openingElement.name.name === 'WebView'
        ) {
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (
                (attr.name.name === 'allowFileAccess' ||
                 attr.name.name === 'allowFileAccessFromFileURLs' ||
                 attr.name.name === 'allowUniversalAccessFromFileURLs') &&
                attr.value?.type === 'JSXExpressionContainer' &&
                attr.value.expression.type === 'BooleanLiteral' &&
                attr.value.expression.value === true
              ) {
                const line = getLineNumber(context.fileContent, node.start || 0);
                
                findings.push({
                  ruleId: 'WEBVIEW_FILE_ACCESS',
                  description: `WebView with ${attr.name.name}={true} - exposes local file system`,
                  severity: Severity.HIGH,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Disable file access unless absolutely necessary. If required, implement strict validation and access controls',
                });
              }
            }
          });
        }
      },
    });

    return findings;
  },
};

const webviewDomStorageRule: Rule = {
  id: 'WEBVIEW_DOM_STORAGE_ENABLED',
  description: 'WebView with DOM storage enabled - may expose sensitive data',
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
          node.openingElement.name.name === 'WebView'
        ) {
          let hasDomStorageEnabled = false;
          let hasJavaScriptEnabled = false;
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'domStorageEnabled') {
                if (
                  attr.value?.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'BooleanLiteral' &&
                  attr.value.expression.value === true
                ) {
                  hasDomStorageEnabled = true;
                }
              }
              
              if (attr.name.name === 'javaScriptEnabled') {
                if (
                  attr.value?.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'BooleanLiteral' &&
                  attr.value.expression.value === true
                ) {
                  hasJavaScriptEnabled = true;
                }
              }
            }
          });
          
          if (hasDomStorageEnabled && hasJavaScriptEnabled) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'WEBVIEW_DOM_STORAGE_ENABLED',
              description: 'WebView with DOM storage and JavaScript enabled - sensitive data may be exposed to XSS',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Avoid storing sensitive data in localStorage/sessionStorage, use secure native storage instead',
            });
          }
        }
      },
    });

    return findings;
  },
};

const webviewGeolocationRule: Rule = {
  id: 'WEBVIEW_GEOLOCATION_ENABLED',
  description: 'WebView with geolocation enabled - requires proper permission handling',
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
          node.openingElement.name.name === 'WebView'
        ) {
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (
                attr.name.name === 'geolocationEnabled' &&
                attr.value?.type === 'JSXExpressionContainer' &&
                attr.value.expression.type === 'BooleanLiteral' &&
                attr.value.expression.value === true
              ) {
                const line = getLineNumber(context.fileContent, node.start || 0);
                
                findings.push({
                  ruleId: 'WEBVIEW_GEOLOCATION_ENABLED',
                  description: 'WebView with geolocation enabled - ensure proper permission handling',
                  severity: Severity.MEDIUM,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Implement onGeolocationPermissionsShowPrompt to properly handle location permissions and user consent',
                });
              }
            }
          });
        }
      },
    });

    return findings;
  },
};

const webviewMixedContentRule: Rule = {
  id: 'WEBVIEW_MIXED_CONTENT',
  description: 'WebView allows mixed content - HTTPS pages can load HTTP resources',
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
          node.openingElement.name.name === 'WebView'
        ) {
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (
                attr.name.name === 'mixedContentMode' &&
                attr.value?.type === 'StringLiteral' &&
                attr.value.value === 'always'
              ) {
                const line = getLineNumber(context.fileContent, node.start || 0);
                
                findings.push({
                  ruleId: 'WEBVIEW_MIXED_CONTENT',
                  description: 'WebView allows mixed content (HTTP resources on HTTPS pages)',
                  severity: Severity.MEDIUM,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Set mixedContentMode to "never" to prevent loading insecure content on HTTPS pages',
                });
              }
            }
          });
        }
      },
    });

    return findings;
  },
};

const webviewUnvalidatedNavigationRule: Rule = {
  id: 'WEBVIEW_UNVALIDATED_NAVIGATION',
  description: 'WebView without URL validation on navigation - potential open redirect',
  severity: Severity.HIGH,
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
          node.openingElement.name.name === 'WebView'
        ) {
          let hasJavaScriptEnabled = false;
          let hasNavigationValidation = false;
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'javaScriptEnabled') {
                if (
                  attr.value?.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'BooleanLiteral' &&
                  attr.value.expression.value === true
                ) {
                  hasJavaScriptEnabled = true;
                }
              }
              
              if (
                attr.name.name === 'onShouldStartLoadWithRequest' ||
                attr.name.name === 'onNavigationStateChange'
              ) {
                hasNavigationValidation = true;
              }
            }
          });
          
          if (hasJavaScriptEnabled && !hasNavigationValidation) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'WEBVIEW_UNVALIDATED_NAVIGATION',
              description: 'WebView without URL validation - vulnerable to open redirect and phishing',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Implement onShouldStartLoadWithRequest to validate URLs before navigation and restrict to trusted domains',
            });
          }
        }
      },
    });

    return findings;
  },
};

const webviewPostMessageRule: Rule = {
  id: 'WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK',
  description: 'WebView onMessage handler without origin validation',
  severity: Severity.HIGH,
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
          node.openingElement.name.name === 'WebView'
        ) {
          let hasOnMessage = false;
          let onMessageHandler: any = null;
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'onMessage') {
                hasOnMessage = true;
                if (attr.value?.type === 'JSXExpressionContainer') {
                  onMessageHandler = attr.value.expression;
                }
              }
            }
          });
          
          if (hasOnMessage && onMessageHandler) {
            let hasOriginCheck = false;
            
            if (
              onMessageHandler.type === 'ArrowFunctionExpression' ||
              onMessageHandler.type === 'FunctionExpression'
            ) {
              const handlerCode = context.fileContent.substring(
                onMessageHandler.start || 0,
                onMessageHandler.end || 0
              );
              
              hasOriginCheck = /origin|nativeEvent\.url|event\.url|source.*url/i.test(handlerCode);
            }
            
            if (!hasOriginCheck) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK',
                description: 'WebView onMessage handler does not validate message origin',
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Always validate event.nativeEvent.url or message origin before processing postMessage data',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const webviewCachingRule: Rule = {
  id: 'WEBVIEW_CACHING_ENABLED',
  description: 'WebView with caching enabled - may cache sensitive content',
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
          node.openingElement.name.name === 'WebView'
        ) {
          let hasCacheEnabled = false;
          let hasAuthHeaders = false;
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'cacheEnabled') {
                if (
                  attr.value?.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'BooleanLiteral' &&
                  attr.value.expression.value === true
                ) {
                  hasCacheEnabled = true;
                }
              }
              
              if (attr.name.name === 'source') {
                const sourceCode = context.fileContent.substring(
                  attr.value?.start || 0,
                  attr.value?.end || 0
                );
                
                if (/header|authorization|token|bearer/i.test(sourceCode)) {
                  hasAuthHeaders = true;
                }
              }
            }
          });
          
          if (hasCacheEnabled && hasAuthHeaders) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'WEBVIEW_CACHING_ENABLED',
              description: 'WebView with caching enabled while loading authenticated content',
              severity: Severity.LOW,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Disable caching for pages with sensitive content or authentication tokens',
            });
          }
        }
      },
    });

    return findings;
  },
};

export const webviewRules: RuleGroup = {
  category: RuleCategory.NETWORK,
  rules: [
    webviewJavascriptInjectionRule,
    webviewFileAccessRule,
    webviewDomStorageRule,
    webviewGeolocationRule,
    webviewMixedContentRule,
    webviewUnvalidatedNavigationRule,
    webviewPostMessageRule,
    webviewCachingRule,
  ],
};
