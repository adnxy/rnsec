/**
 * Network security scanner
 * Detects insecure network patterns
 */

import _traverse from '@babel/traverse';
// Handle ESM/CommonJS interop
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

/**
 * Rule: INSECURE_HTTP_URL
 * Detects HTTP (non-HTTPS) URLs in network calls
 */
const insecureHttpUrlRule: Rule = {
  id: 'INSECURE_HTTP_URL',
  description: 'Insecure HTTP URLs detected in network requests',
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
        
        // Check for fetch() calls
        if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
          const urlArg = node.arguments[0];
          
          if (urlArg && urlArg.type === 'StringLiteral') {
            const url = urlArg.value;
            
            if (url.startsWith('http://')) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'INSECURE_HTTP_URL',
                description: `Insecure HTTP URL detected in fetch: "${url}"`,
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Use HTTPS instead of HTTP for all network requests',
              });
            }
          }
        }
        
        // Check for axios calls
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'axios'
        ) {
          const urlArg = node.arguments[0];
          
          if (urlArg && urlArg.type === 'StringLiteral') {
            const url = urlArg.value;
            
            if (url.startsWith('http://')) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'INSECURE_HTTP_URL',
                description: `Insecure HTTP URL detected in axios: "${url}"`,
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Use HTTPS instead of HTTP for all network requests',
              });
            }
          }
        }
      },
      
      // Check for baseURL in axios.create
      ObjectProperty(path: any) {
        const { node } = path;
        
        if (
          (node.key.type === 'Identifier' && node.key.name === 'baseURL') &&
          node.value.type === 'StringLiteral'
        ) {
          const url = node.value.value;
          
          if (url.startsWith('http://')) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'INSECURE_HTTP_URL',
              description: `Insecure HTTP baseURL detected: "${url}"`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use HTTPS instead of HTTP for all network requests',
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Rule: INSECURE_WEBVIEW
 * Detects WebView with insecure configuration
 */
const insecureWebViewRule: Rule = {
  id: 'INSECURE_WEBVIEW',
  description: 'WebView with insecure configuration detected',
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
        
        // Check if it's a WebView component
        if (
          node.openingElement.name.type === 'JSXIdentifier' &&
          node.openingElement.name.name === 'WebView'
        ) {
          let hasJavaScriptEnabled = false;
          let hasWildcardOrigin = false;
          
          // Check attributes
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'javaScriptEnabled') {
                if (
                  attr.value &&
                  attr.value.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'BooleanLiteral' &&
                  attr.value.expression.value === true
                ) {
                  hasJavaScriptEnabled = true;
                }
              }
              
              if (attr.name.name === 'originWhitelist') {
                if (
                  attr.value &&
                  attr.value.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'ArrayExpression'
                ) {
                  attr.value.expression.elements.forEach((el: any) => {
                    if (el && el.type === 'StringLiteral' && el.value === '*') {
                      hasWildcardOrigin = true;
                    }
                  });
                }
              }
            }
          });
          
          // If both conditions are met, flag it
          if (hasJavaScriptEnabled && hasWildcardOrigin) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'INSECURE_WEBVIEW',
              description: 'WebView with javaScriptEnabled and wildcard originWhitelist',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Restrict originWhitelist to specific domains and disable JavaScript if not needed',
            });
          }
        }
      },
    });

    return findings;
  },
};

export const networkRules: RuleGroup = {
  category: RuleCategory.NETWORK,
  rules: [insecureHttpUrlRule, insecureWebViewRule],
};

