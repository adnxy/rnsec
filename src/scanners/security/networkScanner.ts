import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';

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
        
        if (
          node.openingElement.name.type === 'JSXIdentifier' &&
          node.openingElement.name.name === 'WebView'
        ) {
          let hasJavaScriptEnabled = false;
          let hasWildcardOrigin = false;
          
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

const noRequestTimeoutRule: Rule = {
  id: 'NO_REQUEST_TIMEOUT',
  description: 'Network request without timeout configuration',
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
        
        // Check for fetch without timeout
        if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
          const optionsArg = node.arguments[1];
          
          if (!optionsArg || optionsArg.type !== 'ObjectExpression') {
            const line = getLineNumber(context.fileContent, node.start || 0);
            findings.push({
              ruleId: 'NO_REQUEST_TIMEOUT',
              description: 'fetch() without timeout - vulnerable to slowloris DoS',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Add timeout to fetch using AbortSignal with setTimeout, or use a library like axios with timeout config.',
            });
          } else {
            // Check if timeout/signal is present
            const hasTimeout = optionsArg.properties.some((prop: any) => 
              prop.key && (prop.key.name === 'signal' || prop.key.name === 'timeout')
            );
            
            if (!hasTimeout) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              findings.push({
                ruleId: 'NO_REQUEST_TIMEOUT',
                description: 'fetch() without timeout configuration',
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Add timeout using AbortSignal: const controller = new AbortController(); setTimeout(() => controller.abort(), 30000);',
              });
            }
          }
        }
        
        // Check for axios without timeout
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.name === 'axios'
        ) {
          const configArg = node.arguments[1] || node.arguments[0];
          
          if (configArg && configArg.type === 'ObjectExpression') {
            const hasTimeout = configArg.properties.some((prop: any) => 
              prop.key && prop.key.name === 'timeout'
            );
            
            if (!hasTimeout) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              findings.push({
                ruleId: 'NO_REQUEST_TIMEOUT',
                description: 'axios request without timeout configuration',
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Add timeout to axios config: { timeout: 30000 } to prevent hanging requests.',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const weakTlsConfigurationRule: Rule = {
  id: 'WEAK_TLS_CONFIGURATION',
  description: 'Weak TLS configuration detected',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    const content = context.fileContent;

    // Check for TLS 1.0/1.1 usage
    if (content.includes('TLSv1.0') || content.includes('TLSv1.1') || content.includes('TLSv1_0') || content.includes('TLSv1_1')) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('TLSv1.0') || lines[i].includes('TLSv1.1') || lines[i].includes('TLSv1_0') || lines[i].includes('TLSv1_1')) {
          findings.push({
            ruleId: 'WEAK_TLS_CONFIGURATION',
            description: 'Weak TLS version (< 1.2) configured - deprecated and insecure',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line: i + 1,
            snippet: lines[i].trim(),
            suggestion: 'Use TLS 1.2 or higher. TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.',
          });
        }
      }
    }

    // Check for insecure httpsAgent configuration
    if (content.includes('httpsAgent') && (content.includes('rejectUnauthorized') || content.includes('secureProtocol'))) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('rejectUnauthorized') && lines[i].includes('false')) {
          findings.push({
            ruleId: 'WEAK_TLS_CONFIGURATION',
            description: 'HTTPS agent with rejectUnauthorized: false - disables certificate validation',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line: i + 1,
            snippet: lines[i].trim(),
            suggestion: 'Never disable certificate validation in production. Remove rejectUnauthorized: false.',
          });
        }
      }
    }

    // Check for weak ciphers
    const weakCiphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
    for (const cipher of weakCiphers) {
      if (content.includes(cipher) && content.toLowerCase().includes('cipher')) {
        findings.push({
          ruleId: 'WEAK_TLS_CONFIGURATION',
          description: `Weak cipher suite detected: ${cipher}`,
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: 1,
          suggestion: `Remove weak cipher ${cipher}. Use strong ciphers like AES-GCM, ChaCha20-Poly1305.`,
        });
        break;
      }
    }

    return findings;
  },
};

const insecureWebSocketRule: Rule = {
  id: 'INSECURE_WEBSOCKET',
  description: 'WebSocket connection using unencrypted ws:// protocol',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      NewExpression(path: any) {
        const { node } = path;

        if (
          node.callee.type === 'Identifier' &&
          node.callee.name === 'WebSocket'
        ) {
          const urlArg = node.arguments[0];

          if (urlArg && urlArg.type === 'StringLiteral' && urlArg.value.startsWith('ws://')) {
            // Skip localhost/dev URLs
            const url = urlArg.value.toLowerCase();
            if (url.includes('localhost') || url.includes('127.0.0.1') || url.includes('10.0.') || url.includes('192.168.')) {
              const surroundingCode = context.fileContent.substring(
                Math.max(0, (node.start || 0) - 200),
                Math.min(context.fileContent.length, (node.end || 0) + 100)
              );
              const hasDevCheck = /__DEV__|process\.env\.NODE_ENV/.test(surroundingCode);
              if (hasDevCheck) return;
            }

            const line = getLineNumber(context.fileContent, node.start || 0);

            findings.push({
              ruleId: 'INSECURE_WEBSOCKET',
              description: `Unencrypted WebSocket connection: "${urlArg.value}"`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use wss:// (WebSocket Secure) instead of ws:// for encrypted WebSocket connections.',
            });
          }
        }
      },

      StringLiteral(path: any) {
        const { node } = path;

        // Also catch ws:// URLs assigned to variables (e.g., const WS_URL = 'ws://...')
        if (node.value.startsWith('ws://') && !node.value.includes('localhost') && !node.value.includes('127.0.0.1')) {
          const parent = path.parent;
          if (
            parent.type === 'VariableDeclarator' ||
            (parent.type === 'ObjectProperty' &&
             parent.key &&
             (parent.key.name || parent.key.value || '').toLowerCase().includes('url'))
          ) {
            const surroundingCode = context.fileContent.substring(
              Math.max(0, (node.start || 0) - 200),
              Math.min(context.fileContent.length, (node.end || 0) + 100)
            );
            const hasDevCheck = /__DEV__|process\.env\.NODE_ENV/.test(surroundingCode);
            if (hasDevCheck) return;

            const line = getLineNumber(context.fileContent, node.start || 0);

            findings.push({
              ruleId: 'INSECURE_WEBSOCKET',
              description: `Unencrypted WebSocket URL configured: "${node.value}"`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use wss:// instead of ws:// for encrypted WebSocket connections.',
            });
          }
        }
      },
    });

    return findings;
  },
};

const hardcodedIpAddressRule: Rule = {
  id: 'HARDCODED_IP_ADDRESS',
  description: 'Hardcoded IP address in production code',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.ast) {
      return findings;
    }

    const filePath = context.filePath.toLowerCase();
    if (
      filePath.includes('.test.') ||
      filePath.includes('.spec.') ||
      filePath.includes('/__tests__/') ||
      filePath.includes('node_modules') ||
      filePath.includes('metro.config') ||
      filePath.includes('.config.')
    ) {
      return findings;
    }

    // Match IP addresses in URLs or standalone
    const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

    traverse(context.ast, {
      StringLiteral(path: any) {
        const { node } = path;
        const value = node.value;

        const match = value.match(ipPattern);
        if (!match) return;

        const ip = match[1];

        // Skip local/private IPs only if behind __DEV__ check
        const isPrivate = ip.startsWith('127.') || ip.startsWith('10.') ||
                          ip.startsWith('192.168.') || ip.startsWith('172.') ||
                          ip === '0.0.0.0' || ip === '255.255.255.255';

        if (isPrivate) {
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 200),
            Math.min(context.fileContent.length, (node.end || 0) + 100)
          );
          const hasDevCheck = /__DEV__|process\.env\.NODE_ENV/.test(surroundingCode);
          if (hasDevCheck) return;
        }

        // Only flag IPs in URL-like context or API config
        const isUrlContext = value.includes('://') || value.includes('http');
        const parent = path.parent;
        const isApiConfig = parent && parent.type === 'ObjectProperty' && parent.key &&
          /url|host|endpoint|server|api|base/i.test(parent.key.name || parent.key.value || '');

        if (isUrlContext || isApiConfig) {
          const line = getLineNumber(context.fileContent, node.start || 0);

          findings.push({
            ruleId: 'HARDCODED_IP_ADDRESS',
            description: `Hardcoded IP address in ${isPrivate ? 'private' : 'public'} network URL: ${ip}`,
            severity: isPrivate ? Severity.LOW : Severity.MEDIUM,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: isPrivate
              ? 'Wrap development IP addresses in __DEV__ check to prevent them from being included in production builds.'
              : 'Use domain names instead of hardcoded IP addresses. Configure server URLs through environment variables.',
          });
        }
      },
    });

    return findings;
  },
};

export const networkRules: RuleGroup = {
  category: RuleCategory.NETWORK,
  rules: [
    insecureHttpUrlRule,
    insecureWebViewRule,
    noRequestTimeoutRule,
    weakTlsConfigurationRule,
    insecureWebSocketRule,
    hardcodedIpAddressRule,
  ],
};
