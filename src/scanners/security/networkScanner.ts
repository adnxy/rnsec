import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { isLocalOrPrivateHost, classifyIpv4 } from '../../utils/hostUtils.js';
import { isNonProductionPath } from '../../utils/pathFilters.js';

interface UrlPrefix {
  text: string;
  /** true when `text` is the whole URL (no interpolated or concatenated parts) */
  complete: boolean;
}

/** Leading literal text of a string, template literal or `'http://x' + y` concatenation. */
function literalUrlPrefix(node: any): UrlPrefix | null {
  if (!node) return null;
  if (node.type === 'StringLiteral') return { text: node.value, complete: true };
  if (node.type === 'TemplateLiteral') {
    const first = node.quasis?.[0]?.value?.cooked;
    return typeof first === 'string' ? { text: first, complete: node.quasis.length === 1 } : null;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = literalUrlPrefix(node.left);
    return left ? { text: left.text, complete: false } : null;
  }
  return null;
}

/** Plain http:// URL that is not obviously a local/private development address. */
function isInsecurePublicHttpUrl(prefix: UrlPrefix | null, schemes: RegExp = /^http:\/\//i): boolean {
  if (!prefix || !schemes.test(prefix.text)) return false;
  const rest = prefix.text.slice(prefix.text.indexOf('://') + 3);
  // `http://${host}/x` or `'http://' + host`: the host is not visible, do not guess.
  if (!prefix.complete && !/[:/?#]/.test(rest)) return false;
  // only the visible host matters (`http://[::1]:${port}/x` -> `[::1]`)
  const hostPart = rest.startsWith('[') ? rest.slice(0, rest.indexOf(']') + 1) : rest.split(/[:/?#]/)[0];
  return !isLocalOrPrivateHost(`http://${hostPart}`);
}

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

    const report = (node: any, description: string) => {
      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'INSECURE_HTTP_URL',
        description,
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Use HTTPS instead of HTTP for all network requests',
      });
    };

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
          const prefix = literalUrlPrefix(node.arguments[0]);
          if (isInsecurePublicHttpUrl(prefix)) {
            report(node, `Insecure HTTP URL detected in fetch: "${prefix!.text}"`);
          }
        }
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'axios'
        ) {
          const prefix = literalUrlPrefix(node.arguments[0]);
          if (isInsecurePublicHttpUrl(prefix)) {
            report(node, `Insecure HTTP URL detected in axios: "${prefix!.text}"`);
          }
        }
      },
      
      ObjectProperty(path: any) {
        const { node } = path;
        
        if (node.key.type === 'Identifier' && node.key.name === 'baseURL') {
          const prefix = literalUrlPrefix(node.value);
          if (isInsecurePublicHttpUrl(prefix)) {
            report(node, `Insecure HTTP baseURL detected: "${prefix!.text}"`);
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

function isMember(node: any, object: string, property: string): boolean {
  return (
    node?.type === 'MemberExpression' &&
    node.object?.type === 'Identifier' && node.object.name === object &&
    !node.computed && node.property?.name === property
  );
}

/**
 * Does this subtree bound request time? AbortSignal.timeout, AbortController + a timer,
 * Promise.race with a timer, or a `timeout` option/assignment.
 */
function subtreeHasTimeoutGuard(root: any): boolean {
  let abortController = false;
  let timer = false;
  let race = false;
  let timeoutOption = false;
  let abortSignalTimeout = false;

  const visit = (node: any) => {
    if (!node || typeof node.type !== 'string') return;
    if (isMember(node, 'AbortSignal', 'timeout')) abortSignalTimeout = true;
    if (isMember(node, 'Promise', 'race')) race = true;
    if (node.type === 'Identifier') {
      if (node.name === 'AbortController') abortController = true;
      if (node.name === 'setTimeout' || node.name === 'timeout') timer = true;
    }
    if (
      (node.type === 'ObjectProperty' || node.type === 'ObjectMethod') &&
      !node.computed && (node.key?.name === 'timeout' || node.key?.value === 'timeout')
    ) {
      timeoutOption = true;
    }
    if (node.type === 'AssignmentExpression' && node.left?.type === 'MemberExpression' && node.left.property?.name === 'timeout') {
      timeoutOption = true;
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments') continue;
      const child = node[key];
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child.type === 'string') visit(child);
    }
  };
  visit(root);

  return abortSignalTimeout || timeoutOption || (abortController && timer) || (race && timer);
}

const noRequestTimeoutRule: Rule = {
  id: 'NO_REQUEST_TIMEOUT',
  description: 'Network request without timeout configuration',
  // A hanging server can only stall the user's own request on a mobile client: low impact.
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    // axios.create({ timeout }) / axios.defaults.timeout = ... anywhere in the file covers its axios calls.
    let axiosDefaultTimeout = false;
    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        if (
          isMember(node.callee, 'axios', 'create') &&
          node.arguments[0]?.type === 'ObjectExpression' &&
          subtreeHasTimeoutGuard(node.arguments[0])
        ) {
          axiosDefaultTimeout = true;
        }
      },
      AssignmentExpression(path: any) {
        const { left } = path.node;
        if (
          left.type === 'MemberExpression' && left.property?.name === 'timeout' &&
          left.object?.type === 'MemberExpression' && left.object.property?.name === 'defaults'
        ) {
          axiosDefaultTimeout = true;
        }
      },
    });

    const guardedByEnclosingFunction = (path: any): boolean => {
      let fn = path.getFunctionParent();
      while (fn) {
        if (subtreeHasTimeoutGuard(fn.node)) return true;
        fn = fn.parentPath?.getFunctionParent();
      }
      return false;
    };

    const report = (path: any, description: string, suggestion: string) => {
      const line = getLineNumber(context.fileContent, path.node.start || 0);
      findings.push({
        ruleId: 'NO_REQUEST_TIMEOUT',
        description,
        severity: Severity.LOW,
        confidence: 'medium',
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion,
      });
    };

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for fetch without timeout
        if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
          const optionsArg = node.arguments[1];
          
          if (!optionsArg || optionsArg.type !== 'ObjectExpression') {
            if (!guardedByEnclosingFunction(path)) {
              report(
                path,
                'fetch() without timeout - a stalled server can hang the request indefinitely',
                'Add timeout to fetch using AbortSignal with setTimeout, or use a library like axios with timeout config.'
              );
            }
          } else {
            // Check if timeout/signal is present
            const hasTimeout = optionsArg.properties.some((prop: any) => 
              prop.key && (prop.key.name === 'signal' || prop.key.name === 'timeout')
            );
            
            if (!hasTimeout && !guardedByEnclosingFunction(path)) {
              report(
                path,
                'fetch() without timeout configuration',
                'Add timeout using AbortSignal: const controller = new AbortController(); setTimeout(() => controller.abort(), 30000);'
              );
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
            
            if (!hasTimeout && !axiosDefaultTimeout && !guardedByEnclosingFunction(path)) {
              report(
                path,
                'axios request without timeout configuration',
                'Add timeout to axios config: { timeout: 30000 } to prevent hanging requests.'
              );
            }
          }
        }
      },
    });

    return findings;
  },
};

// Protocol names as passed to minVersion/maxVersion/secureProtocol/SSLContext options.
const WEAK_TLS_VERSION = /^(?:SSLv[23]|TLSv1(?:[._][01])?)(?:_method)?$/i;
// Cipher-suite name tokens that are broken or export-grade (`TLS_RSA_WITH_RC4_128_SHA`, `DES-CBC3-SHA`).
const WEAK_CIPHER_TOKENS = new Set(['rc4', 'des', '3des', 'md5', 'null', 'export', 'exp', 'anon', 'adh', 'aecdh']);

function weakCipherEntry(value: string): string | null {
  for (const entry of value.split(/[:,\s]+/)) {
    // OpenSSL lists use !RC4 / -DES / +MD5 to turn suites off or reorder them
    if (!entry || /^[!\-+]/.test(entry)) continue;
    const tokens = entry.toLowerCase().split(/[-_]/);
    if (tokens.length > 1 && tokens.some(t => WEAK_CIPHER_TOKENS.has(t))) return entry;
  }
  return null;
}

const weakTlsConfigurationRule: Rule = {
  id: 'WEAK_TLS_CONFIGURATION',
  description: 'Weak TLS configuration detected',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const hasHttpsAgent = context.fileContent.includes('httpsAgent');

    // String literals only: comments and identifiers such as SSL_OP_NO_TLSv1_1 (which
    // *disables* the old protocol) are not configuration of a weak protocol.
    traverse(context.ast, {
      StringLiteral(path: any) {
        const { node } = path;
        const line = getLineNumber(context.fileContent, node.start || 0);
        const snippet = extractSnippet(context.fileContent, line);

        if (WEAK_TLS_VERSION.test(node.value)) {
          findings.push({
            ruleId: 'WEAK_TLS_CONFIGURATION',
            description: `Weak TLS version (< 1.2) configured: "${node.value}" - deprecated and insecure`,
            severity: Severity.HIGH,
            filePath: context.filePath,
            line,
            snippet,
            suggestion: 'Use TLS 1.2 or higher. TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.',
          });
          return;
        }

        const parent = path.parent;
        const inCipherProperty =
          parent?.type === 'ObjectProperty' && parent.value === node &&
          /cipher/i.test(parent.key?.name ?? parent.key?.value ?? '');
        if (inCipherProperty || /_WITH_/.test(node.value)) {
          const weak = weakCipherEntry(node.value);
          if (weak) {
            findings.push({
              ruleId: 'WEAK_TLS_CONFIGURATION',
              description: `Weak cipher suite detected: ${weak}`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet,
              suggestion: `Remove weak cipher ${weak}. Use strong ciphers like AES-GCM, ChaCha20-Poly1305.`,
            });
          }
        }
      },

      // Insecure httpsAgent configuration
      ObjectProperty(path: any) {
        const { node } = path;
        const key = node.key?.name ?? node.key?.value;
        if (hasHttpsAgent && key === 'rejectUnauthorized' && node.value?.type === 'BooleanLiteral' && node.value.value === false) {
          const line = getLineNumber(context.fileContent, node.start || 0);
          findings.push({
            ruleId: 'WEAK_TLS_CONFIGURATION',
            description: 'HTTPS agent with rejectUnauthorized: false - disables certificate validation',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Never disable certificate validation in production. Remove rejectUnauthorized: false.',
          });
        }
      },
    });

    return findings;
  },
};

const CLEARTEXT_WS = /^ws:\/\//i;

/** Single owner of cleartext ws:// reports; uses the same host policy as INSECURE_HTTP_URL. */
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

    const report = (node: any, description: string) => {
      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'INSECURE_WEBSOCKET',
        description,
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Use wss:// (WebSocket Secure) instead of ws:// for encrypted WebSocket connections.',
      });
    };

    traverse(context.ast, {
      // new WebSocket('ws://x')
      NewExpression(path: any) {
        const { node } = path;
        if (node.callee.type === 'Identifier' && node.callee.name === 'WebSocket') {
          const prefix = literalUrlPrefix(node.arguments[0]);
          if (isInsecurePublicHttpUrl(prefix, CLEARTEXT_WS)) {
            report(node, `Unencrypted WebSocket connection: "${prefix!.text}"`);
          }
        }
      },

      // socket.io-client: io('ws://x')
      CallExpression(path: any) {
        const { node } = path;
        if (node.callee.type === 'Identifier' && node.callee.name === 'io') {
          const prefix = literalUrlPrefix(node.arguments[0]);
          if (isInsecurePublicHttpUrl(prefix, CLEARTEXT_WS)) {
            report(node, `Unencrypted WebSocket connection in io(): "${prefix!.text}"`);
          }
        }
      },

      StringLiteral(path: any) {
        const { node } = path;
        // Also catch ws:// URLs assigned to variables (e.g., const WS_URL = 'ws://...')
        const parent = path.parent;
        if (
          parent.type === 'VariableDeclarator' ||
          (parent.type === 'ObjectProperty' &&
           parent.value === node &&
           parent.key &&
           (parent.key.name || parent.key.value || '').toLowerCase().includes('url'))
        ) {
          if (isInsecurePublicHttpUrl({ text: node.value, complete: true }, CLEARTEXT_WS)) {
            report(node, `Unencrypted WebSocket URL configured: "${node.value}"`);
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

    // test, mock and tooling-config files; `src/config/api.ts` is app code and is scanned.
    // The engine already filters with the real scan root; this only backs up direct callers, and
    // without a known root the absolute path (e.g. a checkout under /tests/) must not decide.
    if (context.project?.rootDir && isNonProductionPath(context.filePath, context.project.rootDir)) {
      return findings;
    }

    // Match IP addresses in URLs or standalone
    const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

    traverse(context.ast, {
      StringLiteral(path: any) {
        const { node } = path;
        const value = node.value;

        // Loopback, private, link-local, emulator, documentation ranges and invalid octets are not findings
        const ip = (value.match(ipPattern) ?? []).find((candidate: string) => classifyIpv4(candidate) === 'public');
        if (!ip) return;

        // Only flag IPs in URL-like context or API config
        const isUrlContext = value.includes('://') || value.includes('http');
        const parent = path.parent;
        const isApiConfig = parent && parent.type === 'ObjectProperty' && parent.key &&
          /url|host|endpoint|server|api|base/i.test(parent.key.name || parent.key.value || '');

        if (isUrlContext || isApiConfig) {
          const line = getLineNumber(context.fileContent, node.start || 0);

          findings.push({
            ruleId: 'HARDCODED_IP_ADDRESS',
            description: `Hardcoded IP address in public network URL: ${ip}`,
            severity: Severity.MEDIUM,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Use domain names instead of hardcoded IP addresses. Configure server URLs through environment variables.',
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
