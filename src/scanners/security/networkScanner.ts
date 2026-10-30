import { propertyKeyName } from '../../utils/identifierUtils.js';
import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { ProjectInfo, Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { isLocalOrPrivateHost, classifyIpv4 } from '../../utils/hostUtils.js';
import { isNonProductionPath } from '../../utils/pathFilters.js';
import { collectDevOnlyRanges, isLineInRanges } from '../../utils/devGuards.js';
import { isAppSource, projectHasFile } from '../../utils/projectEvidence.js';
import { nativeTlsValidationRule } from './nativeTlsScanner.js';

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

/** Packages that export a `fetch` with the platform's semantics: no timeout unless the caller adds one */
const GLOBAL_EQUIVALENT_FETCH = /^(?:node-fetch|cross-fetch|whatwg-fetch|isomorphic-fetch|isomorphic-unfetch|unfetch|expo\/fetch|react-native-fetch-api)$/;
/** URL schemes that never leave the device */
const LOCAL_URL_SCHEME = /^(?:file|data|blob|content|asset|assets-library|ph|ipod-library):/i;

/**
 * Is this `fetch` the platform's global fetch (or a drop-in for it)? A `fetch` that resolves to a local
 * function, a parameter, a project wrapper (relative or aliased import) or any other package is somebody
 * else's API: the call is judged where the real global `fetch` is called.
 */
function isGlobalFetch(path: any): boolean {
  const binding = path.scope.getBinding('fetch');
  if (!binding) return true;
  const decl = binding.path;
  if (decl.isImportSpecifier() || decl.isImportDefaultSpecifier() || decl.isImportNamespaceSpecifier()) {
    return GLOBAL_EQUIVALENT_FETCH.test(decl.parent?.source?.value ?? '');
  }
  if (decl.isVariableDeclarator()) {
    const init = decl.node.init;
    // `const fetch = require('node-fetch')`
    if (init?.type === 'CallExpression' && init.callee?.name === 'require' && init.arguments[0]?.type === 'StringLiteral') {
      return GLOBAL_EQUIVALENT_FETCH.test(init.arguments[0].value);
    }
    // `const fetch = global.fetch`
    return init?.type === 'MemberExpression' && ['global', 'globalThis', 'window', 'self'].includes(init.object?.name) && init.property?.name === 'fetch';
  }
  return false;
}

/** The URL argument is visibly a local resource (`file://`, `blob:`, `data:`, `require(...)`, `URL.createObjectURL(...)`) */
function isLocalResourceUrl(arg: any, path: any, depth = 0): boolean {
  if (!arg || depth > 3) return false;
  const prefix = literalUrlPrefix(arg);
  if (prefix) return LOCAL_URL_SCHEME.test(prefix.text);
  if (arg.type === 'CallExpression') {
    const c = arg.callee;
    if (c?.type === 'Identifier' && c.name === 'require') return true;
    return c?.type === 'MemberExpression' && ['createObjectURL', 'resolveAssetSource', 'toDataURL'].includes(c.property?.name);
  }
  if (arg.type === 'Identifier') {
    const init = path.scope.getBinding(arg.name)?.path?.node?.init;
    return init ? isLocalResourceUrl(init, path, depth + 1) : false;
  }
  return false;
}

/** `axios.defaults.timeout = ...` */
function isAxiosDefaultsTimeout(left: any): boolean {
  return left?.type === 'MemberExpression' && left.property?.name === 'timeout' &&
    left.object?.type === 'MemberExpression' && left.object.property?.name === 'defaults';
}

/** `globalThis.fetch = ...`: the app replaced the global fetch */
function isGlobalFetchAssignment(left: any): boolean {
  return left?.type === 'MemberExpression' && !left.computed && left.property?.name === 'fetch' &&
    left.object?.type === 'Identifier' && ['global', 'globalThis', 'window', 'self'].includes(left.object.name);
}

const AXIOS_DEFAULT_TIMEOUT_TEXT = /axios\.defaults\.timeout\s*=/;
// text approximation of `isGlobalFetchAssignment` + `subtreeHasTimeoutGuard` for the unchanged files of a partial scan
const GLOBAL_FETCH_ASSIGNMENT_TEXT = /\b(?:global|globalThis|window|self)\.fetch\s*=(?!=)[\s\S]{0,800}?(?:AbortSignal\.timeout|AbortController|\btimeout\b)/;
const TIMEOUT_SOURCE_FILES = /\.(?:js|jsx|ts|tsx)$/;

interface TimeoutCandidate {
  kind: 'fetch' | 'axios';
  finding: Finding;
}

/**
 * Calls are collected in `apply` and reported by `finalize`, so a project-wide default can still clear them:
 * `axios.defaults.timeout = ...` anywhere covers every `axios.<verb>()` call, and an app-level
 * `globalThis.fetch = ...` override that itself bounds the request (AbortSignal.timeout, a timer + AbortController, ...)
 * covers every global `fetch()` call. (An `axios.create({ timeout })` instance
 * or a fetch helper only covers the calls that go through it, and those never match this rule.)
 * In `--changed-files` scans the rest of the project is read from disk to look for these defaults.
 */
let timeoutCandidates: TimeoutCandidate[] = [];
let axiosDefaultSeen = false;
let globalFetchPatched = false;

const noRequestTimeoutRule: Rule = {
  id: 'NO_REQUEST_TIMEOUT',
  description: 'Network request without timeout configuration',
  // A hanging server can only stall the user's own request on a mobile client: low impact.
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  beginScan: () => {
    timeoutCandidates = [];
    axiosDefaultSeen = false;
    globalFetchPatched = false;
  },
  finalize: async (project?: ProjectInfo): Promise<Finding[]> => {
    const wants = (kind: 'fetch' | 'axios') => timeoutCandidates.some(c => c.kind === kind);
    if (wants('axios') && !axiosDefaultSeen) {
      axiosDefaultSeen = await projectHasFile(project, TIMEOUT_SOURCE_FILES, c => AXIOS_DEFAULT_TIMEOUT_TEXT.test(c));
    }
    if (wants('fetch') && !globalFetchPatched) {
      globalFetchPatched = await projectHasFile(project, TIMEOUT_SOURCE_FILES, c => GLOBAL_FETCH_ASSIGNMENT_TEXT.test(c));
    }
    return timeoutCandidates
      .filter(c => !(c.kind === 'axios' ? axiosDefaultSeen : globalFetchPatched))
      .map(c => c.finding);
  },
  apply: async (context: RuleContext): Promise<Finding[]> => {
    if (!context.ast || !isAppSource(context)) {
      return [];
    }
    let devRanges: ReturnType<typeof collectDevOnlyRanges> | undefined;

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
        if (isAxiosDefaultsTimeout(left)) {
          axiosDefaultTimeout = true;
          axiosDefaultSeen = true;
        }
        // only an override that bounds the request counts: nitro/mock-server shims replace fetch without adding a timeout
        if (isGlobalFetchAssignment(left) && subtreeHasTimeoutGuard(path.node.right)) globalFetchPatched = true;
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

    const report = (path: any, kind: 'fetch' | 'axios', description: string, suggestion: string) => {
      const line = getLineNumber(context.fileContent, path.node.start || 0);
      devRanges ??= collectDevOnlyRanges(context.ast);
      if (isLineInRanges(line, devRanges)) return;
      timeoutCandidates.push({
        kind,
        finding: {
          ruleId: 'NO_REQUEST_TIMEOUT',
          description,
          severity: Severity.LOW,
          confidence: 'medium',
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion,
        },
      });
    };

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for fetch without timeout
        if (node.callee.type === 'Identifier' && node.callee.name === 'fetch' && isGlobalFetch(path)) {
          if (isLocalResourceUrl(node.arguments[0], path)) return;
          let optionsArg = node.arguments[1];
          // `const init = { ... }; fetch(url, init)`: judge the object that is visible
          if (optionsArg?.type === 'Identifier') {
            const init = path.scope.getBinding(optionsArg.name)?.path?.node?.init;
            if (init?.type === 'ObjectExpression') optionsArg = init;
          }

          if (!optionsArg || optionsArg.type !== 'ObjectExpression') {
            if (!guardedByEnclosingFunction(path)) {
              report(
                path,
                'fetch',
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
                'fetch',
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
                'axios',
                'axios request without timeout configuration',
                'Add timeout to axios config: { timeout: 30000 } to prevent hanging requests.'
              );
            }
          }
        }
      },
    });

    return [];
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
           propertyKeyName(parent).toLowerCase().includes('url'))
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
          /url|host|endpoint|server|api|base/i.test(propertyKeyName(parent));

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
    nativeTlsValidationRule,
  ],
};
