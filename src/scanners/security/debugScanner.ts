import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { extractHost, isLocalOrPrivateHost } from '../../utils/hostUtils.js';
import { identifierTokens } from '../../utils/identifierUtils.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';

const PASSWORD_TERMS: ReadonlySet<string> = new Set(['password', 'passwd', 'pass', 'pwd', 'passcode']);
const USERNAME_TERMS: ReadonlySet<string> = new Set(['username', 'user', 'email']);

// Placeholder values followed by a non-letter (or end): `admin`, `test123`, `Test@123`, not `administrator`.
const TEST_PASSWORD_VALUE = /^(?:test|demo|admin|password|123456|qwerty)(?![a-z])/i;
const TEST_USERNAME_VALUE = /^(?:test|demo|admin|user@test\.com)(?![a-z])/i;
const TEST_EMAIL_VALUE = /^test@(?:test|example)\.(?:com|org)$/i;
const TEST_BEARER_VALUE = /Bearer\s+test[a-zA-Z0-9]+/i;

function nameOf(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'MemberExpression' && !node.computed) return node.property?.name ?? null;
  return null;
}

/** Last word of an identifier: `adminPassword` -> `password`, `bypassAuth` -> `auth`. */
function lastToken(name: string): string | undefined {
  const tokens = identifierTokens(name);
  return tokens[tokens.length - 1];
}

function stringValueOf(node: any): string | null {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0]?.value?.cooked ?? null;
  return null;
}

const testCredentialsRule: Rule = {
  id: 'TEST_CREDENTIALS_IN_CODE',
  description: 'Test credentials or example passwords found in source code',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const report = (node: any, type: string, shown: string) => {
      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'TEST_CREDENTIALS_IN_CODE',
        description: `Test ${type} found in production code: ${shown}`,
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Remove test credentials from production code. Use environment variables or mock data in tests only.',
      });
    };

    // name = value pairs: `const password = 'admin'`, `{ username: 'test' }`, `this.pwd = 'qwerty'`
    const checkPair = (reportNode: any, name: string | null, valueNode: any) => {
      const value = stringValueOf(valueNode);
      if (!name || !value) return false;
      const last = lastToken(name);
      if (!last) return false;
      if (PASSWORD_TERMS.has(last) && TEST_PASSWORD_VALUE.test(value)) {
        report(reportNode, 'password', `${name} = "${value}"`);
        return true;
      }
      if (USERNAME_TERMS.has(last) && TEST_USERNAME_VALUE.test(value)) {
        report(reportNode, 'username', `${name} = "${value}"`);
        return true;
      }
      return false;
    };

    const reported = new Set<any>();

    traverse(context.ast, {
      VariableDeclarator(path: any) {
        const { node } = path;
        if (node.id.type === 'Identifier' && checkPair(node, node.id.name, node.init)) reported.add(node.init);
      },
      ObjectProperty(path: any) {
        const { node } = path;
        if (!node.computed && checkPair(node, nameOf(node.key), node.value)) reported.add(node.value);
      },
      AssignmentExpression(path: any) {
        const { node } = path;
        if (node.operator === '=' && checkPair(node, nameOf(node.left), node.right)) reported.add(node.right);
      },
      JSXAttribute(path: any) {
        const { node } = path;
        const valueNode = node.value?.type === 'JSXExpressionContainer' ? node.value.expression : node.value;
        if (node.name?.type === 'JSXIdentifier' && checkPair(node, node.name.name, valueNode)) reported.add(valueNode);
      },
      StringLiteral(path: any) {
        const { node } = path;
        if (reported.has(node)) return;
        if (TEST_EMAIL_VALUE.test(node.value)) report(node, 'email', node.value);
        else if (TEST_BEARER_VALUE.test(node.value)) report(node, 'token', node.value);
      },
      TemplateLiteral(path: any) {
        const { node } = path;
        const text = node.quasis.map((q: any) => q.value.cooked ?? '').join('');
        if (TEST_BEARER_VALUE.test(text)) report(node, 'token', text.match(TEST_BEARER_VALUE)![0]);
      },
    });

    return findings;
  },
};

const DEBUG_SEGMENT_PARENTS = new Set(['api', 'admin']);

/** Path of a URL or relative path, without query/hash. */
function pathOf(value: string): string | null {
  if (value.startsWith('/') && !value.startsWith('//')) return value.split(/[?#]/)[0];
  const host = extractHost(value);
  if (!host) return null;
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http:${value}`).pathname;
  } catch {
    return null;
  }
}

/**
 * `/debug/...` , `/api/debug`, `/admin/debug`, `/__debug__/` as whole path segments.
 * `/api/debug-utils/` and `/debugger` are different routes.
 */
function isDebugPath(path: string): boolean {
  const segments = path.toLowerCase().split('/');
  for (let i = 1; i < segments.length; i++) {
    const seg = segments[i];
    if (seg.startsWith('__debug')) return true;
    if (seg !== 'debug') continue;
    const hasMore = i < segments.length - 1; // `/debug/x` or `/debug/`
    if (hasMore || DEBUG_SEGMENT_PARENTS.has(segments[i - 1])) return true;
  }
  return false;
}

const debugEndpointsRule: Rule = {
  id: 'DEBUG_ENDPOINTS_EXPOSED',
  description: 'Debug or development endpoints exposed in production code',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      StringLiteral(path: any) {
        const { node } = path;
        const value = node.value;
        
        if (typeof value !== 'string' || !(value.includes('://') || value.startsWith('/'))) return;
        if (isLocalOrPrivateHost(value)) return;

        const urlPath = pathOf(value);
        if (!urlPath || !isDebugPath(urlPath)) return;

        const line = getLineNumber(context.fileContent, node.start || 0);
        findings.push({
          ruleId: 'DEBUG_ENDPOINTS_EXPOSED',
          description: `Debug endpoint exposed: ${value}`,
          severity: Severity.HIGH,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Wrap debug endpoints in __DEV__ checks or remove them from production builds. Debug endpoints should never be accessible in production.',
        });
      },
    });

    return findings;
  },
};

/** Strip `(window as any)`, `(<any>window)`, `window!` and parentheses down to the wrapped expression */
function unwrapTsWrappers(node: any): any {
  while (node && ['TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression', 'TSSatisfiesExpression', 'ParenthesizedExpression'].includes(node.type)) {
    node = node.expression;
  }
  return node;
}

const reduxDevToolsRule: Rule = {
  id: 'REDUX_DEVTOOLS_ENABLED',
  description: 'Redux DevTools enabled in production',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      MemberExpression(path: any) {
        const { node } = path;
        
        if (unwrapTsWrappers(node.object).type === 'Identifier' &&
            unwrapTsWrappers(node.object).name === 'window' &&
            node.property.type === 'Identifier' &&
            node.property.name === '__REDUX_DEVTOOLS_EXTENSION__') {
          
          const start = Math.max(0, (node.start || 0) - 200);
          const end = Math.min(context.fileContent.length, (node.end || 0) + 200);
          const surroundingCode = context.fileContent.substring(start, end);
          
          const hasDevCheck = /__DEV__|process\.env\.NODE_ENV.*!==.*production/.test(surroundingCode);
          
          if (!hasDevCheck) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            findings.push({
              ruleId: 'REDUX_DEVTOOLS_ENABLED',
              description: 'Redux DevTools extension enabled without production check',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Wrap Redux DevTools in __DEV__ or NODE_ENV check: window.__REDUX_DEVTOOLS_EXTENSION__ && __DEV__ ? ... : undefined',
            });
          }
        }
      },
    });

    return findings;
  },
};

export const debugRules: RuleGroup = {
  category: RuleCategory.LOGGING,
  rules: [
    testCredentialsRule,
    debugEndpointsRule,
    reduxDevToolsRule,
  ],
};

