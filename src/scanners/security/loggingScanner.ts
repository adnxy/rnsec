import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { identifierEndsWithTerm } from '../../utils/identifierUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { SENSITIVE_DATA_CATEGORIES } from '../../utils/sensitiveDataPatterns.js';

function categorizeSensitiveData(text: string): string {
  const lowerText = text.toLowerCase();
  
  if (lowerText.includes('password') || lowerText.includes('passwd') || lowerText.includes('pwd')) {
    return SENSITIVE_DATA_CATEGORIES.PASSWORD;
  }
  if (lowerText.includes('token') || lowerText.includes('jwt') || lowerText.includes('bearer')) {
    return SENSITIVE_DATA_CATEGORIES.TOKEN;
  }
  if (lowerText.includes('apikey') || lowerText.includes('api_key') || lowerText.includes('secret')) {
    return SENSITIVE_DATA_CATEGORIES.API_KEY;
  }
  if (lowerText.includes('session') || lowerText.includes('sessionid')) {
    return SENSITIVE_DATA_CATEGORIES.SESSION;
  }
  if (lowerText.includes('email') || lowerText.includes('phone') || lowerText.includes('ssn')) {
    return SENSITIVE_DATA_CATEGORIES.PII;
  }
  if (lowerText.includes('credit') || lowerText.includes('card') || lowerText.includes('cvv') || lowerText.includes('pin')) {
    return SENSITIVE_DATA_CATEGORIES.PAYMENT;
  }
  if (lowerText.includes('user') && (lowerText.includes('profile') || lowerText.includes('data'))) {
    return SENSITIVE_DATA_CATEGORIES.USER_PROFILE;
  }
  if (lowerText.includes('private') || lowerText.includes('encryption')) {
    return SENSITIVE_DATA_CATEGORIES.CRYPTO_KEY;
  }
  
  return SENSITIVE_DATA_CATEGORIES.SENSITIVE;
}

// Words that make a *value* sensitive when they name an identifier or property (userToken, API_KEY, data.password).
const SENSITIVE_VALUE_TERMS: ReadonlySet<string> = new Set([
  'password', 'passwd', 'pwd', 'passcode', 'credential',
  'token', 'jwt', 'bearer', 'accesstoken', 'refreshtoken', 'idtoken', 'authtoken', 'sessiontoken', 'csrftoken',
  'secret', 'secretkey', 'clientsecret', 'apikey', 'privatekey', 'encryptionkey',
  'authorization', 'sessionid', 'cookie', 'otp',
  'ssn', 'creditcard', 'cardnumber', 'cvv', 'cvc', 'iban', 'accountnumber',
]);

// `'token:'`, `'Password ='`: a label that announces the next argument is the sensitive value.
const LABEL_PATTERN = /([A-Za-z_][A-Za-z0-9_ -]*?)\s*[:=]\s*$/;

function isSensitiveName(name: string): boolean {
  // Head word decides: `userToken` and `API_KEY` are secrets, `tokenCount` and `passwordStrength` are not.
  return identifierEndsWithTerm(name, SENSITIVE_VALUE_TERMS);
}

/** Name of the value an expression reads (`token`, `data.password`, `headers['Authorization']`). */
function readName(node: any): string | null {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    if (!node.computed && node.property?.type === 'Identifier') return node.property.name;
    if (node.computed && node.property?.type === 'StringLiteral') return node.property.value;
  }
  if (node.type === 'TSNonNullExpression' || node.type === 'TSAsExpression') return readName(node.expression);
  return null;
}

interface Hit {
  what: string;
  fromLabel?: boolean;
}

/** Find a sensitive value among the leaves of an argument (identifier, member, template parts, `+` chain, object fields). */
function findSensitiveValue(node: any, depth = 0): Hit | null {
  if (!node || depth > 4) return null;

  const name = readName(node);
  if (name !== null) return isSensitiveName(name) ? { what: name } : null;

  if (node.type === 'TemplateLiteral') {
    for (const expr of node.expressions) {
      const hit = findSensitiveValue(expr, depth + 1);
      if (hit) return hit;
    }
    return null;
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return findSensitiveValue(node.left, depth + 1) ?? findSensitiveValue(node.right, depth + 1);
  }

  if (node.type === 'ObjectExpression') {
    for (const prop of node.properties) {
      if (prop.type !== 'ObjectProperty' || prop.computed) continue;
      const key = prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'StringLiteral' ? prop.key.value : null;
      if (!key) continue;
      // `{ password: '***' }` is redacted; `{ token }` and `{ password: pwd }` leak
      const redacted = prop.value.type === 'StringLiteral' || prop.value.type === 'NumericLiteral' || prop.value.type === 'BooleanLiteral' || prop.value.type === 'NullLiteral';
      if (!redacted && isSensitiveName(key)) return { what: `{ ${key} }` };
      if (prop.value.type === 'ObjectExpression') {
        const hit = findSensitiveValue(prop.value, depth + 1);
        if (hit) return hit;
      }
    }
  }

  return null;
}

/** Text of a leading literal label (string, or leftmost part of a `'a' + b` chain) that names a sensitive value. */
function sensitiveLabel(node: any): string | null {
  const text =
    node.type === 'StringLiteral' ? node.value :
    node.type === 'TemplateLiteral' && node.expressions.length === 0 ? node.quasis[0]?.value?.cooked :
    null;
  if (!text) return null;
  const m = LABEL_PATTERN.exec(text.trim());
  return m && isSensitiveName(m[1].trim()) ? m[1].trim() : null;
}

function isLiteral(node: any): boolean {
  if (node.type === 'TemplateLiteral') return node.expressions.length === 0;
  return /Literal$/.test(node.type);
}

const sensitiveLoggingRule: Rule = {
  id: 'SENSITIVE_LOGGING',
  description: 'Sensitive data potentially logged to console',
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
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'console' &&
          node.callee.property.type === 'Identifier' &&
          ['log', 'error', 'warn', 'info', 'debug'].includes(node.callee.property.name)
        ) {
          let hit: Hit | null = null;
          const args: any[] = node.arguments;

          for (const arg of args) {
            hit = findSensitiveValue(arg);
            if (hit) break;
          }
          // `console.log('token:', response.data)`: the label says what the next value is
          for (let i = 0; i + 1 < args.length && !hit; i++) {
            const label = isLiteral(args[i + 1]) ? null : sensitiveLabel(args[i]);
            if (label) hit = { what: label, fromLabel: true };
          }
          // `'token: ' + value`
          if (!hit) {
            for (const arg of args) {
              if (arg.type === 'BinaryExpression' && arg.operator === '+') {
                let leftmost = arg;
                while (leftmost.type === 'BinaryExpression') leftmost = leftmost.left;
                const label = sensitiveLabel(leftmost);
                if (label && !isLiteral(arg.right)) hit = { what: label, fromLabel: true };
              }
            }
          }

          if (hit) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            const consoleMethod = node.callee.property.name;
            const dataCategory = categorizeSensitiveData(hit.what);
            
            findings.push({
              ruleId: 'SENSITIVE_LOGGING',
              description: `console.${consoleMethod}() logging ${dataCategory}: ${hit.what}`,
              severity: Severity.MEDIUM,
              ...(hit.fromLabel ? { confidence: 'medium' as const } : {}),
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Remove console logs with sensitive data or wrap in __DEV__ check. Use a logging library with data filtering for production.',
            });
          }
        }
      },
    });

    return findings;
  },
};

const ERROR_OBJECT_NAMES = new Set(['error', 'err', 'exception']);

/** `error.message` / `err.stack` on a plain error variable (not `stderr.message` or `this.error.message`). */
function isErrorDetailAccess(node: any, errorNames: Set<string>): boolean {
  return (
    node?.type === 'MemberExpression' &&
    !node.computed &&
    node.object?.type === 'Identifier' &&
    errorNames.has(node.object.name) &&
    (node.property?.name === 'message' || node.property?.name === 'stack')
  );
}

function isUserFacingAlert(callee: any): boolean {
  return (
    (callee.type === 'Identifier' && (callee.name === 'alert' || callee.name === 'Alert')) ||
    (callee.type === 'MemberExpression' && callee.object?.type === 'Identifier' &&
      callee.object.name === 'Alert' && callee.property?.name === 'alert')
  );
}

const TOAST_OBJECTS = new Set(['Toast', 'toast', 'Snackbar', 'snackbar', 'Burnt', 'Notifier']);
const TOAST_FUNCTION = /^(?:show|display|notify|present)\w*(?:Toast|Snackbar|Alert|Banner|Notification)$/;
const RESPONSE_OBJECTS = new Set(['res', 'response', 'reply']);
const RESPONSE_METHODS = new Set(['send', 'json', 'end', 'write']);
// Properties of an error that carry request data (axios: `error.config.headers.Authorization`, `error.request`)
const ERROR_REQUEST_FIELDS = new Set(['config', 'request', 'headers']);
const JSX_TEXT_ELEMENT = /(?:^|[A-Z])(?:Text|Label|Paragraph|Title|Caption|Message|Banner)$/;

type SinkKind = 'ui' | 'console' | 'response';

function rootIdentifier(node: any): string | null {
  let cur = node;
  while (cur) {
    if (cur.type === 'Identifier') return cur.name;
    if (cur.type === 'CallExpression') cur = cur.callee;
    else if (cur.type === 'MemberExpression') cur = cur.object;
    else return null;
  }
  return null;
}

/** Where a call sends its arguments: a user-visible UI, the device log, or a network response. */
function sinkKind(callee: any): SinkKind | null {
  if (isUserFacingAlert(callee)) return 'ui';
  if (callee.type === 'Identifier') return TOAST_FUNCTION.test(callee.name) ? 'ui' : null;
  if (callee.type !== 'MemberExpression' || callee.computed) return null;
  const method = callee.property?.name;
  if (callee.object?.type === 'Identifier' && callee.object.name === 'console') {
    return method === 'error' || method === 'warn' ? 'console' : null;
  }
  const root = rootIdentifier(callee.object);
  if (root && TOAST_OBJECTS.has(root)) return 'ui';
  if (root && RESPONSE_OBJECTS.has(root) && RESPONSE_METHODS.has(method)) return 'response';
  return null;
}

function* subNodes(node: any, depth = 0): Generator<any> {
  if (!node || typeof node.type !== 'string' || depth > 6) return;
  yield node;
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments') continue;
    const v = node[key];
    if (Array.isArray(v)) for (const c of v) yield* subNodes(c, depth + 1);
    else if (v && typeof v.type === 'string') yield* subNodes(v, depth + 1);
  }
}

/**
 * The error's message or stack reaches this expression (template parts, `+` chains, object fields), or the whole
 * caught error is passed (only for a name bound by a catch clause / `.catch` callback: a bare `error` elsewhere is
 * often a validation string).
 */
function exposesErrorDetail(arg: any, errorNames: Set<string>, boundNames: Set<string>): boolean {
  for (const n of subNodes(arg)) {
    if (isErrorDetailAccess(n, errorNames)) return true;
  }
  return arg.type === 'Identifier' && boundNames.has(arg.name);
}

/** `error.config.headers`, `error.request`, `error.token`: a field of the error that holds request data or a secret. */
function exposesSensitiveErrorField(arg: any, errorNames: Set<string>): boolean {
  for (const n of subNodes(arg)) {
    if (n.type !== 'MemberExpression' || n.computed) continue;
    const prop = n.property?.name;
    if (!prop) continue;
    if (!ERROR_REQUEST_FIELDS.has(prop) && !isSensitiveName(prop)) continue;
    const root = rootIdentifier(n.object);
    if (root && errorNames.has(root)) return true;
  }
  return false;
}

/** Error variable names in scope: the usual names, the enclosing catch parameter, a `.catch(e => ...)` callback parameter. */
function errorNamesAt(path: any, bound = new Set<string>()): Set<string> {
  const names = new Set(ERROR_OBJECT_NAMES);
  for (let p = path.parentPath; p; p = p.parentPath) {
    const n = p.node;
    if (n.type === 'CatchClause' && n.param?.type === 'Identifier') { names.add(n.param.name); bound.add(n.param.name); }
    if (
      (n.type === 'ArrowFunctionExpression' || n.type === 'FunctionExpression') &&
      n.params[0]?.type === 'Identifier' &&
      p.parent?.type === 'CallExpression' &&
      p.parent.callee?.type === 'MemberExpression' &&
      p.parent.callee.property?.name === 'catch'
    ) {
      names.add(n.params[0].name);
      bound.add(n.params[0].name);
    }
  }
  return names;
}

const sensitiveDataInErrorMessagesRule: Rule = {
  id: 'SENSITIVE_DATA_IN_ERROR_MESSAGES',
  description: 'Error messages or stack traces may expose sensitive data',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }
    const stripsConsole = context.project?.stripsConsoleInRelease === true;

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        const kind = sinkKind(node.callee);
        if (!kind) return;
        // `catch (e) { Alert.alert(e.message) }` is reported once, at the catch clause
        if (kind !== 'console' && path.findParent((p: any) => p.isCatchClause())) return;

        const boundNames = new Set<string>();
        const errorNames = errorNamesAt(path, boundNames);

        if (kind === 'console') {
          // Device logs are not a user-visible sink: plain console.error(err) is routine. Only report a logged
          // value that carries request data or a secret, and nothing when release builds strip console calls.
          if (stripsConsole) return;
          if (!node.arguments.some((arg: any) => exposesSensitiveErrorField(arg, errorNames))) return;
          const line = getLineNumber(context.fileContent, node.start || 0);
          findings.push({
            ruleId: 'SENSITIVE_DATA_IN_ERROR_MESSAGES',
            description: 'Error request data (headers, config, token) written to the log',
            severity: Severity.LOW,
            confidence: 'low',
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Log only safe error properties (message, code). Never log request headers, tokens or the full request config.',
          });
          return;
        }

        if (!node.arguments.some((arg: any) => exposesErrorDetail(arg, errorNames, boundNames))) return;
        const line = getLineNumber(context.fileContent, node.start || 0);
        findings.push({
          ruleId: 'SENSITIVE_DATA_IN_ERROR_MESSAGES',
          description: kind === 'response'
            ? 'Error message or stack trace sent in a network response'
            : 'Backend error message or stack trace exposed to user',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Use generic error messages for users. Log detailed errors server-side only. Never expose stack traces or backend errors.',
        });
      },

      // <Text>{error.message}</Text>
      JSXExpressionContainer(path: any) {
        const element = path.parent;
        if (element?.type !== 'JSXElement') return;
        const name = element.openingElement?.name;
        const tag = name?.type === 'JSXIdentifier' ? name.name : name?.type === 'JSXMemberExpression' ? name.property?.name : null;
        if (!tag || !JSX_TEXT_ELEMENT.test(tag)) return;
        const errorNames = errorNamesAt(path);
        if (path.findParent((p: any) => p.isCatchClause())) return;
        if (!Array.from(subNodes(path.node.expression)).some(n => isErrorDetailAccess(n, errorNames))) return;
        const line = getLineNumber(context.fileContent, path.node.start || 0);
        findings.push({
          ruleId: 'SENSITIVE_DATA_IN_ERROR_MESSAGES',
          description: 'Backend error message or stack trace rendered in the UI',
          severity: Severity.MEDIUM,
          confidence: 'low',
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Render a generic message for users and log the detail separately.',
        });
      },
      
      // Check for catch blocks that expose errors directly
      CatchClause(path: any) {
        const { node } = path;
        const errorNames = new Set(ERROR_OBJECT_NAMES);
        if (node.param?.type === 'Identifier') errorNames.add(node.param.name);

        let exposes = false;
        path.traverse({
          CallExpression(inner: any) {
            if (exposes) return;
            const kind = sinkKind(inner.node.callee);
            if (kind !== 'ui' && kind !== 'response') return;
            // Alert.alert('Failed', error.message) or `Failed: ${error.message}`
            for (const arg of inner.node.arguments) {
              if (Array.from(subNodes(arg)).some(n => isErrorDetailAccess(n, errorNames))) {
                exposes = true;
                inner.stop();
                return;
              }
            }
          },
        });

        if (exposes) {
          const line = getLineNumber(context.fileContent, node.start || 0);
          
          findings.push({
            ruleId: 'SENSITIVE_DATA_IN_ERROR_MESSAGES',
            description: 'Catch block shows raw error message to user - may expose sensitive backend details',
            severity: Severity.MEDIUM,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Replace with user-friendly generic messages. Example: "An error occurred. Please try again." Log details securely.',
          });
        }
      },
    });

    return findings;
  },
};

export const loggingRules: RuleGroup = {
  category: RuleCategory.LOGGING,
  rules: [sensitiveLoggingRule, sensitiveDataInErrorMessagesRule],
};
