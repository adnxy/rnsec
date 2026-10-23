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

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for error logging or displaying
        const isConsole =
          node.callee.type === 'MemberExpression' &&
          node.callee.object.name === 'console' &&
          (node.callee.property.name === 'error' || node.callee.property.name === 'warn');
        const isErrorHandling = isConsole || (node.callee.type === 'Identifier' && isUserFacingAlert(node.callee));

        if (isErrorHandling) {
          // A console log only reaches device logs; showing it to the user is the real exposure.
          const confidence = isConsole ? ('low' as const) : undefined;

          for (const arg of node.arguments) {
            // Check if error object or message is being logged directly
            if (arg.type === 'Identifier' && ERROR_OBJECT_NAMES.has(arg.name)) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'SENSITIVE_DATA_IN_ERROR_MESSAGES',
                description: 'Error object logged directly - may contain sensitive data or stack traces',
                // console output only reaches device logs; showing the error to the user is the real exposure
                severity: isConsole ? Severity.LOW : Severity.MEDIUM,
                ...(confidence ? { confidence } : {}),
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Log only safe error properties (message, code). Sanitize error messages before displaying to users. Never expose stack traces in production.',
              });
            }
            
            // Check for error.message being shown to users
            if (isErrorDetailAccess(arg, ERROR_OBJECT_NAMES)) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'SENSITIVE_DATA_IN_ERROR_MESSAGES',
                description: 'Backend error message or stack trace exposed to user',
                severity: Severity.MEDIUM,
                ...(confidence ? { confidence } : {}),
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Use generic error messages for users. Log detailed errors server-side only. Never expose stack traces or backend errors.',
              });
            }
          }
        }
      },
      
      // Check for catch blocks that expose errors directly
      CatchClause(path: any) {
        const { node } = path;
        const errorNames = new Set(ERROR_OBJECT_NAMES);
        if (node.param?.type === 'Identifier') errorNames.add(node.param.name);

        let exposes = false;
        path.traverse({
          CallExpression(inner: any) {
            if (exposes || !isUserFacingAlert(inner.node.callee)) return;
            // Alert.alert('Failed', error.message) or `Failed: ${error.message}`
            inner.traverse({
              MemberExpression(member: any) {
                if (isErrorDetailAccess(member.node, errorNames)) {
                  exposes = true;
                  member.stop();
                }
              },
            });
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
