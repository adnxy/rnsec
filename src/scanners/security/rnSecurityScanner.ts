import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { tokenizeName as tokenize, hasAdjacentTokens as hasAdjacent, classifySecretName } from '../../utils/secretNames.js';

const JS_FILES = ['.js', '.jsx', '.ts', '.tsx'];

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

interface ImportInfo {
  /** every module specifier imported/required in the file */
  sources: Set<string>;
  /** local binding name -> where it came from */
  locals: Map<string, { source: string; imported: string }>;
}

function collectImports(ast: any): ImportInfo {
  const info: ImportInfo = { sources: new Set(), locals: new Map() };

  traverse(ast, {
    ImportDeclaration(path: any) {
      const source = path.node.source.value as string;
      info.sources.add(source);
      for (const spec of path.node.specifiers) {
        if (spec.type === 'ImportDefaultSpecifier') {
          info.locals.set(spec.local.name, { source, imported: 'default' });
        } else if (spec.type === 'ImportNamespaceSpecifier') {
          info.locals.set(spec.local.name, { source, imported: '*' });
        } else if (spec.type === 'ImportSpecifier') {
          const imported = spec.imported.type === 'Identifier' ? spec.imported.name : spec.imported.value;
          info.locals.set(spec.local.name, { source, imported });
        }
      }
    },
    CallExpression(path: any) {
      const { node } = path;
      if (
        node.callee.type === 'Identifier' &&
        node.callee.name === 'require' &&
        node.arguments[0]?.type === 'StringLiteral'
      ) {
        const source = node.arguments[0].value as string;
        info.sources.add(source);

        // const X = require('m')  /  require('m').default  /  const { A } = require('m')
        let target = path.parentPath;
        let imported = '*';
        if (
          target.node.type === 'MemberExpression' &&
          !target.node.computed &&
          target.node.property.type === 'Identifier' &&
          target.node.property.name === 'default'
        ) {
          imported = 'default';
          target = target.parentPath;
        }
        if (target.node.type === 'VariableDeclarator') {
          const id = target.node.id;
          if (id.type === 'Identifier') {
            info.locals.set(id.name, { source, imported: imported === '*' ? 'default' : imported });
          } else if (id.type === 'ObjectPattern') {
            for (const prop of id.properties) {
              if (
                prop.type === 'ObjectProperty' &&
                prop.key.type === 'Identifier' &&
                prop.value.type === 'Identifier'
              ) {
                info.locals.set(prop.value.name, { source, imported: prop.key.name });
              }
            }
          }
        }
      }
    },
  });

  return info;
}

function hasSource(info: ImportInfo, pred: (source: string) => boolean): boolean {
  for (const s of info.sources) {
    if (pred(s)) return true;
  }
  return false;
}

/** Local names bound to `imported` from modules matching `pred`. */
function localsFor(info: ImportInfo, pred: (source: string) => boolean, imported: string): Set<string> {
  const out = new Set<string>();
  for (const [local, meta] of info.locals) {
    if (pred(meta.source) && meta.imported === imported) out.add(local);
  }
  return out;
}

function propName(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'StringLiteral') return node.value;
  return null;
}

/** Name of `obj.prop` / `obj['prop']` member access property. */
function memberPropName(node: any): string | null {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return null;
  if (!node.computed) return node.property.type === 'Identifier' ? node.property.name : null;
  return node.property.type === 'StringLiteral' ? node.property.value : null;
}

function isProcessEnv(node: any): boolean {
  return (
    node &&
    node.type === 'MemberExpression' &&
    node.object.type === 'Identifier' &&
    node.object.name === 'process' &&
    memberPropName(node) === 'env'
  );
}

function makeFinding(
  context: RuleContext,
  node: any,
  partial: Pick<Finding, 'ruleId' | 'description' | 'severity' | 'reason' | 'suggestion'> & {
    confidence?: Finding['confidence'];
  }
): Finding {
  const line = getLineNumber(context.fileContent, node.start || 0);
  return {
    ...partial,
    filePath: context.filePath,
    line,
    snippet: extractSnippet(context.fileContent, line),
  };
}

// ---------------------------------------------------------------------------
// 1. TLS_VALIDATION_DISABLED_ENV
//
// `rejectUnauthorized: false` in object literals is already reported by
// CERT_PINNING_DISABLED / WEAK_TLS_CONFIGURATION, so this rule only covers the
// shapes those do not: the process-wide env switch and property assignments.
// ---------------------------------------------------------------------------

const TLS_ENV_NAME = 'NODE_TLS_REJECT_UNAUTHORIZED';

function isZeroValue(node: any): boolean {
  if (!node) return false;
  if (node.type === 'StringLiteral') return node.value.trim() === '0';
  if (node.type === 'NumericLiteral') return node.value === 0;
  if (node.type === 'TemplateLiteral') {
    return node.expressions.length === 0 && node.quasis[0].value.cooked.trim() === '0';
  }
  return false;
}

const tlsValidationDisabledEnvRule: Rule = {
  id: 'TLS_VALIDATION_DISABLED_ENV',
  description: 'TLS certificate validation disabled process-wide or via property assignment',
  severity: Severity.HIGH,
  fileTypes: JS_FILES,
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const reason =
      'With certificate validation off, any network attacker (public Wi-Fi, malicious proxy) can present a forged ' +
      'certificate and read or modify all HTTPS traffic, including credentials and tokens (man-in-the-middle).';

    traverse(context.ast, {
      AssignmentExpression(path: any) {
        const { node } = path;
        if (node.operator !== '=' || node.left.type !== 'MemberExpression') return;
        const name = memberPropName(node.left);

        if (name === TLS_ENV_NAME && isProcessEnv(node.left.object) && isZeroValue(node.right)) {
          findings.push(
            makeFinding(context, node, {
              ruleId: 'TLS_VALIDATION_DISABLED_ENV',
              description: `${TLS_ENV_NAME} set to '0' - disables TLS certificate validation for every HTTPS request`,
              severity: Severity.HIGH,
              confidence: 'high',
              reason,
              suggestion:
                'Remove this assignment. For development against self-signed servers, install the dev CA on the device/emulator instead.',
            })
          );
        } else if (
          name === 'rejectUnauthorized' &&
          node.right.type === 'BooleanLiteral' &&
          node.right.value === false
        ) {
          findings.push(
            makeFinding(context, node, {
              ruleId: 'TLS_VALIDATION_DISABLED_ENV',
              description: 'rejectUnauthorized assigned false - disables TLS certificate validation',
              severity: Severity.HIGH,
              confidence: 'high',
              reason,
              suggestion: 'Leave rejectUnauthorized at its default (true) and trust a proper CA instead.',
            })
          );
        }
      },

      // Object.assign(process.env, { NODE_TLS_REJECT_UNAUTHORIZED: '0' }), spawn env, etc.
      ObjectProperty(path: any) {
        const { node } = path;
        if (propName(node.key) === TLS_ENV_NAME && !node.computed && isZeroValue(node.value)) {
          findings.push(
            makeFinding(context, node, {
              ruleId: 'TLS_VALIDATION_DISABLED_ENV',
              description: `${TLS_ENV_NAME} set to '0' - disables TLS certificate validation`,
              severity: Severity.HIGH,
              confidence: 'high',
              reason,
              suggestion: 'Remove this setting; do not ship configuration that turns off certificate validation.',
            })
          );
        }
      },
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// 2. BUNDLED_ENV_SECRET
// ---------------------------------------------------------------------------

const classifyEnvName = classifySecretName;

const bundledEnvSecretRule: Rule = {
  id: 'BUNDLED_ENV_SECRET',
  description: 'Secret read from an environment variable that is bundled into the client app',
  severity: Severity.HIGH,
  fileTypes: JS_FILES,
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const imports = collectImports(context.ast);
    const isConfigModule = (s: string) => s === 'react-native-config';
    const configLocals = new Set<string>([
      ...localsFor(imports, isConfigModule, 'default'),
      ...localsFor(imports, isConfigModule, 'Config'),
    ]);

    const seen = new Set<string>();
    const report = (node: any, name: string, origin: string, via: string) => {
      const severity = classifyEnvName(name);
      if (!severity) return;
      const key = `${origin}:${name}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(
        makeFinding(context, node, {
          ruleId: 'BUNDLED_ENV_SECRET',
          description: `Secret-looking variable "${name}" is read from ${via}, which is bundled into the app`,
          severity,
          confidence: 'medium',
          reason:
            `${via} values are inlined into the JavaScript bundle / native build at build time and can be extracted ` +
            'from the shipped app by anyone. They are not secret.',
          suggestion:
            'Keep secrets on a backend and call it from the app. If this value is actually public, rename it so it does not look like a secret.',
        })
      );
    };

    const fromProcessEnv = (node: any, name: string | null) => {
      if (name && name.startsWith('EXPO_PUBLIC_')) {
        report(node, name.slice('EXPO_PUBLIC_'.length), 'expo', 'process.env.EXPO_PUBLIC_*');
      }
    };

    traverse(context.ast, {
      MemberExpression(path: any) {
        const { node } = path;
        const name = memberPropName(node);
        if (!name) return;
        if (isProcessEnv(node.object)) {
          fromProcessEnv(node, name);
        } else if (node.object.type === 'Identifier' && configLocals.has(node.object.name)) {
          report(node, name, 'config', 'react-native-config');
        }
      },

      VariableDeclarator(path: any) {
        const { node } = path;
        if (node.id.type !== 'ObjectPattern' || !node.init) return;
        const fromEnv = isProcessEnv(node.init);
        const fromConfig = node.init.type === 'Identifier' && configLocals.has(node.init.name);
        if (!fromEnv && !fromConfig) return;
        for (const prop of node.id.properties) {
          if (prop.type !== 'ObjectProperty' || prop.computed) continue;
          const name = propName(prop.key);
          if (!name) continue;
          if (fromEnv) fromProcessEnv(prop, name);
          else report(prop, name, 'config', 'react-native-config');
        }
      },

      ImportDeclaration(path: any) {
        const { node } = path;
        if (node.source.value !== '@env') return;
        for (const spec of node.specifiers) {
          if (spec.type !== 'ImportSpecifier') continue;
          const name = spec.imported.type === 'Identifier' ? spec.imported.name : spec.imported.value;
          report(spec, name, 'dotenv', '@env (react-native-dotenv)');
        }
      },
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// 3. MMKV_UNENCRYPTED_SENSITIVE_DATA
// ---------------------------------------------------------------------------

const MMKV_SENSITIVE_TOKENS = new Set([
  'token', 'password', 'secret', 'credential', 'credentials', 'session', 'jwt', 'pin', 'otp',
  'refresh', 'auth', 'ssn', 'card',
]);
const MMKV_BENIGN_SUFFIXES = new Set([
  'enabled', 'count', 'at', 'time', 'timestamp', 'expires', 'expiry', 'expiration', 'ttl', 'type', 'mode',
  'flag', 'visible', 'shown', 'seen', 'hint', 'label',
]);

function sensitiveKeyToken(text: string): string | null {
  const tokens = text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map(t => t.toLowerCase());
  if (tokens.length === 0) return null;
  if (MMKV_BENIGN_SUFFIXES.has(tokens[tokens.length - 1])) return null;
  return tokens.find(t => MMKV_SENSITIVE_TOKENS.has(t)) ?? null;
}

/** Best-effort static text of a storage key argument. */
function keyText(node: any): string | null {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral') return node.quasis.map((q: any) => q.value.cooked ?? '').join(' ');
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') return memberPropName(node);
  return null;
}

const mmkvUnencryptedSensitiveDataRule: Rule = {
  id: 'MMKV_UNENCRYPTED_SENSITIVE_DATA',
  description: 'react-native-mmkv storage without encryption holding sensitive data, or hardcoded encryption key',
  severity: Severity.MEDIUM,
  fileTypes: JS_FILES,
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const imports = collectImports(context.ast);
    const isMmkv = (s: string) => s === 'react-native-mmkv';
    const ctorNames = localsFor(imports, isMmkv, 'MMKV');
    const factoryNames = localsFor(imports, isMmkv, 'createMMKV');
    if (ctorNames.size === 0 && factoryNames.size === 0) return findings;

    const isMmkvCreate = (node: any): boolean =>
      (node.type === 'NewExpression' && node.callee.type === 'Identifier' && ctorNames.has(node.callee.name)) ||
      (node.type === 'CallExpression' && node.callee.type === 'Identifier' && factoryNames.has(node.callee.name));

    /** 'encrypted' | 'plain' | 'unknown' for the config argument of a constructor call. */
    const classify = (node: any): 'encrypted' | 'plain' | 'unknown' => {
      const arg = node.arguments[0];
      if (!arg) return 'plain';
      if (arg.type !== 'ObjectExpression') return 'unknown';
      if (arg.properties.some((p: any) => p.type !== 'ObjectProperty')) return 'unknown';
      return arg.properties.some((p: any) => propName(p.key) === 'encryptionKey') ? 'encrypted' : 'plain';
    };

    traverse(context.ast, {
      // Hardcoded encryptionKey
      ObjectProperty(path: any) {
        const { node } = path;
        if (propName(node.key) !== 'encryptionKey' || node.computed) return;
        const parent = path.parentPath?.parentPath?.node;
        if (!parent || !isMmkvCreate(parent)) return;
        const v = node.value;
        const literal =
          v.type === 'StringLiteral'
            ? v.value
            : v.type === 'TemplateLiteral' && v.expressions.length === 0
              ? v.quasis[0].value.cooked
              : null;
        if (!literal) return;
        findings.push(
          makeFinding(context, node, {
            ruleId: 'MMKV_UNENCRYPTED_SENSITIVE_DATA',
            description: 'MMKV encryptionKey is a hardcoded string literal',
            severity: Severity.MEDIUM,
            confidence: 'medium',
            reason:
              'A key literal in source ships inside the app bundle, so anyone who unpacks the app can recover it and decrypt the MMKV file.',
            suggestion:
              'Generate a random key per install, keep it in the Keychain/Keystore (e.g. expo-secure-store) and read it at startup.',
          })
        );
      },

      // Unencrypted instance that receives sensitive keys
      VariableDeclarator(path: any) {
        const { node } = path;
        if (node.id.type !== 'Identifier' || !node.init || !isMmkvCreate(node.init)) return;
        if (classify(node.init) !== 'plain') return;

        const binding = path.scope.getBinding(node.id.name);
        if (!binding) return;

        for (const ref of binding.referencePaths) {
          const member = ref.parent;
          if (
            member?.type !== 'MemberExpression' ||
            member.object !== ref.node ||
            memberPropName(member) !== 'set'
          ) {
            continue;
          }
          const call = ref.parentPath.parent;
          if (call?.type !== 'CallExpression' || call.callee !== member) continue;
          const text = keyText(call.arguments[0]);
          const hit = text ? sensitiveKeyToken(text) : null;
          if (!hit) continue;

          findings.push(
            makeFinding(context, node, {
              ruleId: 'MMKV_UNENCRYPTED_SENSITIVE_DATA',
              description: `MMKV instance "${node.id.name}" has no encryptionKey but stores sensitive data (key "${text}" on line ${getLineNumber(context.fileContent, call.start || 0)})`,
              severity: Severity.MEDIUM,
              confidence: 'medium',
              reason:
                'Unencrypted MMKV files are stored as plain data in the app sandbox and can be read from backups or on rooted/jailbroken devices.',
              suggestion:
                'Pass an encryptionKey (kept in Keychain/Keystore) when creating the instance, or store secrets with expo-secure-store / react-native-keychain.',
            })
          );
          break; // one finding per instance
        }
      },
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// 4. SQLITE_QUERY_INJECTION
// ---------------------------------------------------------------------------

const SQLITE_MODULES = new Set([
  'expo-sqlite',
  'expo-sqlite/legacy',
  'expo-sqlite/next',
  'react-native-sqlite-storage',
  '@op-engineering/op-sqlite',
  'react-native-quick-sqlite',
]);
const SQLITE_METHODS = new Set([
  'execAsync', 'runAsync', 'getFirstAsync', 'getAllAsync', 'getEachAsync', 'prepareAsync',
  'execSync', 'runSync', 'getFirstSync', 'getAllSync', 'getEachSync', 'prepareSync',
  'executeSql', 'execute', 'executeSync', 'executeRaw',
]);
const SQL_KEYWORD = /\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|CREATE|DROP|ALTER|VALUES)\b/i;
const SQL_DDL_START = /^\s*(CREATE|ALTER|DROP)\b/i;
const USER_INPUT_TOKENS = new Set([
  'INPUT', 'QUERY', 'SEARCH', 'TERM', 'KEYWORD', 'NAME', 'ID', 'EMAIL', 'USERNAME', 'TEXT', 'VALUE', 'FILTER', 'Q',
]);
const NUMERIC_CALLEES = new Set(['Number', 'parseInt', 'parseFloat']);

/** Flattens a template literal / `+` chain into static text pieces and dynamic expressions. */
function collectSql(node: any, statics: string[], exprs: any[]): void {
  switch (node.type) {
    case 'StringLiteral':
      statics.push(node.value);
      return;
    case 'NumericLiteral':
    case 'BooleanLiteral':
    case 'NullLiteral':
      return;
    case 'TemplateLiteral':
      node.quasis.forEach((q: any) => statics.push(q.value.cooked ?? ''));
      node.expressions.forEach((e: any) => exprs.push(e));
      return;
    case 'BinaryExpression':
      if (node.operator === '+') {
        collectSql(node.left, statics, exprs);
        collectSql(node.right, statics, exprs);
        return;
      }
      exprs.push(node);
      return;
    case 'TSAsExpression':
    case 'TSNonNullExpression':
      collectSql(node.expression, statics, exprs);
      return;
    default:
      exprs.push(node);
  }
}

const sqliteQueryInjectionRule: Rule = {
  id: 'SQLITE_QUERY_INJECTION',
  description: 'SQLite query built with string interpolation instead of bound parameters',
  severity: Severity.MEDIUM,
  fileTypes: JS_FILES,
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const imports = collectImports(context.ast);
    if (!hasSource(imports, s => SQLITE_MODULES.has(s))) return findings;

    const text = (n: any): string => context.fileContent.slice(n.start || 0, n.end || 0);
    const PLACEHOLDER = /['"`]\?['"`]/;

    const isConstLiteral = (path: any, node: any): boolean => {
      if (node.type !== 'Identifier') return false;
      const b = path.scope.getBinding(node.name);
      if (!b || b.kind !== 'const' || b.scope.block.type !== 'Program') return false;
      const init = b.path.node.init;
      return !!init && (init.type === 'StringLiteral' || init.type === 'NumericLiteral');
    };

    const isNumericSafe = (node: any): boolean => {
      if (node.type === 'NumericLiteral') return true;
      if (node.type === 'MemberExpression' && memberPropName(node) === 'length') return true;
      if (node.type === 'CallExpression') {
        const c = node.callee;
        if (c.type === 'Identifier' && NUMERIC_CALLEES.has(c.name)) return true;
        if (c.type === 'MemberExpression' && c.object.type === 'Identifier') {
          if (c.object.name === 'Math') return true;
          if (c.object.name === 'Date' && memberPropName(c) === 'now') return true;
        }
      }
      return false;
    };

    const isPlaceholderList = (path: any, node: any): boolean => {
      if (PLACEHOLDER.test(text(node))) return true;
      if (node.type === 'Identifier') {
        const b = path.scope.getBinding(node.name);
        const init = b?.path.node.type === 'VariableDeclarator' ? b.path.node.init : null;
        return !!init && PLACEHOLDER.test(text(init));
      }
      return false;
    };

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        if (node.callee.type !== 'MemberExpression') return;
        const method = memberPropName(node.callee);
        if (!method || !SQLITE_METHODS.has(method)) return;

        const sqlArg = node.arguments[0];
        if (!sqlArg || (sqlArg.type !== 'TemplateLiteral' && sqlArg.type !== 'BinaryExpression')) return;

        const statics: string[] = [];
        const exprs: any[] = [];
        collectSql(sqlArg, statics, exprs);
        if (exprs.length === 0) return;

        const sqlText = statics.join(' ');
        if (!SQL_KEYWORD.test(sqlText)) return;

        // `IN (${ids.map(() => '?').join(',')})` with bound params is the safe idiom.
        const dynamic = exprs.filter(e => !isPlaceholderList(path, e) && !isNumericSafe(e));
        if (dynamic.length === 0) return;

        const allConst = dynamic.every(e => isConstLiteral(path, e));
        if (allConst && SQL_DDL_START.test(sqlText)) return;

        const hasBinding = node.arguments.length > 1;
        const userControlled = dynamic.some(e => {
          if (e.type !== 'Identifier') return false;
          const b = path.scope.getBinding(e.name);
          return b?.kind === 'param' && tokenize(e.name).some(t => USER_INPUT_TOKENS.has(t));
        });

        const severity = userControlled && !hasBinding ? Severity.HIGH : Severity.MEDIUM;
        const confidence = allConst ? 'low' : 'medium';

        findings.push(
          makeFinding(context, node, {
            ruleId: 'SQLITE_QUERY_INJECTION',
            description: `SQL passed to ${method}() is built with ${sqlArg.type === 'TemplateLiteral' ? 'template interpolation' : 'string concatenation'} of non-constant values`,
            severity,
            confidence,
            reason:
              'Interpolated values become part of the SQL text, so crafted input (deep link params, search boxes, synced data) can change the query. ' +
              (method === 'execAsync' ? 'expo-sqlite documents that execAsync() does not escape parameters. ' : ''),
            suggestion:
              'Use placeholders and pass values as bound parameters, e.g. db.getAllAsync("SELECT * FROM t WHERE name = ?", [name]). Table/column names cannot be bound; validate them against a whitelist.',
          })
        );
      },
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// 5. OAUTH_INSECURE_FLOW
// ---------------------------------------------------------------------------

const IMPLICIT_URL = /response_type=(?:token|id_token%20token|id_token\+token|token%20id_token|token\+id_token)(?![A-Za-z0-9_])/;

const oauthInsecureFlowRule: Rule = {
  id: 'OAUTH_INSECURE_FLOW',
  description: 'OAuth flow configured without PKCE/nonce or using the implicit grant',
  severity: Severity.MEDIUM,
  fileTypes: JS_FILES,
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const imports = collectImports(context.ast);
    const isExpoAuth = (s: string) => s === 'expo-auth-session' || s.startsWith('expo-auth-session/');
    const isAppAuth = (s: string) => s === 'react-native-app-auth';
    const usesExpoAuth = hasSource(imports, isExpoAuth);
    const usesAppAuth = hasSource(imports, isAppAuth);
    const mentionsAuthRequest = /\bAuthRequest\b/.test(context.fileContent);
    if (!usesExpoAuth && !usesAppAuth && !mentionsAuthRequest) return findings;

    const implicitReason =
      'The implicit flow returns the access token in the redirect URL, where other apps registered for the same scheme, browser history and logs can capture it. It is deprecated by OAuth 2.0 Security BCP / OAuth 2.1.';

    const add = (node: any, description: string, reason: string, suggestion: string) =>
      findings.push(
        makeFinding(context, node, {
          ruleId: 'OAUTH_INSECURE_FLOW',
          description,
          severity: Severity.MEDIUM,
          confidence: 'high',
          reason,
          suggestion,
        })
      );

    const isTokenResponseType = (v: any): boolean => {
      if (v.type === 'StringLiteral') return v.value.split(/\s+/).includes('token');
      if (v.type === 'MemberExpression') {
        return (
          memberPropName(v) === 'Token' &&
          (v.object.type === 'Identifier'
            ? v.object.name === 'ResponseType'
            : v.object.type === 'MemberExpression' && memberPropName(v.object) === 'ResponseType')
        );
      }
      return false;
    };

    const checkUrlText = (node: any, value: string) => {
      if (IMPLICIT_URL.test(value)) {
        add(
          node,
          'Authorization URL requests response_type=token (OAuth implicit flow)',
          implicitReason,
          'Use the authorization code flow with PKCE (response_type=code) and exchange the code at the token endpoint.'
        );
      }
    };

    traverse(context.ast, {
      ObjectProperty(path: any) {
        const { node } = path;
        if (node.computed) return;
        const key = propName(node.key);
        const v = node.value;

        if (key === 'usePKCE' && v.type === 'BooleanLiteral' && v.value === false) {
          add(
            node,
            'OAuth request configured with usePKCE: false',
            'Without PKCE, a malicious app that intercepts the redirect (custom URL scheme) can redeem the authorization code itself.',
            'Remove usePKCE: false so the library uses PKCE (S256) with the authorization code flow.'
          );
        } else if (key === 'useNonce' && v.type === 'BooleanLiteral' && v.value === false && usesAppAuth) {
          add(
            node,
            'react-native-app-auth configured with useNonce: false',
            'The nonce binds the ID token to this login request; without it a captured ID token can be replayed.',
            'Remove useNonce: false (the default is true).'
          );
        } else if ((key === 'responseType' || key === 'response_type') && isTokenResponseType(v)) {
          add(
            node,
            'OAuth responseType "token" selects the implicit flow',
            implicitReason,
            'Use ResponseType.Code with PKCE and exchange the code at the token endpoint.'
          );
        }
      },

      StringLiteral(path: any) {
        checkUrlText(path.node, path.node.value);
      },

      TemplateLiteral(path: any) {
        checkUrlText(path.node, path.node.quasis.map((q: any) => q.value.cooked ?? '').join('\u0000'));
      },
    });

    return findings;
  },
};

export const rnSecurityRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [
    tlsValidationDisabledEnvRule,
    bundledEnvSecretRule,
    mmkvUnencryptedSensitiveDataRule,
    sqliteQueryInjectionRule,
    oauthInsecureFlowRule,
  ],
};
