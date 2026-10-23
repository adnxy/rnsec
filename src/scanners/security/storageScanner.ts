import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { containsSensitiveKeyword, getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import {
  API_SECRET_PATTERNS,
  hasNonSecretQualifier,
  hasSensitiveWord,
  isCredentialKeyName,
  isPiiKeyName,
  isPlaceholderValue,
  looksRandom,
  shannonEntropy,
  tokenizeIdentifier,
} from '../../utils/sensitiveDataPatterns.js';

// ---------------------------------------------------------------------------
// AST helpers
// ---------------------------------------------------------------------------

interface ModuleAliases {
  /** Local names bound to the module itself (default / namespace import, require result) */
  objects: Set<string>;
  /** Local names bound to one of its named exports: local -> exported name */
  named: Map<string, string>;
}

/** Follow `import X from 'mod'`, `import * as X`, `import { fn as f }` and `require('mod')` for matching modules. */
function collectModuleAliases(
  ast: any,
  matches: (source: string) => boolean,
  options: { defaults?: string[]; legacyReactNativeExport?: string } = {}
): ModuleAliases {
  const aliases: ModuleAliases = { objects: new Set(options.defaults ?? []), named: new Map() };

  traverse(ast, {
    ImportDeclaration(path: any) {
      const source: string = path.node.source.value;
      const moduleMatches = matches(source);
      for (const spec of path.node.specifiers) {
        if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
          if (moduleMatches) aliases.objects.add(spec.local.name);
        } else if (spec.type === 'ImportSpecifier') {
          const imported = spec.imported.type === 'Identifier' ? spec.imported.name : spec.imported.value;
          if (moduleMatches) {
            if (imported === 'default') aliases.objects.add(spec.local.name);
            else aliases.named.set(spec.local.name, imported);
          } else if (source === 'react-native' && imported === options.legacyReactNativeExport) {
            aliases.objects.add(spec.local.name);
          }
        }
      }
    },
    VariableDeclarator(path: any) {
      let init = path.node.init;
      if (init?.type === 'MemberExpression' && init.property?.name === 'default') init = init.object;
      if (
        init?.type === 'CallExpression' &&
        init.callee.type === 'Identifier' &&
        init.callee.name === 'require' &&
        init.arguments[0]?.type === 'StringLiteral' &&
        matches(init.arguments[0].value)
      ) {
        const id = path.node.id;
        if (id.type === 'Identifier') {
          aliases.objects.add(id.name);
        } else if (id.type === 'ObjectPattern') {
          for (const prop of id.properties) {
            if (prop.type === 'ObjectProperty' && prop.key.type === 'Identifier' && prop.value.type === 'Identifier') {
              aliases.named.set(prop.value.name, prop.key.name);
            }
          }
        }
      }
    },
  });

  return aliases;
}

/** Resolve a node to the string it holds, following const bindings, template literals and `a + b`. */
function resolveString(node: any, scope: any, depth = 0): string | null {
  if (!node || depth > 4) return null;
  switch (node.type) {
    case 'StringLiteral':
      return node.value;
    case 'TemplateLiteral': {
      // Text around the expressions is enough to recognise "user_${id}_token"
      const text = node.quasis.map((q: any) => q.value.cooked ?? '').join('_');
      return text.replace(/_+/g, '_').replace(/^_|_$/g, '') || null;
    }
    case 'BinaryExpression': {
      if (node.operator !== '+') return null;
      const left = resolveString(node.left, scope, depth + 1);
      const right = resolveString(node.right, scope, depth + 1);
      return left !== null || right !== null ? `${left ?? ''}_${right ?? ''}` : null;
    }
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'TSSatisfiesExpression':
      return resolveString(node.expression, scope, depth + 1);
    case 'Identifier': {
      const binding = scope?.getBinding(node.name);
      if (!binding?.constant || !binding.path.isVariableDeclarator()) return null;
      return resolveString(binding.path.node.init, binding.scope, depth + 1);
    }
    case 'MemberExpression': {
      const propName =
        !node.computed && node.property.type === 'Identifier'
          ? node.property.name
          : node.property.type === 'StringLiteral'
            ? node.property.value
            : null;
      if (!propName || node.object.type !== 'Identifier') return null;
      const binding = scope?.getBinding(node.object.name);
      if (!binding) return null;
      const declNode = binding.path.node;
      if (binding.path.isVariableDeclarator() && binding.constant) {
        let obj = declNode.init;
        while (obj && ['TSAsExpression', 'TSSatisfiesExpression'].includes(obj.type)) obj = obj.expression;
        if (obj?.type !== 'ObjectExpression') return null;
        for (const prop of obj.properties) {
          if (prop.type !== 'ObjectProperty') continue;
          const k = prop.key.type === 'Identifier' ? prop.key.name : prop.key.value;
          if (k === propName) return resolveString(prop.value, binding.scope, depth + 1);
        }
      } else if (binding.path.isTSEnumDeclaration?.()) {
        for (const member of declNode.members) {
          const k = member.id.type === 'Identifier' ? member.id.name : member.id.value;
          if (k === propName && member.initializer) return resolveString(member.initializer, binding.scope, depth + 1);
        }
      }
      return null;
    }
    default:
      return null;
  }
}

/** Identifier / property names and template text inside an expression (one level of const lookup). */
function collectWords(node: any, scope: any, followBinding = true): string[] {
  const words: string[] = [];
  const visit = (n: any) => {
    if (!n || typeof n.type !== 'string') return;
    if (n.type === 'Identifier') {
      words.push(n.name);
      if (followBinding) {
        const binding = scope?.getBinding(n.name);
        if (binding?.constant && binding.path.isVariableDeclarator() && binding.path.node.init) {
          words.push(...collectWords(binding.path.node.init, binding.scope, false));
        }
      }
      return;
    }
    if (n.type === 'StringLiteral' && n.value.length <= 40) words.push(n.value);
    if (n.type === 'TemplateElement' && n.value.cooked) words.push(n.value.cooked);
    for (const key of Object.keys(n)) {
      if (['loc', 'start', 'end', 'leadingComments', 'trailingComments', 'innerComments', 'extra'].includes(key)) continue;
      const child = n[key];
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child === 'object') visit(child);
    }
  };
  visit(node);
  return words;
}

const propName = (member: any): string | null =>
  member?.type !== 'MemberExpression'
    ? null
    : !member.computed && member.property.type === 'Identifier'
      ? member.property.name
      : member.property.type === 'StringLiteral'
        ? member.property.value
        : null;

// ---------------------------------------------------------------------------
// AsyncStorage: shared detection of `setItem(<key>, ...)` through aliases and wrappers
// ---------------------------------------------------------------------------

const ASYNC_STORAGE_SOURCES = new Set([
  '@react-native-async-storage/async-storage',
  '@react-native-community/async-storage',
  'react-native-async-storage',
]);
const ENCRYPTING_WRAPPER = /encrypt|secure|cipher|crypt/i;
const ASYNC_STORAGE_WRITE_METHODS = new Set(['setItem', 'mergeItem', 'multiSet', 'multiMerge']);

interface StorageWrite {
  node: any;
  key: string;
}

const storageWritesCache = new WeakMap<object, StorageWrite[]>();

function findAsyncStorageWrites(ast: any): StorageWrite[] {
  const cached = storageWritesCache.get(ast);
  if (cached) return cached;

  const aliases = collectModuleAliases(ast, s => ASYNC_STORAGE_SOURCES.has(s), {
    defaults: ['AsyncStorage'],
    legacyReactNativeExport: 'AsyncStorage',
  });
  const storageNames = aliases.objects;
  /** `this.storage = AsyncStorage`, `{ storage: AsyncStorage }` ... referenced as `<x>.storage` */
  const storageProps = new Set<string>();
  /** `const { setItem } = AsyncStorage` and `import { setItem }` -> local fn name -> method */
  const directFns = new Map<string, string>();
  for (const [local, imported] of aliases.named) {
    if (ASYNC_STORAGE_WRITE_METHODS.has(imported)) directFns.set(local, imported);
  }
  /** In-file helpers that forward a parameter as the storage key: name -> parameter index */
  const wrappers = new Map<string, number>();

  const isStorageRef = (n: any): boolean => {
    if (!n) return false;
    if (n.type === 'Identifier') return storageNames.has(n.name);
    if (n.type === 'MemberExpression') {
      const p = propName(n);
      if (p === 'default' && n.object.type === 'Identifier') return storageNames.has(n.object.name);
      return p !== null && storageProps.has(p);
    }
    return false;
  };
  /** An expression that hands the storage object to something (createJSONStorage(() => AsyncStorage)). */
  const carriesStorage = (n: any): boolean => {
    if (!n) return false;
    if (isStorageRef(n)) return true;
    if (n.type === 'ArrowFunctionExpression') return carriesStorage(n.body);
    if (n.type === 'ObjectExpression') return n.properties.some((p: any) => p.type === 'ObjectProperty' && carriesStorage(p.value));
    if (n.type === 'CallExpression' || n.type === 'NewExpression') {
      // createEncryptedStorage(AsyncStorage) and friends are not plain AsyncStorage
      const callee = n.callee.type === 'Identifier' ? n.callee.name : propName(n.callee) ?? '';
      if (ENCRYPTING_WRAPPER.test(callee)) return false;
      return n.arguments.some((a: any) => carriesStorage(a));
    }
    return false;
  };

  // Alias discovery. Two passes so `const a = AsyncStorage; const b = wrap(a)` resolves.
  for (let pass = 0; pass < 2; pass++) {
    traverse(ast, {
      VariableDeclarator(path: any) {
        const { id, init } = path.node;
        if (!init) return;
        if (id.type === 'Identifier' && carriesStorage(init)) {
          storageNames.add(id.name);
        } else if (id.type === 'ObjectPattern' && isStorageRef(init)) {
          for (const prop of id.properties) {
            if (
              prop.type === 'ObjectProperty' &&
              prop.key.type === 'Identifier' &&
              prop.value.type === 'Identifier' &&
              ASYNC_STORAGE_WRITE_METHODS.has(prop.key.name)
            ) {
              directFns.set(prop.value.name, prop.key.name);
            }
          }
        }
      },
      AssignmentExpression(path: any) {
        const { left, right } = path.node;
        const name = propName(left);
        if (name && carriesStorage(right)) storageProps.add(name);
        if (left.type === 'Identifier' && carriesStorage(right)) storageNames.add(left.name);
      },
      ClassProperty(path: any) {
        const { key, value } = path.node;
        if (key?.type === 'Identifier' && carriesStorage(value)) storageProps.add(key.name);
      },
    });
  }

  const storageMethod = (callee: any): string | null => {
    if (callee.type === 'MemberExpression') {
      const m = propName(callee);
      return m && ASYNC_STORAGE_WRITE_METHODS.has(m) && isStorageRef(callee.object) ? m : null;
    }
    if (callee.type === 'Identifier') return directFns.get(callee.name) ?? null;
    return null;
  };

  // Wrapper discovery: function save(key, value) { return AsyncStorage.setItem(key, value) }
  const registerWrapper = (name: string, fn: any, fnPath: any) => {
    const params: string[] = fn.params.map((p: any) => (p.type === 'Identifier' ? p.name : ''));
    fnPath.traverse({
      CallExpression(inner: any) {
        const method = storageMethod(inner.node.callee);
        if (method !== 'setItem' && method !== 'mergeItem') return;
        const first = inner.node.arguments[0];
        if (first?.type === 'Identifier' && params.includes(first.name)) wrappers.set(name, params.indexOf(first.name));
      },
    });
  };
  traverse(ast, {
    FunctionDeclaration(path: any) {
      if (path.node.id) registerWrapper(path.node.id.name, path.node, path);
    },
    VariableDeclarator(path: any) {
      const { id, init } = path.node;
      if (id.type !== 'Identifier' || !init) return;
      if (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression') {
        registerWrapper(id.name, init, path.get('init'));
      } else if (init.type === 'ObjectExpression') {
        path.get('init.properties').forEach((propPath: any) => {
          const prop = propPath.node;
          if (prop.type === 'ObjectProperty' && ['ArrowFunctionExpression', 'FunctionExpression'].includes(prop.value.type)) {
            const k = prop.key.type === 'Identifier' ? prop.key.name : prop.key.value;
            registerWrapper(`${id.name}.${k}`, prop.value, propPath.get('value'));
          } else if (prop.type === 'ObjectMethod') {
            const k = prop.key.type === 'Identifier' ? prop.key.name : prop.key.value;
            registerWrapper(`${id.name}.${k}`, prop, propPath);
          }
        });
      }
    },
  });

  const writes: StorageWrite[] = [];
  traverse(ast, {
    CallExpression(path: any) {
      const { node } = path;
      const keyNodes: any[] = [];

      const method = storageMethod(node.callee);
      if (method === 'multiSet' || method === 'multiMerge') {
        const pairs = node.arguments[0];
        if (pairs?.type === 'ArrayExpression') {
          for (const pair of pairs.elements) {
            if (pair?.type === 'ArrayExpression' && pair.elements[0]) keyNodes.push(pair.elements[0]);
          }
        }
      } else if (method) {
        if (node.arguments[0]) keyNodes.push(node.arguments[0]);
      } else {
        const calleeName =
          node.callee.type === 'Identifier'
            ? node.callee.name
            : node.callee.type === 'MemberExpression' && node.callee.object.type === 'Identifier' && propName(node.callee)
              ? `${node.callee.object.name}.${propName(node.callee)}`
              : null;
        const idx = calleeName !== null ? wrappers.get(calleeName) : undefined;
        if (idx !== undefined && node.arguments[idx]) keyNodes.push(node.arguments[idx]);
      }

      for (const keyNode of keyNodes) {
        const key = resolveString(keyNode, path.scope);
        if (key) writes.push({ node, key });
      }
    },
  });

  storageWritesCache.set(ast, writes);
  return writes;
}

const asyncStorageSensitiveKeyRule: Rule = {
  id: 'ASYNCSTORAGE_SENSITIVE_KEY',
  description: 'AsyncStorage used with sensitive key names (token, password, auth, secret)',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    for (const { node, key } of findAsyncStorageWrites(context.ast)) {
      if (!isCredentialKeyName(key)) continue;
      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'ASYNCSTORAGE_SENSITIVE_KEY',
        description: `AsyncStorage storing sensitive key: "${key}"`,
        severity: Severity.HIGH,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Use encrypted storage like expo-secure-store or react-native-keychain for sensitive data',
      });
    }

    return findings;
  },
};

const asyncStoragePiiDataRule: Rule = {
  id: 'ASYNCSTORAGE_PII_DATA',
  description: 'AsyncStorage storing PII (email, phone, SSN) without encryption',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    for (const { node, key } of findAsyncStorageWrites(context.ast)) {
      if (!isPiiKeyName(key)) continue;
      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'ASYNCSTORAGE_PII_DATA',
        description: `AsyncStorage storing PII data with key: "${key}"`,
        severity: Severity.HIGH,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Use encrypted storage (expo-secure-store, react-native-keychain, or MMKV with encryption) for PII data',
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// HARDCODED_SECRETS
// ---------------------------------------------------------------------------

type SecretKind = 'password' | 'secret' | 'apikey' | 'token';

/** Words in a name that say "this is not a credential value" (labels, test data, formats ...). */
const IGNORED_NAME_TOKENS = new Set([
  'test', 'tests', 'mock', 'mocks', 'fixture', 'example', 'examples', 'dummy', 'sample', 'placeholder',
  'label', 'title', 'text', 'message', 'msg', 'error', 'hint', 'help', 'description', 'prompt', 'tooltip',
  'url', 'uri', 'path', 'endpoint', 'regex', 'pattern', 'format', 'charset', 'alphabet', 'characters',
  'letters', 'digits', 'allowed', 'template', 'field', 'input', 'route', 'screen', 'header', 'headers',
  'storage', 'name', 'type', 'param', 'params', 'prefix', 'suffix', 'id', 'cookie',
]);

const PROVIDER_PATTERNS = API_SECRET_PATTERNS
  .filter(p => !p.generic && p.name !== 'JWT Token')
  .map(p => new RegExp(p.pattern.source, p.pattern.flags.replace('g', '')));

function classifySecretName(name: string): SecretKind | null {
  const tokens = tokenizeIdentifier(name);
  if (tokens.length === 0 || tokens.some(t => IGNORED_NAME_TOKENS.has(t)) || hasNonSecretQualifier(tokens, true)) return null;
  const has = (...words: string[]) => words.some(w => tokens.includes(w));
  const pair = (a: string, b: string) => tokens.some((t, i) => t === a && tokens[i + 1] === b);
  const isKeyWord = tokens.includes('key');

  if (has('password', 'passwd', 'pwd', 'passcode')) return isKeyWord ? null : 'password';
  if (has('secret', 'secrets', 'privatekey', 'secretkey', 'clientsecret', 'encryptionkey', 'signingkey') ||
      pair('private', 'key') || pair('encryption', 'key') || pair('signing', 'key')) return 'secret';
  if (has('apikey', 'accesskey') || pair('api', 'key') || pair('access', 'key')) return 'apikey';
  if (has('token', 'jwt', 'bearer', 'accesstoken', 'refreshtoken', 'authtoken', 'idtoken', 'sessiontoken', 'apitoken')) {
    // TOKEN_KEY = 'auth_token' names the storage slot, it is not the token
    return isKeyWord ? null : 'token';
  }
  return null;
}

const LABEL_WORDS = new Set([
  'new', 'old', 'confirm', 'current', 'repeat', 'enter', 'your', 'the', 'my', 'forgot', 'reset', 'change',
  'show', 'hide', 'input', 'field', 'label', 'text', 'secure', 'entry', 'please', 'user', 'login', 'sign', 'in',
]);

/** Returns null when the literal is not a plausible hardcoded credential for a variable called `name`. */
function evaluateSecretValue(kind: SecretKind, name: string, value: string): 'high' | 'medium' | null {
  // Provider-format secrets (and public-by-design keys) belong to API_KEY_EXPOSED. JWTs stay here:
  // API_KEY_EXPOSED drops the well-known sample token, HARDCODED_SECRETS keeps judging by name.
  if (PROVIDER_PATTERNS.some(p => p.test(value))) return null;
  if (/\s/.test(value)) return null; // sentences, UI text
  if (isPlaceholderValue(value, true)) return null;
  if (/^(https?|wss?|file|data):/i.test(value) || /^\.{0,2}\//.test(value) || /^@[\w-]+\/[\w.\-/]+$/.test(value)) return null;
  // i18n keys and enum-like strings: 'auth.password.label' (a JWT is dotted too, but starts with eyJ)
  if (/^[a-z][\w-]*(\.[\w-]+)+$/i.test(value) && !value.startsWith('eyJ')) return null;

  const nameTokens = new Set(tokenizeIdentifier(name));
  const valueTokens = tokenizeIdentifier(value);
  if (valueTokens.length > 0 && valueTokens.every(t => nameTokens.has(t) || LABEL_WORDS.has(t))) return null;

  if (kind === 'password') {
    if (value.length < 8 || !/[^A-Za-z]/.test(value)) return null;
    return 'medium';
  }

  const minLength = kind === 'secret' ? 12 : 16;
  if (value.length < minLength || !looksRandom(value, 3.0)) return null;
  return value.length >= 20 && shannonEntropy(value) >= 3.5 ? 'high' : 'medium';
}

function literalValue(node: any): string | null {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0 && node.quasis.length === 1) {
    return node.quasis[0].value.cooked ?? null;
  }
  return null;
}

const hardcodedSecretsRule: Rule = {
  id: 'HARDCODED_SECRETS',
  description: 'Hardcoded secrets or tokens detected in source code',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const check = (name: string | null, valueNode: any, startNode: any, what: string) => {
      if (!name) return;
      const value = literalValue(valueNode);
      if (value === null) return; // env lookups, calls, identifiers: not a hardcoded literal
      const kind = classifySecretName(name);
      if (!kind) return;
      const confidence = evaluateSecretValue(kind, name, value);
      if (!confidence) return;

      const line = getLineNumber(context.fileContent, startNode.start || 0);
      const finding: Finding = {
        ruleId: 'HARDCODED_SECRETS',
        description: `Potential hardcoded secret in ${what} "${name}"`,
        severity: Severity.HIGH,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Move secrets to environment variables or secure config management',
      };
      if (confidence === 'medium') finding.confidence = 'medium';
      findings.push(finding);
    };

    traverse(context.ast, {
      VariableDeclarator(path: any) {
        const { node } = path;
        if (node.id.type === 'Identifier') check(node.id.name, node.init, node, 'variable');
      },
      ObjectProperty(path: any) {
        const { node } = path;
        if (node.computed) return;
        const keyName = node.key.type === 'Identifier' ? node.key.name : node.key.type === 'StringLiteral' ? node.key.value : null;
        check(keyName, node.value, node, 'property');
      },
      ClassProperty(path: any) {
        const { node } = path;
        if (node.key?.type === 'Identifier' && !node.computed) check(node.key.name, node.value, node, 'property');
      },
      AssignmentExpression(path: any) {
        const { node } = path;
        if (node.operator !== '=') return;
        const target = node.left.type === 'Identifier' ? node.left.name : propName(node.left);
        check(target, node.right, node, 'assignment to');
      },
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// REDUX_PERSIST_NO_ENCRYPTION
// ---------------------------------------------------------------------------

const SENSITIVE_REDUCER_WORDS = new Set(['auth', 'authentication', 'user', 'users', 'payment', 'payments', 'session', 'token', 'tokens', 'credentials', 'account']);
const SECURE_STORAGE_HINT = /secure|encrypt|keychain|keystore|sensitive/i;

const reduxPersistNoEncryptionRule: Rule = {
  id: 'REDUX_PERSIST_NO_ENCRYPTION',
  description: 'Redux persist configuration without encryption transform for sensitive data',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;

        if (
          node.callee.type === 'Identifier' &&
          (node.callee.name === 'persistStore' || node.callee.name === 'persistReducer')
        ) {
          let configArg = node.arguments[0];
          // const persistConfig = { ... }; persistReducer(persistConfig, reducer)
          if (configArg?.type === 'Identifier') {
            const binding = path.scope.getBinding(configArg.name);
            if (binding?.constant && binding.path.isVariableDeclarator()) {
              configArg = binding.path.node.init;
              while (configArg && ['TSAsExpression', 'TSSatisfiesExpression'].includes(configArg.type)) configArg = configArg.expression;
            }
          }
          if (configArg && configArg.type === 'ObjectExpression') {
            let hasTransforms = false;
            let hasWhitelist = false;
            let whitelistContainsSensitive = false;
            let usesSecureStorage = false;

            configArg.properties.forEach((prop: any) => {
              const keyName = prop.key && (prop.key.name ?? prop.key.value);
              if (keyName === 'transforms') {
                hasTransforms = true;
              }

              if (keyName === 'storage' && prop.value) {
                const text = context.fileContent.substring(prop.value.start || 0, prop.value.end || 0);
                usesSecureStorage = SECURE_STORAGE_HINT.test(text);
              }

              if (keyName === 'whitelist' && prop.value.type === 'ArrayExpression') {
                hasWhitelist = true;
                prop.value.elements.forEach((el: any) => {
                  if (el && el.type === 'StringLiteral') {
                    if (tokenizeIdentifier(el.value).some(t => SENSITIVE_REDUCER_WORDS.has(t))) {
                      whitelistContainsSensitive = true;
                    }
                  }
                });
              }
            });

            if (hasWhitelist && whitelistContainsSensitive && !hasTransforms && !usesSecureStorage) {
              const line = getLineNumber(context.fileContent, node.start || 0);

              findings.push({
                ruleId: 'REDUX_PERSIST_NO_ENCRYPTION',
                description: 'Redux persist storing sensitive reducers without encryption transforms',
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Add encryption transform (redux-persist-sensitive-storage) to persistConfig for sensitive data',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// CLIPBOARD_SENSITIVE_DATA
// ---------------------------------------------------------------------------

const CLIPBOARD_SOURCES = new Set(['@react-native-clipboard/clipboard', '@react-native-community/clipboard', 'expo-clipboard']);
const CLIPBOARD_METHODS = new Set(['setString', 'setStringAsync']);

const clipboardSensitiveDataRule: Rule = {
  id: 'CLIPBOARD_SENSITIVE_DATA',
  description: 'Sensitive data copied to clipboard (accessible by other apps)',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const aliases = collectModuleAliases(context.ast, s => CLIPBOARD_SOURCES.has(s), {
      defaults: ['Clipboard'],
      legacyReactNativeExport: 'Clipboard',
    });

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        const callee = node.callee;

        const isClipboardCall =
          (callee.type === 'MemberExpression' &&
            callee.object.type === 'Identifier' &&
            aliases.objects.has(callee.object.name) &&
            CLIPBOARD_METHODS.has(propName(callee) ?? '')) ||
          (callee.type === 'Identifier' && CLIPBOARD_METHODS.has(aliases.named.get(callee.name) ?? ''));
        if (!isClipboardCall || !node.arguments[0]) return;

        // Judge by what is copied (names inside the argument), not by unrelated nearby code
        const words = collectWords(node.arguments[0], path.scope);
        if (!words.some(w => hasSensitiveWord(tokenizeIdentifier(w)))) return;

        const line = getLineNumber(context.fileContent, node.start || 0);
        findings.push({
          ruleId: 'CLIPBOARD_SENSITIVE_DATA',
          description: 'Sensitive data copied to clipboard - accessible by other apps',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Avoid copying sensitive data to clipboard. If necessary, clear clipboard after short timeout and notify user',
          confidence: 'medium',
        });
      },
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// INSECURE_FILE_STORAGE
// ---------------------------------------------------------------------------

const FILE_SYSTEM_SOURCES = new Set(['expo-file-system', 'expo-file-system/legacy', 'react-native-fs']);
const FILE_WRITE_METHODS = new Set(['writeAsStringAsync', 'writeFile', 'appendFile']);
// App-private locations (documentDirectory, cacheDirectory, DocumentDirectoryPath ...) are deliberately absent
const EXTERNAL_LOCATION =
  /external[a-z]*dir|downloaddir|picturesdir|dcimdir|moviesdir|musicdir|\/sdcard|\/storage\/emulated|\/downloads\b/i;
const ENCRYPTION_HINT = /encrypt|cipher|crypto|securestore|\baes\b/i;

const insecureFileStorageRule: Rule = {
  id: 'INSECURE_FILE_STORAGE',
  description: 'Files written to insecure storage locations',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const aliases = collectModuleAliases(context.ast, s => FILE_SYSTEM_SOURCES.has(s), {
      defaults: ['FileSystem', 'RNFS'],
    });

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        const callee = node.callee;

        const isWrite =
          (callee.type === 'MemberExpression' &&
            callee.object.type === 'Identifier' &&
            aliases.objects.has(callee.object.name) &&
            FILE_WRITE_METHODS.has(propName(callee) ?? '')) ||
          (callee.type === 'Identifier' && FILE_WRITE_METHODS.has(aliases.named.get(callee.name) ?? ''));
        if (!isWrite) return;

        const pathArg = node.arguments[0];
        const contentArg = node.arguments[1];
        if (!pathArg) return;

        const textOf = (n: any) => context.fileContent.substring(n.start || 0, n.end || 0);
        let pathText = textOf(pathArg);
        if (pathArg.type === 'Identifier') {
          const binding = path.scope.getBinding(pathArg.name);
          if (binding?.constant && binding.path.isVariableDeclarator() && binding.path.node.init) {
            pathText += ' ' + textOf(binding.path.node.init);
          }
        }
        const isExternal = EXTERNAL_LOCATION.test(pathText);

        const words = [
          ...collectWords(pathArg, path.scope),
          ...(contentArg ? collectWords(contentArg, path.scope) : []),
        ];
        const hasSensitiveData = words.some(w => hasSensitiveWord(tokenizeIdentifier(w)));
        const contentWords = contentArg ? collectWords(contentArg, path.scope).join(' ') : '';
        const hasEncryption = ENCRYPTION_HINT.test(contentWords);
        const writesPlaintextSecret = hasSensitiveData && !hasEncryption;

        const line = getLineNumber(context.fileContent, node.start || 0);
        if (isExternal) {
          findings.push({
            ruleId: 'INSECURE_FILE_STORAGE',
            description: writesPlaintextSecret
              ? 'Sensitive data written to external/shared storage - accessible by other apps'
              : 'File written to external/shared storage - accessible by other apps',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Use FileSystem.documentDirectory for app-private files. Encrypt sensitive data before writing to any storage.',
          });
        } else if (writesPlaintextSecret) {
          findings.push({
            ruleId: 'INSECURE_FILE_STORAGE',
            description: 'Sensitive data written to file without encryption',
            severity: Severity.MEDIUM,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Encrypt sensitive data before writing to files. Use expo-secure-store for credentials.',
            confidence: 'medium',
          });
        }
      },
    });

    return findings;
  },
};

const mmkvNoEncryptionRule: Rule = {
  id: 'MMKV_NO_ENCRYPTION',
  description: 'MMKV used without encryption for sensitive data',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    // Track MMKV instances created without encryption
    const unencryptedMmkvInstances = new Set<string>();

    // Helper function to check if createMMKV has encryption
    const hasEncryption = (configArg: any): boolean => {
      if (!configArg || configArg.type !== 'ObjectExpression') {
        return false;
      }
      
      return configArg.properties.some((prop: any) => {
        if (!prop.key) return false;
        const keyName = prop.key.name || (prop.key.type === 'StringLiteral' ? prop.key.value : null);
        return keyName === 'encryptionKey';
      });
    };

    // First traversal: Collect all unencrypted MMKV instances
    traverse(context.ast, {
      VariableDeclarator(path: any) {
        const { node } = path;
        
        // Check if this is a variable declaration with createMMKV()
        if (
          node.init &&
          node.init.type === 'CallExpression' &&
          node.init.callee.type === 'Identifier' &&
          node.init.callee.name === 'createMMKV'
        ) {
          const configArg = node.init.arguments[0];
          
          // If no encryption and variable is an identifier, track it
          if (!hasEncryption(configArg) && node.id.type === 'Identifier') {
            unencryptedMmkvInstances.add(node.id.name);
          }
        }
      },
    });

    // Second traversal: Find MMKV.set() calls with sensitive data
    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for direct createMMKV().set() calls without encryption
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'CallExpression' &&
          node.callee.object.callee.type === 'Identifier' &&
          node.callee.object.callee.name === 'createMMKV' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'set'
        ) {
          const configArg = node.callee.object.arguments[0];
          
          if (!hasEncryption(configArg)) {
            const keyArg = node.arguments[0];
            
            if (keyArg && keyArg.type === 'StringLiteral') {
              const key = keyArg.value;
              
              if (containsSensitiveKeyword(key)) {
                const line = getLineNumber(context.fileContent, node.start || 0);
                
                findings.push({
                  ruleId: 'MMKV_NO_ENCRYPTION',
                  description: `MMKV storing sensitive key "${key}" without encryption`,
                  severity: Severity.HIGH,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Use MMKV with encryption: createMMKV({ encryptionKey: "your-encryption-key" }) or use expo-secure-store/react-native-keychain for sensitive data',
                });
              }
            }
          }
        }
        
        // Check for MMKV.set() calls on tracked unencrypted instances
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'set'
        ) {
          const mmkvVarName = node.callee.object.name;
          
          // Check if this MMKV instance was created without encryption
          if (unencryptedMmkvInstances.has(mmkvVarName)) {
            const keyArg = node.arguments[0];
            
            // Check if key contains sensitive keywords
            if (keyArg && keyArg.type === 'StringLiteral') {
              const key = keyArg.value;
              
              if (containsSensitiveKeyword(key)) {
                const line = getLineNumber(context.fileContent, node.start || 0);
                
                findings.push({
                  ruleId: 'MMKV_NO_ENCRYPTION',
                  description: `MMKV storing sensitive key "${key}" without encryption`,
                  severity: Severity.HIGH,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Use MMKV with encryption: createMMKV({ encryptionKey: "your-encryption-key" }) or use expo-secure-store/react-native-keychain for sensitive data',
                });
              }
            }
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Does the code window mention credentials or other sensitive data? Works on whole identifiers
 * (split into words), so `token` / `authToken` / `Credentials` count but `tokenizer`, `authorName`,
 * `userAgent` and `passportPhoto` do not.
 */
const SENSITIVE_DOMAIN_WORDS = new Set(['payment', 'payments', 'medical', 'health']);
const USER_DATA_WORDS = new Set(['user', 'users', 'account', 'accounts', 'profile', 'profiles']);
const DATA_HOLDER_WORDS = new Set(['schema', 'model', 'db', 'database', 'store', 'data', 'info', 'entity', 'table', 'record', 'records']);

function hasSensitiveDataContext(window: string): boolean {
  for (const word of window.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? []) {
    if (isCredentialKeyName(word)) return true;
    const tokens = tokenizeIdentifier(word);
    if (tokens.some(t => SENSITIVE_DOMAIN_WORDS.has(t))) return true;
    // `UserSchema`, `accounts.db`: a user-data holder, but not `userAgent`
    if (tokens.some(t => USER_DATA_WORDS.has(t)) && tokens.every(t => USER_DATA_WORDS.has(t) || DATA_HOLDER_WORDS.has(t))) return true;
  }
  return false;
}

const unencryptedRealmDatabaseRule: Rule = {
  id: 'UNENCRYPTED_REALM_DATABASE',
  description: 'Realm database opened without encryption in sensitive context',
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

        // Check for Realm.open({ ... }) without encryptionKey
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Realm' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'open'
        ) {
          const configArg = node.arguments[0];

          if (configArg && configArg.type === 'ObjectExpression') {
            const hasEncryption = configArg.properties.some((prop: any) =>
              prop.key && (prop.key.name === 'encryptionKey' || prop.key.value === 'encryptionKey')
            );

            if (!hasEncryption) {
              const surroundingCode = context.fileContent.substring(
                Math.max(0, (node.start || 0) - 300),
                Math.min(context.fileContent.length, (node.end || 0) + 100)
              );

              if (hasSensitiveDataContext(surroundingCode)) {
                const line = getLineNumber(context.fileContent, node.start || 0);

                findings.push({
                  ruleId: 'UNENCRYPTED_REALM_DATABASE',
                  description: 'Realm database storing sensitive data without encryption',
                  severity: Severity.HIGH,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Add encryptionKey to Realm.open() config to encrypt the database at rest. Generate a 64-byte encryption key and store it securely.',
                });
              }
            }
          }
        }
      },

      NewExpression(path: any) {
        const { node } = path;

        // Check for new Realm({ ... }) without encryptionKey
        if (
          node.callee.type === 'Identifier' &&
          node.callee.name === 'Realm'
        ) {
          const configArg = node.arguments[0];

          if (configArg && configArg.type === 'ObjectExpression') {
            const hasEncryption = configArg.properties.some((prop: any) =>
              prop.key && (prop.key.name === 'encryptionKey' || prop.key.value === 'encryptionKey')
            );

            if (!hasEncryption) {
              const surroundingCode = context.fileContent.substring(
                Math.max(0, (node.start || 0) - 300),
                Math.min(context.fileContent.length, (node.end || 0) + 100)
              );

              if (hasSensitiveDataContext(surroundingCode)) {
                const line = getLineNumber(context.fileContent, node.start || 0);

                findings.push({
                  ruleId: 'UNENCRYPTED_REALM_DATABASE',
                  description: 'Realm database storing sensitive data without encryption',
                  severity: Severity.HIGH,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Add encryptionKey to Realm config to encrypt the database at rest.',
                });
              }
            }
          }
        }
      },
    });

    return findings;
  },
};

const unencryptedSqliteDatabaseRule: Rule = {
  id: 'UNENCRYPTED_SQLITE_DATABASE',
  description: 'SQLite database used without encryption for sensitive data',
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

        // Check for SQLite.openDatabase() or openDatabaseAsync() or expo-sqlite
        const isSqliteOpen =
          (node.callee.type === 'MemberExpression' &&
           node.callee.property.type === 'Identifier' &&
           (node.callee.property.name === 'openDatabase' || node.callee.property.name === 'openDatabaseAsync')) ||
          (node.callee.type === 'Identifier' &&
           (node.callee.name === 'openDatabase' || node.callee.name === 'openDatabaseAsync'));

        if (isSqliteOpen) {
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 400),
            Math.min(context.fileContent.length, (node.end || 0) + 400)
          );
          const surroundingLower = surroundingCode.toLowerCase();

          const hasEncryption =
            surroundingLower.includes('sqlcipher') ||
            surroundingLower.includes('encrypt') ||
            surroundingLower.includes('cipher') ||
            surroundingLower.includes('pragma key');

          if (hasSensitiveDataContext(surroundingCode) && !hasEncryption) {
            const line = getLineNumber(context.fileContent, node.start || 0);

            findings.push({
              ruleId: 'UNENCRYPTED_SQLITE_DATABASE',
              description: 'SQLite database storing sensitive data without encryption',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use SQLCipher or an encrypted SQLite wrapper to encrypt the database at rest. Plain SQLite databases can be extracted and read.',
            });
          }
        }
      },
    });

    return findings;
  },
};

/** SecureStore accessibility values Apple deprecates ("not recommended"): readable even while the device is locked. */
const SECURE_STORE_ALWAYS = new Set(['ALWAYS', 'ALWAYS_THIS_DEVICE_ONLY']);
const SECURE_STORE_SETTERS = new Set(['setItemAsync', 'setItem']);

const expoSecureStoreWeakOptionsRule: Rule = {
  id: 'EXPO_SECURE_STORE_WEAK_OPTIONS',
  description: 'Expo SecureStore item with ALWAYS keychainAccessible (readable while the device is locked)',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.ast) {
      return findings;
    }

    // `SecureStore.ALWAYS`, `ALWAYS` (named import) and `SecureStore['ALWAYS']`
    const store = collectModuleAliases(context.ast, source => source === 'expo-secure-store', { defaults: ['SecureStore'] });
    const alwaysName = (value: any): string | null => {
      if (value.type === 'Identifier') {
        const imported = store.named.get(value.name);
        return imported && SECURE_STORE_ALWAYS.has(imported) ? imported : null;
      }
      const name = propName(value);
      return name && SECURE_STORE_ALWAYS.has(name) && value.object.type === 'Identifier' && store.objects.has(value.object.name)
        ? name
        : null;
    };

    // AFTER_FIRST_UNLOCK[_THIS_DEVICE_ONLY] is deliberately not reported: Apple recommends it as the
    // replacement for ALWAYS and it is the usual choice when background access is needed.
    traverse(context.ast, {
      ObjectProperty(path: any) {
        const { node } = path;
        if (node.computed) return;
        const key = node.key.type === 'Identifier' ? node.key.name : node.key.type === 'StringLiteral' ? node.key.value : null;
        if (key !== 'keychainAccessible') return;
        const accessibility = alwaysName(node.value);
        if (!accessibility) return;

        // key name of `SecureStore.setItemAsync('key', value, { keychainAccessible })`, when this is that call
        let itemKey: string | null = null;
        const call = path.parentPath?.parent;
        if (call?.type === 'CallExpression' && call.arguments[2] === path.parent) {
          const callee = call.callee;
          const setter = callee.type === 'Identifier' ? store.named.get(callee.name) : propName(callee);
          if (setter && SECURE_STORE_SETTERS.has(setter)) itemKey = resolveString(call.arguments[0], path.scope);
        }
        const credentialLike = itemKey !== null && isCredentialKeyName(itemKey);

        const line = getLineNumber(context.fileContent, node.start || 0);
        findings.push({
          ruleId: 'EXPO_SECURE_STORE_WEAK_OPTIONS',
          description: `SecureStore ${itemKey !== null ? `item "${itemKey}"` : 'item'} uses keychainAccessible ${accessibility} - readable even while the device is locked (deprecated, not recommended by Apple)`,
          severity: credentialLike ? Severity.HIGH : Severity.MEDIUM,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Use WHEN_UNLOCKED_THIS_DEVICE_ONLY for sensitive data (or AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY if it must be readable in the background).',
        });
      },
    });

    return findings;
  },
};

export const storageRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [
    asyncStorageSensitiveKeyRule,
    hardcodedSecretsRule,
    asyncStoragePiiDataRule,
    reduxPersistNoEncryptionRule,
    clipboardSensitiveDataRule,
    insecureFileStorageRule,
    mmkvNoEncryptionRule,
    unencryptedRealmDatabaseRule,
    unencryptedSqliteDatabaseRule,
    expoSecureStoreWeakOptionsRule,
  ],
};
