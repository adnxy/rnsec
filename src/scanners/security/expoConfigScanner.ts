import { existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { classifySecretName, hasAdjacentTokens, tokenizeName } from '../../utils/secretNames.js';
import { extractSnippet } from '../../utils/stringUtils.js';

// ---------------------------------------------------------------------------
// Value tree: one shape for JSON files (with exact lines) and JS/TS config
// objects (plain literals only), so each rule is written once.
// ---------------------------------------------------------------------------

type Node =
  | { t: 'obj'; line: number; props: Map<string, Node> }
  | { t: 'arr'; line: number; items: Node[] }
  | { t: 'str'; line: number; v: string }
  | { t: 'bool'; line: number; v: boolean }
  | { t: 'other'; line: number }; // numbers, null, expressions: never inspected

const obj = (n: Node | undefined) => (n && n.t === 'obj' ? n : undefined);
const prop = (n: Node | undefined, ...path: string[]): Node | undefined => {
  let cur: Node | undefined = n;
  for (const key of path) {
    cur = obj(cur)?.props.get(key);
    if (!cur) return undefined;
  }
  return cur;
};
const isTrue = (n: Node | undefined) => n?.t === 'bool' && n.v === true;

/** Small JSON parser that records line numbers; tolerates comments and trailing commas. */
function parseJsonNode(text: string): Node | null {
  let i = 0;
  let line = 1;
  const fail = (): never => {
    throw new Error('parse');
  };
  const ws = () => {
    for (;;) {
      const c = text[i];
      if (c === '\n') { line++; i++; }
      else if (c === ' ' || c === '\t' || c === '\r' || c === '﻿') i++;
      else if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; }
      else if (c === '/' && text[i + 1] === '*') {
        i += 2;
        while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] === '\n') line++; i++; }
        i += 2;
      } else return;
    }
  };
  const str = (): string => {
    if (text[i] !== '"') fail();
    const start = i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === '\\') i++;
      if (text[i] === '\n') fail();
      i++;
    }
    i++;
    return JSON.parse(text.slice(start, i));
  };
  const value = (): Node => {
    ws();
    const at = line;
    const c = text[i];
    if (c === '{') {
      i++;
      const props = new Map<string, Node>();
      for (;;) {
        ws();
        if (text[i] === '}') { i++; break; }
        const keyLine = line;
        const key = str();
        ws();
        if (text[i++] !== ':') fail();
        const v = value();
        // report the line of the key, which is what a reader looks for
        props.set(key, { ...v, line: keyLine } as Node);
        ws();
        if (text[i] === ',') i++;
        else if (text[i] !== '}') fail();
      }
      return { t: 'obj', line: at, props };
    }
    if (c === '[') {
      i++;
      const items: Node[] = [];
      for (;;) {
        ws();
        if (text[i] === ']') { i++; break; }
        items.push(value());
        ws();
        if (text[i] === ',') i++;
        else if (text[i] !== ']') fail();
      }
      return { t: 'arr', line: at, items };
    }
    if (c === '"') return { t: 'str', line: at, v: str() };
    const m = /^(true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i, i + 40));
    if (!m) return fail();
    i += m[0].length;
    if (m[0] === 'true' || m[0] === 'false') return { t: 'bool', line: at, v: m[0] === 'true' };
    return { t: 'other', line: at };
  };
  try {
    const root = value();
    return root;
  } catch {
    return null;
  }
}

/** Convert a Babel expression into a value tree; anything non-literal becomes `other`. */
function astToNode(n: any): Node {
  const line = n?.loc?.start?.line ?? 1;
  if (!n) return { t: 'other', line };
  switch (n.type) {
    case 'ParenthesizedExpression':
    case 'TSAsExpression':
    case 'TSSatisfiesExpression':
    case 'TSNonNullExpression':
      return astToNode(n.expression);
    case 'StringLiteral':
      return { t: 'str', line, v: n.value };
    case 'TemplateLiteral':
      return n.expressions.length === 0 && n.quasis.length === 1
        ? { t: 'str', line, v: n.quasis[0].value.cooked ?? '' }
        : { t: 'other', line };
    case 'BooleanLiteral':
      return { t: 'bool', line, v: n.value };
    case 'ArrayExpression':
      return { t: 'arr', line, items: n.elements.map((e: any) => astToNode(e)) };
    case 'ObjectExpression': {
      const props = new Map<string, Node>();
      for (const p of n.properties) {
        if (p.type !== 'ObjectProperty' || p.computed) continue;
        const key = p.key.type === 'Identifier' ? p.key.name : p.key.type === 'StringLiteral' ? p.key.value : null;
        if (key === null) continue;
        const v = astToNode(p.value);
        props.set(key, { ...v, line: p.loc?.start?.line ?? v.line } as Node);
      }
      return { t: 'obj', line, props };
    }
    default:
      return { t: 'other', line };
  }
}

const unwrapExpr = (n: any): any => {
  while (n && (n.type === 'ParenthesizedExpression' || n.type === 'TSAsExpression' || n.type === 'TSSatisfiesExpression')) {
    n = n.expression;
  }
  return n;
};

/** The object a JS/TS config module exports: `export default {}`, `module.exports = {}`, or a function returning one. */
function findExportedObject(ast: any): any | null {
  const body: any[] = ast?.program?.body ?? [];
  const topLevel = new Map<string, any>();
  for (const st of body) {
    const decls = st.type === 'ExportNamedDeclaration' ? st.declaration : st;
    if (decls?.type === 'VariableDeclaration') {
      for (const d of decls.declarations) if (d.id.type === 'Identifier' && d.init) topLevel.set(d.id.name, d.init);
    }
  }
  const resolve = (expr: any, depth = 0): any | null => {
    expr = unwrapExpr(expr);
    if (!expr || depth > 4) return null;
    if (expr.type === 'ObjectExpression') return expr;
    if (expr.type === 'Identifier') return resolve(topLevel.get(expr.name), depth + 1);
    if (expr.type === 'ArrowFunctionExpression' || expr.type === 'FunctionExpression') {
      if (expr.body.type !== 'BlockStatement') return resolve(expr.body, depth + 1);
      const ret = expr.body.body.find((s: any) => s.type === 'ReturnStatement');
      return ret ? resolve(ret.argument, depth + 1) : null;
    }
    return null;
  };
  for (const st of body) {
    if (st.type === 'ExportDefaultDeclaration') return resolve(st.declaration);
    if (
      st.type === 'ExpressionStatement' &&
      st.expression.type === 'AssignmentExpression' &&
      st.expression.left.type === 'MemberExpression' &&
      st.expression.left.object.type === 'Identifier' &&
      st.expression.left.object.name === 'module' &&
      st.expression.left.property.name === 'exports'
    ) {
      return resolve(st.expression.right);
    }
  }
  return null;
}

const baseName = (p: string) => p.split(/[\\/]/).pop() ?? '';
const JS_CONFIG = /^app\.config\.(js|ts|mjs|cjs)$/;

/** Value tree of the file, or null when it is not a config this scanner reads. */
function loadTree(context: RuleContext, names: (name: string) => boolean): { root: Node; json: boolean } | null {
  const name = baseName(context.filePath);
  if (!names(name)) return null;
  if (name.endsWith('.json')) {
    const root = context.config ? parseJsonNode(context.fileContent) : null;
    return root ? { root, json: true } : null;
  }
  if (!context.ast) return null;
  const exported = findExportedObject(context.ast);
  return exported ? { root: astToNode(exported), json: false } : null;
}

/** `expo` wrapper when present, otherwise the top-level object (app.config.json may omit it). */
const expoRoot = (root: Node): Node | undefined => (obj(prop(root, 'expo')) ? prop(root, 'expo') : obj(root));

function nativeDirExists(context: RuleContext, platform: 'android' | 'ios'): boolean {
  const roots = new Set([context.project?.rootDir ?? dirname(context.filePath), dirname(context.filePath)]);
  for (const root of roots) {
    if (platform === 'android') {
      if (existsSync(join(root, 'android', 'app', 'src', 'main', 'AndroidManifest.xml'))) return true;
    } else {
      try {
        const iosDir = join(root, 'ios');
        for (const entry of readdirSync(iosDir, { withFileTypes: true })) {
          if (entry.isDirectory() && existsSync(join(iosDir, entry.name, 'Info.plist'))) return true;
        }
      } catch {
        // no ios directory
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Literal checks
// ---------------------------------------------------------------------------

const PLACEHOLDER_WORDS = /^(changeme|change[-_ ]?me|todo|tbd|xxx+|\*+|placeholder|example|replace[-_ ]?me|none|null|undefined|true|false)$/i;

function isPlaceholder(value: string): boolean {
  const v = value.trim();
  return (
    v.length < 4 ||
    PLACEHOLDER_WORDS.test(v) ||
    /^your[-_ ]/i.test(v) ||
    /^<.*>$/.test(v) ||
    /\$\{.*\}/.test(v) ||
    /process\.env\b/.test(v) ||
    /^\$[A-Za-z_]/.test(v) ||
    /^%.*%$/.test(v)
  );
}

function finding(
  context: RuleContext,
  ruleId: string,
  line: number,
  severity: Severity,
  confidence: 'high' | 'medium' | 'low',
  description: string,
  reason: string,
  suggestion: string
): Finding {
  return {
    ruleId,
    description,
    severity,
    confidence,
    filePath: context.filePath,
    line,
    snippet: extractSnippet(context.fileContent, line, 1),
    reason,
    suggestion,
    category: 'config',
  };
}

// ---------------------------------------------------------------------------
// 1. EXPO_CONFIG_INSECURE_SETTINGS
// ---------------------------------------------------------------------------

const ATS_KEYS_OVERRIDING_ARBITRARY_LOADS = [
  'NSAllowsArbitraryLoadsInWebContent',
  'NSAllowsArbitraryLoadsForMedia',
  'NSAllowsLocalNetworking',
];

const insecureSettingsRule: Rule = {
  id: 'EXPO_CONFIG_INSECURE_SETTINGS',
  description: 'Insecure native setting enabled in the Expo app config',
  severity: Severity.MEDIUM,
  fileTypes: ['.json', '.js', '.ts'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const tree = loadTree(context, n => n === 'app.json' || n === 'app.config.json' || JS_CONFIG.test(n));
    if (!tree) return [];
    const expo = expoRoot(tree.root);
    if (!expo) return [];

    const id = 'EXPO_CONFIG_INSECURE_SETTINGS';
    const findings: Finding[] = [];
    const androidManaged = !nativeDirExists(context, 'android');
    const iosManaged = !nativeDirExists(context, 'ios');

    if (androidManaged) {
      const backup = prop(expo, 'android', 'allowBackup');
      if (isTrue(backup)) {
        findings.push(
          finding(
            context, id, backup!.line, Severity.MEDIUM, 'medium',
            'android.allowBackup is explicitly set to true; app data can be extracted with adb backup and uploaded to cloud backups',
            'Prebuild writes this into AndroidManifest.xml. Databases, SharedPreferences and files, including cached tokens, are then included in backups.',
            'Set "android.allowBackup" to false, or keep it enabled only with backup rules that exclude tokens and databases.'
          )
        );
      }

      const plugins = prop(expo, 'plugins');
      if (plugins?.t === 'arr') {
        for (const plugin of plugins.items) {
          if (plugin.t !== 'arr' || plugin.items[0]?.t !== 'str' || plugin.items[0].v !== 'expo-build-properties') continue;
          const cleartext = prop(plugin.items[1], 'android', 'usesCleartextTraffic');
          if (isTrue(cleartext)) {
            findings.push(
              finding(
                context, id, cleartext!.line, Severity.HIGH, 'high',
                'expo-build-properties sets android.usesCleartextTraffic to true, allowing unencrypted HTTP traffic',
                'Prebuild writes android:usesCleartextTraffic="true" into the manifest, so any connection can be downgraded to HTTP and read or modified on the network.',
                'Remove usesCleartextTraffic (it defaults to false on Android 9+) and use HTTPS. If one dev host needs HTTP, allow only it in a network security config.'
              )
            );
          }
        }
      }
    }

    if (iosManaged) {
      const infoPlist = prop(expo, 'ios', 'infoPlist');
      const ats = prop(infoPlist, 'NSAppTransportSecurity');
      const arbitrary = prop(ats, 'NSAllowsArbitraryLoads');
      if (isTrue(arbitrary)) {
        const overriding = ATS_KEYS_OVERRIDING_ARBITRARY_LOADS.filter(k => obj(ats)?.props.has(k));
        if (overriding.length > 0) {
          findings.push(
            finding(
              context, id, arbitrary!.line, Severity.LOW, 'medium',
              `ios.infoPlist NSAllowsArbitraryLoads is true but ignored on iOS 10+ because ${overriding.join(', ')} is present (still applies to iOS 9)`,
              'The narrower ATS keys take precedence on current iOS versions, so the broad flag only matters for iOS 9.',
              'Remove NSAllowsArbitraryLoads unless you still ship to iOS 9; the narrower keys already cover the intended exception.'
            )
          );
        } else {
          findings.push(
            finding(
              context, id, arbitrary!.line, Severity.HIGH, 'high',
              'ios.infoPlist sets NSAllowsArbitraryLoads to true, disabling App Transport Security',
              'Expo merges infoPlist into Info.plist unchanged, so every connection may use plain HTTP or weak TLS.',
              'Remove NSAllowsArbitraryLoads and add NSExceptionDomains only for specific servers that need an exception.'
            )
          );
        }
      }

      const fileSharing = prop(infoPlist, 'UIFileSharingEnabled');
      if (isTrue(fileSharing)) {
        findings.push(
          finding(
            context, id, fileSharing!.line, Severity.LOW, 'medium',
            'ios.infoPlist enables UIFileSharingEnabled, exposing the Documents directory through Finder/iTunes file sharing',
            'Anything stored in the app Documents folder can be read by a user or malware with access to the paired computer.',
            'Disable UIFileSharingEnabled unless users must import or export files, and keep sensitive data out of Documents.'
          )
        );
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// 2. EXPO_SENSITIVE_CONFIG_EXPOSED
// ---------------------------------------------------------------------------

/** `authToken`, `accessToken`, `REFRESH_TOKEN`: credentials by name, though classifySecretName ignores them. */
const CREDENTIAL_TOKEN_PREFIXES = new Set(['AUTH', 'ACCESS', 'REFRESH', 'BEARER', 'API', 'SESSION']);

function isCredentialTokenName(name: string): boolean {
  const t = tokenizeName(name);
  if (t.length < 2 || t[t.length - 1] !== 'TOKEN') return false;
  return !t.some(x => x === 'PUBLISHABLE' || x === 'ANON' || x === 'PUBLIC') && t.slice(0, -1).some(x => CREDENTIAL_TOKEN_PREFIXES.has(x));
}

/** `apiKey` / `api_key`: only checked inside ios.config / android.config, where it is mostly a public SDK id. */
function isApiKeyName(name: string): boolean {
  const t = tokenizeName(name);
  return t.length >= 1 && (t[t.length - 1] === 'APIKEY' || hasAdjacentTokens(t, 'API', 'KEY'));
}

/**
 * Public-by-design SDK identifiers that live in ios.config / android.config. Kept small on purpose:
 * Google Maps / Sign-In keys are restricted by bundle id or signing certificate, and Branch
 * key_live_/key_test_ keys ship in every client (the Branch *secret* does not and is still reported).
 */
function isPublicSdkIdentifier(path: string[], value: string): boolean {
  const joined = path.join('.').toLowerCase();
  if (joined === 'googlemapsapikey' || joined === 'googlemaps.apikey') return true;
  if (joined === 'googlemobileadsappid' || joined.startsWith('googlesignin.')) return true;
  return path.some(k => k.toLowerCase() === 'branch') && /^key_(live|test)_/.test(value);
}

type ConfigSection = 'extra' | 'native-config' | 'plugin';

const SECTION_REASON: Record<ConfigSection, string> = {
  extra:
    'expo.extra is exposed to app code through Constants.expoConfig.extra, so it is embedded in the shipped app config and can be read by anyone who downloads the app.',
  'native-config':
    'ios.config / android.config values are written into Info.plist and AndroidManifest.xml, which anyone who downloads the app can read.',
  plugin:
    'Config plugin options are part of the resolved Expo config that is embedded in the app bundle (see GHSA-68c2-4mpx-qh95), so a literal token here ships to every user.',
};

const sensitiveConfigRule: Rule = {
  id: 'EXPO_SENSITIVE_CONFIG_EXPOSED',
  description: 'Secret stored in the Expo app config (extra, ios/android config or plugin options), which ships inside the app',
  severity: Severity.HIGH,
  fileTypes: ['.json', '.js', '.ts'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    const tree = loadTree(context, n => n === 'app.json' || n === 'app.config.json' || JS_CONFIG.test(n));
    if (!tree) return findings;
    const expo = expoRoot(tree.root);

    const walk = (node: Node | undefined, label: string, path: string[], section: ConfigSection) => {
      if (!node) return;
      if (node.t === 'obj') {
        for (const [key, child] of node.props) walk(child, label, [...path, key], section);
      } else if (node.t === 'arr') {
        node.items.forEach(item => walk(item, label, path, section));
      } else if (node.t === 'str') {
        const key = path[path.length - 1];
        if (!key || isPlaceholder(node.v)) return;

        let severity = classifySecretName(key);
        let confidence: 'medium' | 'low' = 'medium';
        if (!severity && isCredentialTokenName(key)) severity = Severity.HIGH;
        if (!severity && section === 'native-config' && isApiKeyName(key) && !isPublicSdkIdentifier(path, node.v)) {
          severity = Severity.MEDIUM;
          confidence = 'low';
        }
        if (!severity) return;

        findings.push(
          finding(
            context, 'EXPO_SENSITIVE_CONFIG_EXPOSED', node.line, severity, confidence,
            `"${label}${path.length ? '.' : ''}${path.join('.')}" looks like a secret and has a literal value in the Expo config`,
            SECTION_REASON[section],
            'Keep the secret on a backend and call that from the app, or inject it at build time (EAS secrets / process.env in app.config.js). If the value is actually public, rename the key so it does not look like a secret.'
          )
        );
      }
    };

    walk(prop(expo, 'extra'), 'extra', [], 'extra');
    walk(prop(expo, 'ios', 'config'), 'ios.config', [], 'native-config');
    walk(prop(expo, 'android', 'config'), 'android.config', [], 'native-config');

    // ["plugin-name", { options }]: the options are the part that can hold a token
    const plugins = prop(expo, 'plugins');
    if (plugins?.t === 'arr') {
      for (const plugin of plugins.items) {
        if (plugin.t !== 'arr' || plugin.items[0]?.t !== 'str') continue;
        walk(plugin.items[1], `plugins[${plugin.items[0].v}]`, [], 'plugin');
      }
    }
    return findings;
  },
};

// ---------------------------------------------------------------------------
// 3. EAS_JSON_SECRET_IN_ENV
// ---------------------------------------------------------------------------

const easEnvSecretRule: Rule = {
  id: 'EAS_JSON_SECRET_IN_ENV',
  description: 'Secret committed as a plain-text env value in eas.json',
  severity: Severity.HIGH,
  fileTypes: ['.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const tree = loadTree(context, n => n === 'eas.json');
    if (!tree) return [];
    const findings: Finding[] = [];

    for (const [profileName, profile] of obj(prop(tree.root, 'build'))?.props ?? []) {
      for (const [envName, value] of obj(prop(profile, 'env'))?.props ?? []) {
        if (value.t !== 'str' || isPlaceholder(value.v)) continue;
        // EXPO_PUBLIC_ values are inlined into the bundle, so classify the name behind the prefix
        const bare = envName.startsWith('EXPO_PUBLIC_') ? envName.slice('EXPO_PUBLIC_'.length) : envName;
        const severity = classifySecretName(bare);
        if (!severity) continue;
        const bundled = envName.startsWith('EXPO_PUBLIC_');
        findings.push(
          finding(
            context, 'EAS_JSON_SECRET_IN_ENV', value.line, severity, 'medium',
            `eas.json build profile "${profileName}" sets secret-looking env "${envName}" to a literal value${bundled ? ' that is also embedded in the app bundle (EXPO_PUBLIC_*)' : ''}`,
            'Values in eas.json are plain text committed to the repository' +
              (bundled ? ', and EXPO_PUBLIC_* variables are additionally readable in the compiled app.' : ' and visible to everyone with repo access.'),
            'Store the value as an EAS secret (eas env:create / the EAS dashboard) and remove it from eas.json. Never give a server secret an EXPO_PUBLIC_ name.'
          )
        );
      }
    }
    return findings;
  },
};

export const expoConfigRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [insecureSettingsRule, sensitiveConfigRule, easEnvSecretRule],
};
