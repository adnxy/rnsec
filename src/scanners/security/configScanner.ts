import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { established, loadJsExpoConfig } from './expoConfigScanner.js';
import { extractSnippet, getLineNumber } from '../../utils/stringUtils.js';

const DANGEROUS_PERMISSIONS = [
  'android.permission.READ_PHONE_STATE',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.CAMERA',
  'android.permission.RECORD_AUDIO',
];

const expoInsecurePermissionsRule: Rule = {
  id: 'EXPO_INSECURE_PERMISSIONS',
  description: 'Potentially dangerous permissions detected in Expo config',
  severity: Severity.LOW,
  fileTypes: ['.json', '.js', '.ts'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    // app.config.js/ts: only literal permission strings of a statically known object
    const jsExpo = loadJsExpoConfig(context);
    if (jsExpo) {
      const permissions = established(jsExpo, 'android', 'permissions');
      if (permissions?.t === 'arr') {
        for (const item of permissions.items) {
          if (item.t === 'str' && DANGEROUS_PERMISSIONS.includes(item.v)) {
            findings.push({
              ruleId: 'EXPO_INSECURE_PERMISSIONS',
              description: `Dangerous permission detected: ${item.v}`,
              severity: Severity.LOW,
              confidence: 'low',
              filePath: context.filePath,
              line: item.line,
              snippet: extractSnippet(context.fileContent, item.line, 1),
              suggestion: 'Only request necessary permissions and explain usage to users',
            });
          }
        }
      }
      return findings;
    }

    const fileName = context.filePath.split(/[\\/]/).pop();
    if (!context.config || (fileName !== 'app.json' && fileName !== 'app.config.json')) {
      return findings;
    }

    const permissions = context.config.expo?.android?.permissions;
    if (Array.isArray(permissions)) {
      const lines = context.fileContent.split('\n');
      
      for (const permission of permissions) {
        if (typeof permission === 'string' && DANGEROUS_PERMISSIONS.includes(permission)) {
          const idx = lines.findIndex(l => l.includes(`"${permission}"`));
          findings.push({
            ruleId: 'EXPO_INSECURE_PERMISSIONS',
            description: `Dangerous permission detected: ${permission}`,
            severity: Severity.LOW,
            // Apps often need these on purpose; the rule cannot see whether they are used
            confidence: 'low',
            filePath: context.filePath,
            line: idx === -1 ? undefined : idx + 1,
            suggestion: 'Only request necessary permissions and explain usage to users',
          });
        }
      }
    }

    return findings;
  },
};

const expoUpdatesInsecureUrlRule: Rule = {
  id: 'EXPO_UPDATES_INSECURE_URL',
  description: 'Expo updates URL configured over insecure HTTP',
  severity: Severity.HIGH,
  fileTypes: ['.json', '.js', '.ts'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    // app.config.js/ts: a literal http:// url in a statically known updates object
    const jsExpo = loadJsExpoConfig(context);
    if (jsExpo) {
      const url = established(jsExpo, 'updates', 'url');
      if (url?.t === 'str' && url.v.startsWith('http://')) {
        findings.push({
          ruleId: 'EXPO_UPDATES_INSECURE_URL',
          description: `Expo updates URL uses insecure HTTP: "${url.v}"`,
          severity: Severity.HIGH,
          filePath: context.filePath,
          line: url.line,
          snippet: extractSnippet(context.fileContent, url.line, 1),
          suggestion: 'Use HTTPS for Expo updates URL to prevent MITM attacks that could inject malicious code via OTA updates.',
        });
      }
      return findings;
    }

    if (!context.config || !context.filePath.includes('app.json')) {
      return findings;
    }

    const expo = context.config.expo;
    if (!expo) return findings;

    const updatesUrl = expo.updates?.url;
    if (updatesUrl && typeof updatesUrl === 'string' && updatesUrl.startsWith('http://')) {
      findings.push({
        ruleId: 'EXPO_UPDATES_INSECURE_URL',
        description: `Expo updates URL uses insecure HTTP: "${updatesUrl}"`,
        severity: Severity.HIGH,
        filePath: context.filePath,
        suggestion: 'Use HTTPS for Expo updates URL to prevent MITM attacks that could inject malicious code via OTA updates.',
      });
    }

    return findings;
  },
};

/** Replace `//` and block comments with spaces (newlines kept, so offsets and line numbers stay valid) */
function blankRulesComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, m => m.replace(/[^\n]/g, ' '));
}

const WRITE_METHODS = new Set(['write', 'create', 'update', 'delete']);
const READ_METHODS = new Set(['read', 'get', 'list']);

/** `request.time < timestamp.date(Y, M, D)`: the expiry of a Firebase "test mode" rule, or undefined for other conditions */
function firestoreExpiry(condition: string): Date | undefined {
  const c = condition.replace(/\s+/g, '').replace(/^\((.*)\)$/, '$1');
  const m = /^request\.time<timestamp\.date\((\d{4}),(\d{1,2}),(\d{1,2})\)$/.exec(c);
  return m ? new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))) : undefined;
}

/** Open for `true` / no condition ('open'), open until a date ('timed'), anything else (undefined: not reported) */
type Openness = { kind: 'open' } | { kind: 'timed'; until: string };

function classifyCondition(condition: string | undefined): Openness | undefined {
  if (condition === undefined) return { kind: 'open' };
  const c = condition.replace(/\s+/g, '').replace(/^\((.*)\)$/, '$1');
  if (c === 'true') return { kind: 'open' };
  const expiry = firestoreExpiry(condition);
  return expiry ? { kind: 'timed', until: expiry.toISOString().slice(0, 10) } : undefined;
}

/** Severity of an open rule; undefined for public read-only access to one specific path (usually intended) */
function openSeverity(openness: Openness, writes: boolean, wildcard: boolean, storage = false): Severity | undefined {
  if (!writes && !wildcard) return undefined;
  if (openness.kind === 'open') return writes ? Severity.HIGH : storage ? Severity.LOW : Severity.MEDIUM;
  // time-limited ("test mode"): graded by access only, never by today's date, so a scan does not change when the expiry passes
  return writes ? Severity.MEDIUM : Severity.LOW;
}

/** Path of the innermost `match <path> {` that encloses `offset` ('' outside any match). Wildcards like `{id}` belong to the path. */
function enclosingMatchPath(src: string, offset: number): string {
  const stack: string[] = [];
  const token = /\bmatch\s+([^\s{]*(?:\{[^}]*\}[^\s{]*)*)\s*\{|\{|\}/g;
  for (let t = token.exec(src); t && t.index < offset; t = token.exec(src)) {
    if (t[0] === '}') stack.pop();
    else stack.push(t[1] ?? '');
  }
  for (let i = stack.length - 1; i >= 0; i--) if (stack[i]) return stack[i];
  return '';
}

/** Offset of the first `"key"` at object depth `depth` (1 = the document root), or -1 */
function jsonKeyOffset(text: string, key: string, depth: number): number {
  let level = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') level++;
    else if (c === '}') level--;
    else if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (level === depth && text.slice(i + 1, j) === key && /^\s*:/.test(text.slice(j + 1))) return i;
      i = j;
    }
  }
  return -1;
}

const firebaseRulesOpenAccessRule: Rule = {
  id: 'FIREBASE_RULES_OPEN_ACCESS',
  description: 'Firebase security rules allow anyone to read or write data',
  severity: Severity.HIGH,
  fileTypes: ['.rules', '.rules.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    const add = (offset: number, severity: Severity, openness: Openness, description: string): void => {
      const line = getLineNumber(context.fileContent, offset);
      findings.push({
        ruleId: 'FIREBASE_RULES_OPEN_ACCESS',
        description:
          openness.kind === 'timed'
            ? `${description} until ${openness.until} (the default "test mode" rule)`
            : description,
        severity,
        confidence: severity === Severity.HIGH ? 'high' : 'medium',
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line, 1),
        reason: 'Firebase client SDKs run in every installed app, so rules that grant access without a condition let anyone with the project identifiers (which ship in the app) read or change the data.',
        suggestion: 'Require authentication and ownership, for example `allow read, write: if request.auth != null && request.auth.uid == userId;`, and grant public access only to the specific read-only paths that need it.',
      });
    };

    if (context.filePath.endsWith('.rules.json')) {
      // Realtime Database rules files may carry // comments, which strict JSON parsing rejects
      const text = blankRulesComments(context.fileContent);
      let config = context.config;
      if (!config) {
        try {
          config = JSON.parse(text);
        } catch {
          return findings;
        }
      }
      const rules = config?.rules;
      if (!rules || typeof rules !== 'object') return findings;
      for (const key of ['.read', '.write'] as const) {
        const value = rules[key];
        let openness: Openness | undefined;
        if (value === true) openness = { kind: 'open' };
        else if (typeof value === 'string') {
          const v = value.replace(/\s+/g, '');
          const timed = /^now<(\d{10,})$/.exec(v);
          if (v === 'true') openness = { kind: 'open' };
          else if (timed) openness = { kind: 'timed', until: new Date(Number(timed[1])).toISOString().slice(0, 10) };
        }
        if (!openness) continue;
        const writes = key === '.write';
        const offset = jsonKeyOffset(text, key, 2);
        const severity = openness.kind === 'open' ? Severity.HIGH : openSeverity(openness, writes, true)!;
        add(
          Math.max(offset, 0),
          severity,
          openness,
          `Realtime Database rules grant public ${writes ? 'write' : 'read'} access to the whole database (root "${key}")`
        );
      }
      return findings;
    }

    const src = blankRulesComments(context.fileContent);
    const service = /\bservice\s+cloud\.firestore\b/.test(src) ? 'Firestore' : /\bservice\s+firebase\.storage\b/.test(src) ? 'Cloud Storage' : undefined;
    if (!service) return findings;

    const allowRe = /\ballow\s+([a-z]+(?:\s*,\s*[a-z]+)*)\s*(?::\s*if\s+([^;]*?))?\s*;/g;
    for (let m = allowRe.exec(src); m; m = allowRe.exec(src)) {
      const methods = m[1].split(',').map(x => x.trim());
      if (!methods.every(x => WRITE_METHODS.has(x) || READ_METHODS.has(x))) continue;
      const openness = classifyCondition(m[2]);
      if (!openness) continue;

      const matchPath = enclosingMatchPath(src, m.index);
      // `allow` at the database / bucket root matches no document or object
      if (/^\/(?:databases\/\{[^}]+\}\/documents|b\/\{[^}]+\}\/o)$/.test(matchPath)) continue;
      const wildcard = /=\*\*/.test(matchPath);
      const writes = methods.some(x => WRITE_METHODS.has(x));
      const where = matchPath ? ` on ${matchPath}` : '';
      const severity = openSeverity(openness, writes, wildcard, service === 'Cloud Storage');
      if (!severity) continue;
      add(
        m.index,
        severity,
        openness,
        `${service} rules allow ${methods.join(', ')} for everyone${where}`
      );
    }
    return findings;
  },
};

export const configRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [
    expoInsecurePermissionsRule,
    expoUpdatesInsecureUrlRule,
    firebaseRulesOpenAccessRule,
  ],
};
