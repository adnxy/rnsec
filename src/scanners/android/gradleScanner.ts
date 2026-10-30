import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { getLineNumber } from '../../utils/stringUtils.js';
import { isPlaceholderValue } from '../../utils/sensitiveDataPatterns.js';
import { isLocalOrPrivateHost } from '../../utils/hostUtils.js';

const baseName = (filePath: string): string => filePath.split(/[\\/]/).pop() ?? '';

/** Public values from the React Native template's debug signingConfig. */
const WELL_KNOWN_DEBUG_PASSWORDS = new Set(['android']);

const mask = (value: string): string => (value.length >= 12 ? `${value.slice(0, 2)}****` : '****');

function isPlaceholderPassword(value: string): boolean {
  const v = value.trim();
  if (!v || /^\*+$/.test(v)) return true;
  if (WELL_KNOWN_DEBUG_PASSWORDS.has(v.toLowerCase())) return true;
  return isPlaceholderValue(v);
}

/** Replace // and block comments with spaces (newlines kept) so offsets and line numbers stay accurate. */
function blankGradleComments(src: string): string {
  let out = '';
  let i = 0;
  let quote: string | null = null;
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1];
    if (quote) {
      out += c;
      if (c === '\\' && next !== undefined) {
        out += next;
        i += 2;
        continue;
      }
      if (c === quote) quote = null;
      i++;
    } else if (c === '"' || c === "'") {
      quote = c;
      out += c;
      i++;
    } else if (c === '/' && next === '/') {
      while (i < src.length && src[i] !== '\n') {
        out += ' ';
        i++;
      }
    } else if (c === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? src.length : end + 2;
      out += src.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/** Index just past the `}` that closes the `{` at `open`, or -1. */
function matchBrace(src: string, open: number): number {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i + 1;
  }
  return -1;
}

interface PasswordHit {
  config: string;
  field: string;
  value: string;
  index: number;
}

// `storePassword 'x'`, `storePassword = "x"`, `keyPassword "x"` - the literal must be the whole value
const LITERAL_PASSWORD = /\b(storePassword|keyPassword)\s*(?:=\s*|\s+)(["'])((?:(?!\2)[^\\\n]|\\.)*)\2[ \t;]*(?=\r?\n|$)/g;

function findLiteralPasswords(src: string): PasswordHit[] {
  const hits: PasswordHit[] = [];
  const blockRe = /\bsigningConfigs\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(src)) !== null) {
    const open = m.index + m[0].length - 1;
    const end = matchBrace(src, open);
    if (end === -1) continue;
    const bodyStart = open + 1;
    const body = src.slice(bodyStart, end - 1);

    // direct children: `name {`, `create("name") {`, `getByName("name") {`, `register("name") {`
    const childRe = /(?:\b(?:create|getByName|register|maybeCreate)\s*\(\s*["'](\w+)["']\s*\)|\b(\w+))\s*\{/g;
    let c: RegExpExecArray | null;
    let pos = 0;
    while (pos < body.length && (childRe.lastIndex = pos, (c = childRe.exec(body)) !== null)) {
      const childOpen = c.index + c[0].length - 1;
      const childEnd = matchBrace(body, childOpen);
      if (childEnd === -1) break;
      const name = c[1] ?? c[2];
      const childBody = body.slice(childOpen + 1, childEnd - 1);
      const childOffset = bodyStart + childOpen + 1;
      LITERAL_PASSWORD.lastIndex = 0;
      let p: RegExpExecArray | null;
      while ((p = LITERAL_PASSWORD.exec(childBody)) !== null) {
        hits.push({ config: name, field: p[1], value: p[3], index: childOffset + p.index });
      }
      pos = childEnd;
    }
  }

  // signingConfigs.release.storePassword = "x"
  const dotted = /\bsigningConfigs\.(\w+)\.(storePassword|keyPassword)\s*=\s*(["'])((?:(?!\3)[^\\\n]|\\.)*)\3[ \t;]*(?=\r?\n|$)/g;
  while ((m = dotted.exec(src)) !== null) {
    hits.push({ config: m[1], field: m[2], value: m[4], index: m.index });
  }
  return hits;
}

// Keys such as MYAPP_UPLOAD_STORE_PASSWORD, storePassword, android.injected.signing.store.password, signing.password
const SIGNING_PASSWORD_KEY = /(storepass(word)?|keypass(word)?|keystorepass(word)?|(upload|release|signing)\w*password)$/;

function isSigningPasswordKey(key: string): boolean {
  if (/^org\.gradle\./i.test(key) || /^systemProp\./i.test(key)) return false;
  return SIGNING_PASSWORD_KEY.test(key.toLowerCase().replace(/[._\-]/g, ''));
}

const signingCredentialsRule: Rule = {
  id: 'ANDROID_SIGNING_CREDENTIALS_HARDCODED',
  description: 'Android signing password hardcoded in a Gradle file',
  severity: Severity.HIGH,
  fileTypes: ['.gradle', '.kts', '.properties'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const name = baseName(context.filePath);
    const findings: Finding[] = [];

    if (name === 'build.gradle' || name === 'build.gradle.kts') {
      const src = blankGradleComments(context.fileContent);
      for (const hit of findLiteralPasswords(src)) {
        if (hit.config.toLowerCase() === 'debug') continue;
        if (isPlaceholderPassword(hit.value) || hit.value.includes('$')) continue;
        findings.push({
          ruleId: 'ANDROID_SIGNING_CREDENTIALS_HARDCODED',
          description: `signingConfigs.${hit.config} hardcodes ${hit.field} as a string literal (${mask(hit.value)})`,
          severity: Severity.HIGH,
          confidence: 'high',
          filePath: context.filePath,
          line: getLineNumber(src, hit.index),
          snippet: `${hit.field} = "${mask(hit.value)}"`,
          reason: 'Anyone with repository access can read the keystore password and, together with the keystore file, sign apps as you.',
          suggestion: 'Read the passwords from ~/.gradle/gradle.properties, environment variables (System.getenv) or CI secrets, and rotate the exposed passwords.',
        });
      }
    } else if (name === 'gradle.properties') {
      context.fileContent.split(/\r?\n/).forEach((raw, i) => {
        const line = raw.trim();
        if (!line || line.startsWith('#') || line.startsWith('!')) return;
        const m = /^([^\s=:]+)\s*[=:]\s*(.*)$/.exec(line);
        if (!m) return;
        const [, key, value] = m;
        if (!isSigningPasswordKey(key) || isPlaceholderPassword(value)) return;
        findings.push({
          ruleId: 'ANDROID_SIGNING_CREDENTIALS_HARDCODED',
          description: `gradle.properties sets ${key} to a literal value (${mask(value.trim())})`,
          severity: Severity.HIGH,
          confidence: 'high',
          filePath: context.filePath,
          line: i + 1,
          snippet: `${key}=${mask(value.trim())}`,
          reason: 'A git-tracked gradle.properties exposes the signing password to everyone with repository access.',
          suggestion: 'Move the value to ~/.gradle/gradle.properties (not checked in) or a CI secret, keep only a placeholder here, and rotate the password.',
        });
      });
    }
    return findings;
  },
};

/** Offset of the `{` that most tightly encloses `index` inside `src[from..]`, or -1 when `index` is at the top level. */
function innermostOpen(src: string, from: number, index: number): number {
  const stack: number[] = [];
  let quote: string | null = null;
  for (let i = from; i < index; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '{') stack.push(i);
    else if (c === '}') stack.pop();
  }
  return stack.length > 0 ? stack[stack.length - 1] : -1;
}

// `url "http://h"`, `url = uri("http://h")`, `setUrl('http://h')`, `maven("http://h")`, `maven(url = "http://h")`
const HTTP_REPOSITORY_URL =
  /(?:\burl\b\s*(?:=\s*|\s+)|\bsetUrl\s*\(\s*|\bmaven\s*\(\s*(?:url\s*=\s*)?)(?:(?:java\.net\.)?[uU][rR][iI]\s*\(\s*|\bresources\.uri\s*\(\s*)?(["'])(http:\/\/[^"'\s]+)\1/g;
const ALLOW_INSECURE = /\b(?:is)?[aA]llowInsecureProtocol\s*(?:=\s*)?true\b/g;

const gradleInsecureRepositoryRule: Rule = {
  id: 'GRADLE_INSECURE_REPOSITORY',
  description: 'Gradle repository fetched over plain HTTP',
  severity: Severity.HIGH,
  fileTypes: ['.gradle', '.kts'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const name = baseName(context.filePath);
    if (!/^(?:build|settings)\.gradle(?:\.kts)?$/.test(name)) return [];
    const src = blankGradleComments(context.fileContent);
    if (!/http:\/\/|allowInsecureProtocol|AllowInsecureProtocol/.test(src)) return [];
    const findings: Finding[] = [];
    const flaggedBlocks = new Set<number>();
    const reported = new Set<number>();

    const report = (index: number, description: string, confidence: 'high' | 'medium', snippet: string): void => {
      const line = getLineNumber(src, index);
      if (reported.has(line)) return;
      reported.add(line);
      findings.push({
        ruleId: 'GRADLE_INSECURE_REPOSITORY',
        description,
        severity: Severity.HIGH,
        confidence,
        filePath: context.filePath,
        line,
        snippet,
        reason: 'Dependencies and plugins fetched over HTTP can be replaced in transit (rogue network, compromised proxy), which puts attacker code into the app and the build.',
        suggestion: 'Use an https:// repository URL and remove allowInsecureProtocol. For an internal mirror, serve it over HTTPS.',
      });
    };

    const blockRe = /\brepositories\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = blockRe.exec(src)) !== null) {
      const open = m.index + m[0].length - 1;
      const end = matchBrace(src, open);
      if (end === -1) continue;
      const body = src.slice(open + 1, end - 1);
      const offset = open + 1;

      HTTP_REPOSITORY_URL.lastIndex = 0;
      let u: RegExpExecArray | null;
      while ((u = HTTP_REPOSITORY_URL.exec(body)) !== null) {
        const url = u[2];
        // a host built from a variable cannot be judged; local and LAN hosts are development mirrors
        if (/^http:\/\/[^/]*\$/.test(url) || isLocalOrPrivateHost(url)) continue;
        const index = offset + u.index;
        const block = innermostOpen(src, open, index);
        if (block !== -1) flaggedBlocks.add(block);
        report(index, `Gradle repository uses a plain HTTP URL (${url.replace(/^(http:\/\/[^/]+).*$/, '$1')})`, 'high', `url "${url}"`);
      }

      ALLOW_INSECURE.lastIndex = 0;
      let a: RegExpExecArray | null;
      while ((a = ALLOW_INSECURE.exec(body)) !== null) {
        const index = offset + a.index;
        const block = innermostOpen(src, open, index);
        if (block !== -1) {
          if (flaggedBlocks.has(block)) continue;
          const blockEnd = matchBrace(src, block);
          const blockText = blockEnd === -1 ? '' : src.slice(block, blockEnd);
          const local = /(["'])(http:\/\/[^"'\s]+)\1/.exec(blockText);
          if (local && (isLocalOrPrivateHost(local[2]) || /^http:\/\/[^/]*\$/.test(local[2]))) continue;
          // the flag does nothing for an https:// repository URL (it only matters for an http redirect)
          if (!local && /(["'])https:\/\/[^"'\s]+\1/.test(blockText)) continue;
        }
        report(index, 'Gradle repository sets allowInsecureProtocol = true (HTTP repository allowed)', 'medium', a[0]);
      }
    }
    return findings;
  },
};

export const gradleRules: RuleGroup = {
  category: RuleCategory.MANIFEST,
  rules: [signingCredentialsRule, gradleInsecureRepositoryRule],
};
