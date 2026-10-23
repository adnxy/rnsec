import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { isLocalOrPrivateHost } from '../../utils/hostUtils.js';

const JS_FILES = ['.js', '.jsx', '.ts', '.tsx'];

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

interface ImportInfo {
  /** every module specifier imported/required in the file */
  sources: Set<string>;
  /** local binding name -> where it came from ('default' | '*' | named export) */
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
        const parent = path.parentPath?.node;
        if (parent?.type === 'VariableDeclarator') {
          if (parent.id.type === 'Identifier') {
            info.locals.set(parent.id.name, { source, imported: 'default' });
          } else if (parent.id.type === 'ObjectPattern') {
            for (const prop of parent.id.properties) {
              if (prop.type === 'ObjectProperty' && prop.key.type === 'Identifier' && prop.value.type === 'Identifier') {
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

/** Value of a string literal or an interpolation-free template literal, else null. */
function staticString(node: any): string | null {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0].value.cooked ?? null;
  return null;
}

function keyName(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'StringLiteral') return node.value;
  return null;
}

function memberName(node: any): string | null {
  if (!node || (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression')) return null;
  if (!node.computed) return node.property.type === 'Identifier' ? node.property.name : null;
  return node.property.type === 'StringLiteral' ? node.property.value : null;
}

const PLACEHOLDER_VALUE =
  /^(?:<.*>|\{.*\}|\$\{?.*|\[.*\]|%[sd]|:\w+|\.{3,}|x{3,}|\*{3,}|-+|_+|(?:your|my|the)[-_ ]?.*|change[-_ ]?me|todo|tbd|fixme|placeholder|example|redacted|replace[-_ ]?.*|insert[-_ ]?.*|pass(?:word)?|pwd|user(?:name)?)$/i;

// ---------------------------------------------------------------------------
// 1. JWT_INSECURE_SIGNING
// ---------------------------------------------------------------------------

const JWT_LIBS = new Set(['jsonwebtoken', 'jose', 'jws', 'jwt-simple', 'react-native-pure-jwt', 'njwt']);
/** Libraries whose `secretOrKey`-style option is also checked. */
const JWT_OPTION_LIBS = new Set([...JWT_LIBS, 'passport-jwt']);
const JWT_SECRET_METHODS = new Set(['sign', 'verify', 'encode', 'decode', 'create']);
const JWT_SECRET_OPTIONS = new Set(['secret', 'secretOrKey', 'secretOrPrivateKey', 'secretOrPublicKey']);

function isUsableSecretLiteral(value: string | null): value is string {
  return value !== null && value.trim().length > 0 && !PLACEHOLDER_VALUE.test(value.trim());
}

const jwtInsecureSigningRule: Rule = {
  id: 'JWT_INSECURE_SIGNING',
  description: 'JWT signed or verified with a hardcoded secret, or with the "none" algorithm',
  severity: Severity.HIGH,
  fileTypes: JS_FILES,
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const imports = collectImports(context.ast);
    const usesJwtLib = [...imports.sources].some(s => JWT_OPTION_LIBS.has(s));
    if (!usesJwtLib) return findings;
    const usesJose = imports.sources.has('jose');

    const isJwtLocal = (name: string) => {
      const meta = imports.locals.get(name);
      return !!meta && JWT_LIBS.has(meta.source);
    };

    const hardcoded = (node: any, how: string): Finding =>
      makeFinding(context, node, {
        ruleId: 'JWT_INSECURE_SIGNING',
        description: `JWT ${how} with a hardcoded secret`,
        severity: Severity.HIGH,
        confidence: 'high',
        reason:
          'A secret embedded in the app bundle can be extracted from any installed copy of the app, so anyone can forge ' +
          'valid tokens. Signing keys belong on a server; the client should only hold the tokens it receives.',
        suggestion: 'Sign and verify tokens on the backend. If the client must verify, use the issuer public key (asymmetric algorithm) instead of a shared secret.',
      });

    const reported = new Set<number>();
    const add = (node: any, how: string) => {
      if (reported.has(node.start)) return;
      reported.add(node.start);
      findings.push(hardcoded(node, how));
    };

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        const callee = node.callee;

        // jwt.sign(payload, 'secret') / jwt.verify(token, 'secret') / named `sign`, `verify` imports
        let method: string | null = null;
        if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier' && isJwtLocal(callee.object.name)) {
          method = memberName(callee);
        } else if (callee.type === 'Identifier' && isJwtLocal(callee.name)) {
          const meta = imports.locals.get(callee.name)!;
          method = meta.imported === 'default' || meta.imported === '*' ? null : meta.imported;
        }
        if (method && JWT_SECRET_METHODS.has(method) && node.arguments[1]) {
          const secret = staticString(node.arguments[1]);
          if (isUsableSecretLiteral(secret)) add(node.arguments[1], method === 'verify' || method === 'decode' ? 'verified' : 'signed');
        }

        // jose: new TextEncoder().encode('secret') used as a key
        if (
          usesJose &&
          callee.type === 'MemberExpression' &&
          memberName(callee) === 'encode' &&
          callee.object.type === 'NewExpression' &&
          callee.object.callee.type === 'Identifier' &&
          callee.object.callee.name === 'TextEncoder'
        ) {
          const secret = staticString(node.arguments[0]);
          if (isUsableSecretLiteral(secret)) add(node.arguments[0], 'key derived');
        }
      },

      ObjectProperty(path: any) {
        const { node } = path;
        const name = keyName(node.key);
        if (!name) return;

        // { secret: 'literal' } / { secretOrKey: 'literal' } (jws.sign, passport-jwt strategy options)
        if (JWT_SECRET_OPTIONS.has(name)) {
          const secret = staticString(node.value);
          if (isUsableSecretLiteral(secret)) add(node.value, 'configured');
        }

        // { algorithms: ['none'] } / { alg: 'none' }
        const isNoneAlg =
          ((name === 'alg' || name === 'algorithm') && /^none$/i.test(staticString(node.value) ?? '')) ||
          (name === 'algorithms' &&
            node.value.type === 'ArrayExpression' &&
            node.value.elements.some((el: any) => /^none$/i.test(staticString(el) ?? '')));
        if (isNoneAlg && !reported.has(node.start)) {
          reported.add(node.start);
          findings.push(
            makeFinding(context, node, {
              ruleId: 'JWT_INSECURE_SIGNING',
              description: 'JWT "none" algorithm allowed - tokens are accepted or produced without a signature',
              severity: Severity.HIGH,
              confidence: 'high',
              reason: 'An unsigned token carries no proof of origin; anyone can craft one with arbitrary claims.',
              suggestion: 'Pin an explicit signature algorithm (e.g. RS256, ES256, HS256) and never include "none".',
            })
          );
        }
      },
    });

    return findings;
  },
};

// ---------------------------------------------------------------------------
// 2. HARDCODED_BASIC_AUTH_CREDENTIALS
//
// URL-embedded credentials and literals fed to base64 encoders. `Basic <base64>` literals
// are already reported by API_KEY_EXPOSED (generic 'Basic Auth' pattern, which decodes the
// value), so they are deliberately not repeated here.
// ---------------------------------------------------------------------------

const URL_CREDENTIALS = /^[a-z][a-z0-9+.-]*:\/\/([^\s:@/?#\u0000]+):([^\s@/?#\u0000]+)@([^\s/?#]+)/i;
const BASE64_ENCODERS = new Set(['btoa']);

function isPlaceholderCredential(user: string, pass: string): boolean {
  return PLACEHOLDER_VALUE.test(pass) || /^(?:x+|\*+)$/i.test(user);
}

/** Template literal text with every interpolation replaced by a NUL, so partially dynamic URLs can be inspected. */
function templateSkeleton(node: any): string | null {
  if (node.type === 'StringLiteral') return node.value;
  if (node.type !== 'TemplateLiteral') return null;
  return node.quasis.map((q: any) => q.value.cooked ?? '').join('\u0000');
}

const hardcodedBasicAuthRule: Rule = {
  id: 'HARDCODED_BASIC_AUTH_CREDENTIALS',
  description: 'Hardcoded username:password credentials (URL userinfo or base64-encoded basic auth)',
  severity: Severity.HIGH,
  fileTypes: JS_FILES,
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    if (!context.ast) return findings;

    const reason =
      'Credentials written into the source ship inside the app bundle and can be extracted by anyone with the app, ' +
      'then used against the backend directly.';
    const suggestion = 'Do not embed credentials. Authenticate the user at runtime and use short-lived tokens issued by the server.';

    const credentialPair = (text: string): boolean => {
      const m = /^([^:\s]+):(\S.*)$/.exec(text);
      return !!m && !m[2].startsWith('//') && !isPlaceholderCredential(m[1], m[2]) && !/[\u0000]/.test(text);
    };

    traverse(context.ast, {
      // scheme://user:password@host
      'StringLiteral|TemplateLiteral'(path: any) {
        const { node } = path;
        if (path.parent.type === 'ImportDeclaration' || path.parent.type === 'TaggedTemplateExpression') return;
        const text = templateSkeleton(node);
        if (!text) return;
        const m = URL_CREDENTIALS.exec(text);
        if (!m) return;
        const [, user, pass, host] = m;
        if (isPlaceholderCredential(user, pass)) return;

        const local = isLocalOrPrivateHost(`http://${host.replace(/^[^@]*@/, '')}`);
        findings.push(
          makeFinding(context, node, {
            ruleId: 'HARDCODED_BASIC_AUTH_CREDENTIALS',
            description: `Hardcoded credentials in URL (${text.split('://')[0]}://${user}:****@${host.replace(/\u0000/g, '${...}')})`,
            severity: Severity.HIGH,
            confidence: local ? 'low' : 'medium',
            reason,
            suggestion,
          })
        );
      },

      CallExpression(path: any) {
        const { node } = path;
        const callee = node.callee;
        let literal: any = null;

        if (callee.type === 'Identifier' && BASE64_ENCODERS.has(callee.name)) {
          literal = node.arguments[0]; // btoa('user:pass')
        } else if (
          callee.type === 'MemberExpression' &&
          (memberName(callee) === 'btoa' ||
            (memberName(callee) === 'encode' &&
              callee.object.type === 'Identifier' &&
              /^base64$/i.test(callee.object.name)))
        ) {
          literal = node.arguments[0]; // window.btoa(...) / Base64.encode(...)
        } else if (
          callee.type === 'MemberExpression' &&
          memberName(callee) === 'toString' &&
          staticString(node.arguments[0]) === 'base64' &&
          callee.object.type === 'CallExpression' &&
          callee.object.callee.type === 'MemberExpression' &&
          callee.object.callee.object.type === 'Identifier' &&
          callee.object.callee.object.name === 'Buffer' &&
          memberName(callee.object.callee) === 'from'
        ) {
          literal = callee.object.arguments[0]; // Buffer.from('user:pass').toString('base64')
        }

        const text = staticString(literal);
        if (text !== null && credentialPair(text)) {
          findings.push(
            makeFinding(context, literal, {
              ruleId: 'HARDCODED_BASIC_AUTH_CREDENTIALS',
              description: 'Hardcoded "user:password" literal base64-encoded for HTTP Basic authentication',
              severity: Severity.HIGH,
              confidence: 'medium',
              reason,
              suggestion,
            })
          );
        }
      },
    });

    return findings;
  },
};

export const rnExtraRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [jwtInsecureSigningRule, hardcodedBasicAuthRule],
};
