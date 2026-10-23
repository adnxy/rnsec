import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { isPlaceholderValue } from '../../utils/sensitiveDataPatterns.js';
import { isLocalOrPrivateHost } from '../../utils/hostUtils.js';

const baseName = (filePath: string): string => filePath.split(/[\\/]/).pop() ?? '';
const ID = 'NPM_REGISTRY_CONFIG_INSECURE';

const mask = (value: string): string => (value.length >= 12 ? `${value.slice(0, 2)}****` : '****');

function unquote(value: string): string {
  const v = value.trim();
  const q = /^(["'])(.*)\1/.exec(v);
  return q ? q[2] : v;
}

/** A credential that is really a reference (`${NPM_TOKEN}`) or an obvious placeholder. */
const isNotLiteralSecret = (value: string): boolean => !value || value.includes('${') || isPlaceholderValue(value);

const isInsecurePublicHttp = (url: string): boolean => /^http:\/\//i.test(url) && !url.includes('${') && !isLocalOrPrivateHost(url);

const AUTH_DOC = 'Use an environment variable reference such as //registry.npmjs.org/:_authToken=${NPM_TOKEN}, store the token in CI secrets, and revoke the exposed token.';

function npmrcFindings(context: RuleContext): Finding[] {
  const findings: Finding[] = [];
  context.fileContent.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) return;
    const m = /^([^=]+?)\s*=\s*(.*)$/.exec(line);
    if (!m) return;
    const key = m[1].trim();
    const value = unquote(m[2]);
    const lineNo = i + 1;

    if (/(^|:)(_authToken|_auth|_password)$/i.test(key)) {
      if (isNotLiteralSecret(value)) return;
      findings.push({
        ruleId: ID,
        description: `.npmrc contains a literal registry credential (${key.replace(/^.*:/, '')}=${mask(value)})`,
        severity: Severity.HIGH,
        confidence: 'high',
        filePath: context.filePath,
        line: lineNo,
        snippet: `${key}=${mask(value)}`,
        reason: 'A committed registry token lets anyone with repository access publish or install private packages as you.',
        suggestion: AUTH_DOC,
      });
    } else if (/^strict-ssl$/i.test(key) && value.toLowerCase() === 'false') {
      findings.push({
        ruleId: ID,
        description: '.npmrc disables TLS certificate validation (strict-ssl=false)',
        severity: Severity.MEDIUM,
        confidence: 'high',
        filePath: context.filePath,
        line: lineNo,
        snippet: line,
        reason: 'Package downloads can be tampered with by anyone on the network path.',
        suggestion: 'Remove strict-ssl=false; trust a private CA with the cafile setting if needed.',
      });
    } else if (/^(@[\w.-]+:)?registry$/i.test(key) && isInsecurePublicHttp(value)) {
      findings.push({
        ruleId: ID,
        description: `.npmrc uses an insecure HTTP registry (${value})`,
        severity: Severity.MEDIUM,
        confidence: 'high',
        filePath: context.filePath,
        line: lineNo,
        snippet: line,
        reason: 'Packages and tokens sent over HTTP can be read or replaced by anyone on the network path.',
        suggestion: 'Use an https:// registry URL.',
      });
    }
  });
  return findings;
}

function yarnrcFindings(context: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const lines = context.fileContent.split(/\r?\n/);
  let whitelistIndent = -1;

  const stripComment = (v: string): string => (/^\s*["']/.test(v) ? v : v.replace(/\s+#.*$/, ''));
  const flagWildcard = (item: string, lineNo: number, raw: string) => {
    if (!item.includes('*')) return;
    findings.push({
      ruleId: ID,
      description: `.yarnrc.yml allows plain HTTP for a wildcard host (unsafeHttpWhitelist: ${item})`,
      severity: Severity.MEDIUM,
      confidence: 'high',
      filePath: context.filePath,
      line: lineNo,
      snippet: raw.trim(),
      reason: 'A wildcard whitelist lets Yarn fetch packages over HTTP from any matching host.',
      suggestion: 'List only the specific hosts that need HTTP, or serve them over HTTPS.',
    });
  };

  lines.forEach((raw, i) => {
    const lineNo = i + 1;
    if (/^\s*(#|$)/.test(raw)) return;
    const indent = raw.length - raw.trimStart().length;

    if (whitelistIndent >= 0) {
      const item = /^\s*-\s*(.*)$/.exec(raw);
      if (item && indent >= whitelistIndent) {
        flagWildcard(unquote(stripComment(item[1])), lineNo, raw);
        return;
      }
      whitelistIndent = -1;
    }

    const m = /^\s*("?[\w@/.:-]+"?)\s*:\s*(.*)$/.exec(raw);
    if (!m) return;
    const key = m[1].replace(/"/g, '');
    const rest = stripComment(m[2]);
    const value = unquote(rest);

    if (/^(npmAuthToken|npmAuthIdent)$/.test(key)) {
      if (isNotLiteralSecret(value)) return;
      findings.push({
        ruleId: ID,
        description: `.yarnrc.yml contains a literal registry credential (${key}: ${mask(value)})`,
        severity: Severity.HIGH,
        confidence: 'high',
        filePath: context.filePath,
        line: lineNo,
        snippet: `${key}: ${mask(value)}`,
        reason: 'A committed registry token lets anyone with repository access publish or install private packages as you.',
        suggestion: 'Use an environment variable reference such as npmAuthToken: "${NPM_TOKEN:-}", store the token in CI secrets, and revoke the exposed token.',
      });
    } else if (key === 'enableStrictSsl' && value.toLowerCase() === 'false') {
      findings.push({
        ruleId: ID,
        description: '.yarnrc.yml disables TLS certificate validation (enableStrictSsl: false)',
        severity: Severity.MEDIUM,
        confidence: 'high',
        filePath: context.filePath,
        line: lineNo,
        snippet: raw.trim(),
        reason: 'Package downloads can be tampered with by anyone on the network path.',
        suggestion: 'Remove enableStrictSsl: false; trust a private CA with httpsCaFilePath if needed.',
      });
    } else if (key === 'npmRegistryServer' && isInsecurePublicHttp(value)) {
      findings.push({
        ruleId: ID,
        description: `.yarnrc.yml uses an insecure HTTP registry (${value})`,
        severity: Severity.MEDIUM,
        confidence: 'high',
        filePath: context.filePath,
        line: lineNo,
        snippet: raw.trim(),
        reason: 'Packages and tokens sent over HTTP can be read or replaced by anyone on the network path.',
        suggestion: 'Use an https:// registry URL.',
      });
    } else if (key === 'unsafeHttpWhitelist') {
      const inline = /^\[(.*)\]$/.exec(rest.trim());
      if (inline) {
        inline[1].split(',').forEach(item => flagWildcard(unquote(item), lineNo, raw));
      } else if (!rest.trim()) {
        whitelistIndent = indent;
      }
    }
  });
  return findings;
}

const registryConfigRule: Rule = {
  id: ID,
  description: 'npm/Yarn registry config exposes credentials or weakens transport security',
  severity: Severity.HIGH,
  fileTypes: ['.npmrc', '.yarnrc.yml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const name = baseName(context.filePath);
    if (name === '.npmrc') return npmrcFindings(context);
    if (name === '.yarnrc.yml') return yarnrcFindings(context);
    return [];
  },
};

export const registryConfigRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [registryConfigRule],
};
