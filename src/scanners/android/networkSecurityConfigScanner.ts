import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { getLineNumber } from '../../utils/stringUtils.js';

const isNetworkSecurityConfig = (filePath: string): boolean =>
  /(^|[\\/])network_security_config\.xml$/.test(filePath);

/** Replace XML comments with spaces (newlines kept) so offsets and line numbers stay accurate. */
function blankComments(xml: string): string {
  return xml.replace(/<!--[\s\S]*?(-->|$)/g, m => m.replace(/[^\n]/g, ' '));
}

function attr(attrs: string, name: string): string | undefined {
  const m = new RegExp(`(?:^|\\s)(?:[\\w-]+:)?${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 'i').exec(attrs);
  return m ? (m[1] ?? m[2]) : undefined;
}

const isTrue = (v: string | undefined): boolean => v?.trim().toLowerCase() === 'true';

const LOCAL_DOMAIN =
  /^(localhost|127(\.\d{1,3}){3}|10\.0\.2\.2|10(\.\d{1,3}){3}|192\.168(\.\d{1,3}){2}|172\.(1[6-9]|2\d|3[01])(\.\d{1,3}){2}|\[?::1\]?|[^\s]+\.local|[^\s]+\.localhost)$/i;

interface CleartextEntry {
  line: number;
  kind: 'base' | 'domain';
  domains: string[];
}
interface CertEntry {
  line: number;
  userSrc: boolean;
  overridePins: boolean;
}

function analyze(xml: string): { cleartext: CleartextEntry[]; certs: CertEntry[] } {
  const src = blankComments(xml);
  const cleartext: CleartextEntry[] = [];
  const certs: CertEntry[] = [];
  const stack: { name: string; entry?: CleartextEntry; cleartext: boolean }[] = [];
  const tagRe = /<(\/?)([A-Za-z][\w:.-]*)((?:"[^"]*"|'[^']*'|[^'">])*?)(\/?)>/g;
  let m: RegExpExecArray | null;

  while ((m = tagRe.exec(src)) !== null) {
    const [, closing, rawName, attrs, selfClose] = m;
    const name = rawName.toLowerCase();
    const inDebug = stack.some(s => s.name === 'debug-overrides');

    if (closing) {
      // Pop to the matching open tag (tolerates unbalanced input).
      const idx = stack.map(s => s.name).lastIndexOf(name);
      if (idx === -1) continue;
      const [closed] = stack.splice(idx);
      if (closed.name === 'domain-config' && closed.entry && closed.cleartext) {
        cleartext.push(closed.entry);
      }
      continue;
    }

    const line = getLineNumber(src, m.index);

    if (name === 'base-config' && !inDebug && isTrue(attr(attrs, 'cleartextTrafficPermitted'))) {
      cleartext.push({ line, kind: 'base', domains: [] });
    } else if (name === 'domain') {
      const owner = [...stack].reverse().find(s => s.name === 'domain-config');
      if (owner?.entry && !selfClose) {
        const rest = src.slice(tagRe.lastIndex);
        const text = rest.slice(0, Math.max(0, rest.indexOf('<'))).trim();
        if (text) owner.entry.domains.push(text);
      }
    } else if (name === 'certificates' && !inDebug) {
      const userSrc = (attr(attrs, 'src') ?? '').trim().toLowerCase() === 'user';
      const overridePins = isTrue(attr(attrs, 'overridePins'));
      if (userSrc || overridePins) certs.push({ line, userSrc, overridePins });
    }

    if (!selfClose) {
      const isDomainConfig = name === 'domain-config';
      stack.push({
        name,
        cleartext: isDomainConfig && !inDebug && isTrue(attr(attrs, 'cleartextTrafficPermitted')),
        entry: isDomainConfig ? { line, kind: 'domain', domains: [] } : undefined,
      });
    }
  }
  return { cleartext, certs };
}

const cleartextRule: Rule = {
  id: 'ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT',
  description: 'Network security config permits cleartext (HTTP) traffic',
  severity: Severity.HIGH,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    if (!context.xmlContent || !isNetworkSecurityConfig(context.filePath)) return [];
    const findings: Finding[] = [];

    for (const entry of analyze(context.xmlContent).cleartext) {
      if (entry.kind === 'base') {
        findings.push({
          ruleId: 'ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT',
          description: 'network_security_config.xml permits cleartext traffic for all domains (<base-config cleartextTrafficPermitted="true">)',
          severity: Severity.HIGH,
          filePath: context.filePath,
          line: entry.line,
          reason: 'Cleartext HTTP traffic can be read and modified by anyone on the network path.',
          suggestion: 'Set cleartextTrafficPermitted="false" on <base-config> and allow cleartext only for specific development hosts in a <domain-config>.',
        });
        continue;
      }
      if (entry.domains.length > 0 && entry.domains.every(d => LOCAL_DOMAIN.test(d))) continue;
      findings.push({
        ruleId: 'ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT',
        description: `network_security_config.xml permits cleartext traffic for ${entry.domains.length ? entry.domains.join(', ') : 'a domain-config'}`,
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line: entry.line,
        reason: 'Cleartext HTTP traffic to a non-local host can be read and modified by anyone on the network path.',
        suggestion: 'Serve these domains over HTTPS and remove cleartextTrafficPermitted="true".',
      });
    }
    return findings;
  },
};

const userCaRule: Rule = {
  id: 'ANDROID_USER_CA_TRUSTED',
  description: 'Network security config weakens certificate trust (user CAs or overridePins)',
  severity: Severity.MEDIUM,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    if (!context.xmlContent || !isNetworkSecurityConfig(context.filePath)) return [];
    const findings: Finding[] = [];

    for (const cert of analyze(context.xmlContent).certs) {
      if (cert.userSrc) {
        findings.push({
          ruleId: 'ANDROID_USER_CA_TRUSTED',
          description: 'App trusts user-installed CA certificates (<certificates src="user"/>) outside debug-overrides',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: cert.line,
          reason: 'User-installed CAs let a device owner or malware-installed certificate intercept TLS traffic. Apps targeting API 24+ do not trust them by default.',
          suggestion: 'Remove <certificates src="user"/> or move it into <debug-overrides>, which only applies to debuggable builds.',
        });
      }
      if (cert.overridePins) {
        findings.push({
          ruleId: 'ANDROID_USER_CA_TRUSTED',
          description: 'Certificate pinning is disabled for trust anchors (overridePins="true") outside debug-overrides',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: cert.line,
          reason: 'overridePins="true" makes these trust anchors bypass pin-set validation.',
          suggestion: 'Remove overridePins="true" or move it into <debug-overrides>.',
        });
      }
    }
    return findings;
  },
};

export const networkSecurityConfigRules: RuleGroup = {
  category: RuleCategory.MANIFEST,
  rules: [cleartextRule, userCaRule],
};
