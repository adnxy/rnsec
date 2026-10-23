import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';

const baseName = (filePath: string): string => filePath.split(/[\\/]/).pop() ?? '';

const SUGGESTION =
  'Remove the file from git and its history (git rm --cached, then git filter-repo or BFG), add it to .gitignore, rotate the credential, and keep it in EAS credentials or your CI secret store.';

const KIND: Record<string, { label: string; severity: Severity }> = {
  jks: { label: 'Android signing keystore', severity: Severity.HIGH },
  keystore: { label: 'Android signing keystore', severity: Severity.HIGH },
  p12: { label: 'PKCS#12 signing certificate and private key', severity: Severity.HIGH },
  pfx: { label: 'PKCS#12 signing certificate and private key', severity: Severity.HIGH },
  p8: { label: 'Apple auth key (.p8)', severity: Severity.HIGH },
  mobileprovision: { label: 'iOS provisioning profile with embedded certificates', severity: Severity.MEDIUM },
};

/** 1-based line of the `"private_key"` entry in raw JSON text. */
function privateKeyLine(text: string): number {
  const m = /"private_key"\s*:/.exec(text);
  if (!m) return 1;
  return text.slice(0, m.index).split('\n').length;
}

const committedCredentialFileRule: Rule = {
  id: 'COMMITTED_CREDENTIAL_FILE',
  description: 'Signing key, certificate or service-account credential committed to the repository',
  severity: Severity.HIGH,
  fileTypes: ['.jks', '.keystore', '.p12', '.pfx', '.p8', '.mobileprovision', '.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const name = baseName(context.filePath);
    const lower = name.toLowerCase();
    if (lower === 'debug.keystore') return [];

    const ext = lower.includes('.') ? lower.slice(lower.lastIndexOf('.') + 1) : '';

    if (ext === 'json') {
      // google-services.json is public Firebase client config, never a secret
      if (lower === 'google-services.json') return [];
      const cfg = context.config as Record<string, unknown> | undefined;
      if (!cfg || typeof cfg !== 'object') return [];
      if (cfg.type !== 'service_account') return [];
      if (typeof cfg.private_key !== 'string' || cfg.private_key.trim() === '') return [];
      return [
        {
          ruleId: 'COMMITTED_CREDENTIAL_FILE',
          description: `${name} is a committed service-account credential containing a private key`,
          severity: Severity.HIGH,
          confidence: 'high',
          filePath: context.filePath,
          line: privateKeyLine(context.fileContent),
          reason: 'The private key grants API access as the service account (for example Firebase Admin or Google Play publishing) to anyone who can read the repository.',
          suggestion: SUGGESTION,
        },
      ];
    }

    const kind = KIND[ext];
    if (!kind) return [];
    return [
      {
        ruleId: 'COMMITTED_CREDENTIAL_FILE',
        description: `${name} is committed to the repository (${kind.label})`,
        severity: kind.severity,
        confidence: 'high',
        filePath: context.filePath,
        line: 1,
        reason: 'Signing keys and certificates must stay private; a leaked key lets others sign builds as you.',
        suggestion: SUGGESTION,
      },
    ];
  },
};

export const credentialFileRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [committedCredentialFileRule],
};
