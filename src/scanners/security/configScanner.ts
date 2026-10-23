import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';

const expoInsecurePermissionsRule: Rule = {
  id: 'EXPO_INSECURE_PERMISSIONS',
  description: 'Potentially dangerous permissions detected in Expo config',
  severity: Severity.LOW,
  fileTypes: ['.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    const fileName = context.filePath.split(/[\\/]/).pop();
    if (!context.config || (fileName !== 'app.json' && fileName !== 'app.config.json')) {
      return findings;
    }

    const dangerousPermissions = [
      'android.permission.READ_PHONE_STATE',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
    ];

    const permissions = context.config.expo?.android?.permissions;
    if (Array.isArray(permissions)) {
      const lines = context.fileContent.split('\n');
      
      for (const permission of permissions) {
        if (typeof permission === 'string' && dangerousPermissions.includes(permission)) {
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
  fileTypes: ['.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

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

export const configRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [
    expoInsecurePermissionsRule,
    expoUpdatesInsecureUrlRule,
  ],
};
