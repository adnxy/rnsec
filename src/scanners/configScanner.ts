import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { RuleCategory } from '../types/ruleTypes.js';

const expoInsecurePermissionsRule: Rule = {
  id: 'EXPO_INSECURE_PERMISSIONS',
  description: 'Potentially dangerous permissions detected in Expo config',
  severity: Severity.LOW,
  fileTypes: ['.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.config || !context.filePath.includes('app.json')) {
      return findings;
    }

    const dangerousPermissions = [
      'android.permission.READ_PHONE_STATE',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
    ];

    if (context.config.expo?.android?.permissions) {
      const permissions = context.config.expo.android.permissions;
      
      for (const permission of permissions) {
        if (dangerousPermissions.includes(permission)) {
          findings.push({
            ruleId: 'EXPO_INSECURE_PERMISSIONS',
            description: `Dangerous permission detected: ${permission}`,
            severity: Severity.LOW,
            filePath: context.filePath,
            suggestion: 'Only request necessary permissions and explain usage to users',
          });
        }
      }
    }

    return findings;
  },
};

export const configRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [expoInsecurePermissionsRule],
};
