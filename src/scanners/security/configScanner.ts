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

const expoSensitiveConfigExposedRule: Rule = {
  id: 'EXPO_SENSITIVE_CONFIG_EXPOSED',
  description: 'Sensitive values exposed in Expo app.json configuration',
  severity: Severity.HIGH,
  fileTypes: ['.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.config || !context.filePath.includes('app.json')) {
      return findings;
    }

    const expo = context.config.expo;
    if (!expo) return findings;

    // Check extra/config for exposed secrets
    const configSections = [expo.extra, expo.plugins, expo.ios?.config, expo.android?.config];
    const sensitiveKeyPatterns = ['secret', 'apikey', 'api_key', 'private_key', 'privatekey', 'password',
                                  'client_secret', 'clientsecret', 'access_token', 'accesstoken'];

    function checkObject(obj: any, path: string): void {
      if (!obj || typeof obj !== 'object') return;

      for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        const isSecretKey = sensitiveKeyPatterns.some(p => lowerKey.includes(p));

        if (isSecretKey && typeof value === 'string' && value.length > 0) {
          // Skip placeholder/env references
          const lowerValue = value.toLowerCase();
          if (lowerValue.includes('process.env') || lowerValue.includes('${') ||
              lowerValue.includes('your_') || lowerValue.includes('placeholder') ||
              lowerValue.includes('example') || lowerValue.includes('xxx')) {
            continue;
          }

          findings.push({
            ruleId: 'EXPO_SENSITIVE_CONFIG_EXPOSED',
            description: `Sensitive config key "${key}" exposed in app.json at ${path}`,
            severity: Severity.HIGH,
            filePath: context.filePath,
            suggestion: 'Move sensitive values to environment variables. Use app.config.js with process.env to inject secrets at build time.',
          });
        }

        if (typeof value === 'object' && value !== null) {
          checkObject(value, `${path}.${key}`);
        }
      }
    }

    if (expo.extra) checkObject(expo.extra, 'expo.extra');
    if (expo.ios?.config) checkObject(expo.ios.config, 'expo.ios.config');
    if (expo.android?.config) checkObject(expo.android.config, 'expo.android.config');

    return findings;
  },
};

export const configRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [
    expoInsecurePermissionsRule,
    expoUpdatesInsecureUrlRule,
    expoSensitiveConfigExposedRule,
  ],
};
