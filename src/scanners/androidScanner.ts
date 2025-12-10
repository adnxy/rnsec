import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { RuleCategory } from '../types/ruleTypes.js';

const androidDebuggableRule: Rule = {
  id: 'ANDROID_DEBUGGABLE_ENABLED',
  description: 'android:debuggable="true" in production manifest',
  severity: Severity.HIGH,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    if (context.xmlContent.includes('android:debuggable="true"')) {
      findings.push({
        ruleId: 'ANDROID_DEBUGGABLE_ENABLED',
        description: 'Application is debuggable - allows memory dumps and code inspection',
        severity: Severity.HIGH,
        filePath: context.filePath,
        suggestion: 'Remove android:debuggable="true" or ensure it\'s only set in debug builds. Debuggable apps expose sensitive data.',
      });
    }

    return findings;
  },
};

const androidBackupAllowedRule: Rule = {
  id: 'ANDROID_BACKUP_ALLOWED',
  description: 'android:allowBackup="true" for sensitive app',
  severity: Severity.MEDIUM,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    const hasBackupEnabled = context.xmlContent.includes('android:allowBackup="true"');
    const hasBackupFalse = context.xmlContent.includes('android:allowBackup="false"');
    
    const sensitiveIndicators = [
      'permission.CAMERA',
      'permission.ACCESS_FINE_LOCATION',
      'permission.READ_CONTACTS',
      'permission.RECORD_AUDIO',
      'SecureStore',
      'biometric',
    ];

    const hasSensitiveContent = sensitiveIndicators.some(indicator => 
      context.xmlContent?.includes(indicator)
    );

    if (hasBackupEnabled && hasSensitiveContent) {
      findings.push({
        ruleId: 'ANDROID_BACKUP_ALLOWED',
        description: 'Backup enabled for app with sensitive data - data can be extracted via ADB',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        suggestion: 'Set android:allowBackup="false" or implement android:fullBackupContent rules to exclude sensitive data.',
      });
    } else if (!hasBackupFalse && !hasBackupEnabled && hasSensitiveContent) {
      findings.push({
        ruleId: 'ANDROID_BACKUP_ALLOWED',
        description: 'Backup setting not specified for sensitive app (defaults to true)',
        severity: Severity.LOW,
        filePath: context.filePath,
        suggestion: 'Explicitly set android:allowBackup="false" for apps handling sensitive data.',
      });
    }

    return findings;
  },
};

const androidExportedComponentRule: Rule = {
  id: 'ANDROID_EXPORTED_COMPONENT',
  description: 'Exported Android component without permission protection',
  severity: Severity.HIGH,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    const componentTypes = ['activity', 'service', 'receiver', 'provider'];
    
    for (const componentType of componentTypes) {
      const componentPattern = new RegExp(
        `<${componentType}[^>]*android:exported="true"[^>]*>([\\s\\S]*?)</${componentType}>`,
        'gi'
      );
      
      const matches = context.xmlContent.matchAll(componentPattern);
      
      for (const match of matches) {
        const componentContent = match[0];
        const hasPermission = componentContent.includes('android:permission=');
        const hasIntentFilter = componentContent.includes('<intent-filter');
        
        if (!hasPermission) {
          findings.push({
            ruleId: 'ANDROID_EXPORTED_COMPONENT',
            description: `Exported ${componentType} without permission protection - accessible by any app`,
            severity: Severity.HIGH,
            filePath: context.filePath,
            suggestion: `Add android:permission attribute to exported ${componentType} or set android:exported="false" if external access is not needed.`,
          });
        }
      }
    }

    return findings;
  },
};

const androidIntentFilterTooPermissiveRule: Rule = {
  id: 'ANDROID_INTENT_FILTER_PERMISSIVE',
  description: 'Overly permissive intent filter may expose functionality',
  severity: Severity.MEDIUM,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    const dangerousIntents = [
      { action: 'android.intent.action.VIEW', category: 'android.intent.category.DEFAULT', risk: 'Can be invoked by any app' },
      { action: 'android.intent.action.SEND', category: 'android.intent.category.DEFAULT', risk: 'Can receive data from any app' },
      { action: 'android.intent.action.SENDTO', category: null, risk: 'Can be invoked with arbitrary data' },
    ];

    for (const { action, category, risk } of dangerousIntents) {
      if (context.xmlContent.includes(action)) {
        const intentFilterPattern = /<intent-filter[\s\S]*?<\/intent-filter>/gi;
        const matches = context.xmlContent.matchAll(intentFilterPattern);
        
        for (const match of matches) {
          const filterContent = match[0];
          
          if (filterContent.includes(action) && (!category || filterContent.includes(category))) {
            findings.push({
              ruleId: 'ANDROID_INTENT_FILTER_PERMISSIVE',
              description: `Permissive intent filter with ${action}: ${risk}`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              suggestion: 'Validate all incoming intents and restrict with custom permissions if external access is not required.',
            });
          }
        }
      }
    }

    return findings;
  },
};

const androidNetworkSecurityConfigMissingRule: Rule = {
  id: 'ANDROID_NETWORK_SECURITY_CONFIG_MISSING',
  description: 'Network security config not configured',
  severity: Severity.MEDIUM,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    const hasNetworkSecurityConfig = context.xmlContent.includes('android:networkSecurityConfig');
    const hasCleartextEnabled = context.xmlContent.includes('android:usesCleartextTraffic="true"');

    if (!hasNetworkSecurityConfig && !hasCleartextEnabled) {
      findings.push({
        ruleId: 'ANDROID_NETWORK_SECURITY_CONFIG_MISSING',
        description: 'No network security configuration specified',
        severity: Severity.LOW,
        filePath: context.filePath,
        suggestion: 'Add android:networkSecurityConfig to implement certificate pinning, restrict cleartext traffic, and configure trusted CAs.',
      });
    }

    return findings;
  },
};

const androidUnprotectedBroadcastReceiverRule: Rule = {
  id: 'ANDROID_UNPROTECTED_RECEIVER',
  description: 'Broadcast receiver without permission protection',
  severity: Severity.HIGH,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    const receiverPattern = /<receiver[^>]*>[\s\S]*?<\/receiver>/gi;
    const matches = context.xmlContent.matchAll(receiverPattern);
    
    for (const match of matches) {
      const receiverContent = match[0];
      const hasPermission = receiverContent.includes('android:permission=');
      const isExported = receiverContent.includes('android:exported="true"') || 
                        receiverContent.includes('<intent-filter');
      
      if (isExported && !hasPermission) {
        findings.push({
          ruleId: 'ANDROID_UNPROTECTED_RECEIVER',
          description: 'Broadcast receiver is exported without permission - can be triggered by malicious apps',
          severity: Severity.HIGH,
          filePath: context.filePath,
          suggestion: 'Add android:permission to protect receiver or set android:exported="false" for internal broadcasts.',
        });
      }
    }

    return findings;
  },
};

const androidContentProviderNoPermissionRule: Rule = {
  id: 'ANDROID_CONTENT_PROVIDER_NO_PERMISSION',
  description: 'Content provider without read/write permissions',
  severity: Severity.HIGH,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    const providerPattern = /<provider[^>]*\/?>|<provider[^>]*>[\s\S]*?<\/provider>/gi;
    const matches = context.xmlContent.matchAll(providerPattern);
    
    for (const match of matches) {
      const providerContent = match[0];
      const isExported = providerContent.includes('android:exported="true"');
      const hasReadPermission = providerContent.includes('android:readPermission=');
      const hasWritePermission = providerContent.includes('android:writePermission=');
      const hasPermission = providerContent.includes('android:permission=');
      
      if (isExported && !hasReadPermission && !hasWritePermission && !hasPermission) {
        findings.push({
          ruleId: 'ANDROID_CONTENT_PROVIDER_NO_PERMISSION',
          description: 'Exported content provider without permission protection - data accessible to all apps',
          severity: Severity.HIGH,
          filePath: context.filePath,
          suggestion: 'Add android:readPermission, android:writePermission, or android:permission to protect the content provider.',
        });
      }
    }

    return findings;
  },
};

export const androidRules: RuleGroup = {
  category: RuleCategory.MANIFEST,
  rules: [
    androidDebuggableRule,
    androidBackupAllowedRule,
    androidExportedComponentRule,
    androidIntentFilterTooPermissiveRule,
    androidNetworkSecurityConfigMissingRule,
    androidUnprotectedBroadcastReceiverRule,
    androidContentProviderNoPermissionRule,
  ],
};

