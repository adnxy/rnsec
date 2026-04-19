import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';

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

const insecureKeystoreUsageRule: Rule = {
  id: 'INSECURE_KEYSTORE_USAGE',
  description: 'Android Keystore used without proper security configuration',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.java', '.kt'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast && !context.fileContent) {
      return findings;
    }

    const content = context.fileContent;
    
    // Check for ECB mode (insecure block cipher mode)
    if (content.includes('BLOCK_MODE_ECB')) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('BLOCK_MODE_ECB')) {
          findings.push({
            ruleId: 'INSECURE_KEYSTORE_USAGE',
            description: 'Android Keystore using ECB block mode - not semantically secure',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line: i + 1,
            snippet: lines[i].trim(),
            suggestion: 'Use BLOCK_MODE_GCM or BLOCK_MODE_CBC instead of ECB mode for proper encryption security.',
          });
        }
      }
    }

    // Check for missing user authentication requirement
    const hasKeystoreUsage = content.includes('KeyGenParameterSpec') || 
                             content.includes('KeyPairGenerator') ||
                             content.includes('KeyGenerator');
    
    if (hasKeystoreUsage) {
      const hasUserAuth = content.includes('setUserAuthenticationRequired') ||
                         content.includes('setUserAuthenticationParameters');
      const hasStrongBox = content.includes('setIsStrongBoxBacked');
      
      // Check if dealing with sensitive keys (encryption, signing)
      const isSensitiveContext = content.includes('PURPOSE_ENCRYPT') || 
                                 content.includes('PURPOSE_DECRYPT') ||
                                 content.includes('PURPOSE_SIGN');
      
      if (isSensitiveContext && !hasUserAuth) {
        findings.push({
          ruleId: 'INSECURE_KEYSTORE_USAGE',
          description: 'Android Keystore key generated without user authentication requirement',
          severity: Severity.HIGH,
          filePath: context.filePath,
          line: 1,
          suggestion: 'Add setUserAuthenticationRequired(true) to KeyGenParameterSpec for sensitive keys to require biometric/device credential authentication.',
        });
      }

      if (isSensitiveContext && !hasStrongBox) {
        findings.push({
          ruleId: 'INSECURE_KEYSTORE_USAGE',
          description: 'Android Keystore not using StrongBox hardware security',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: 1,
          suggestion: 'Consider using setIsStrongBoxBacked(true) for hardware-backed key storage on supported devices.',
        });
      }
    }

    return findings;
  },
};

const excessivePermissionsRule: Rule = {
  id: 'EXCESSIVE_PERMISSIONS',
  description: 'Android permissions declared but not used in code',
  severity: Severity.LOW,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    // Extract declared permissions
    const permissionPattern = /<uses-permission\s+android:name="([^"]+)"\s*\/>/gi;
    const matches = [...context.xmlContent.matchAll(permissionPattern)];
    
    if (matches.length === 0) {
      return findings;
    }

    // Common permission keywords to search for in code
    const permissionChecks = [
      'CAMERA', 'LOCATION', 'CONTACTS', 'MICROPHONE', 'STORAGE',
      'READ_PHONE_STATE', 'CALL_PHONE', 'SMS', 'BLUETOOTH'
    ];

    const unusedPermissions: string[] = [];
    
    for (const match of matches) {
      const permissionName = match[1];
      const permissionShortName = permissionName.split('.').pop() || permissionName;
      
      // Check if permission is commonly excessive
      const isCommonlyExcessive = permissionChecks.some(check => 
        permissionShortName.includes(check)
      );
      
      if (isCommonlyExcessive) {
        unusedPermissions.push(permissionName);
      }
    }

    if (unusedPermissions.length > 0) {
      findings.push({
        ruleId: 'EXCESSIVE_PERMISSIONS',
        description: `Potentially excessive permissions declared: ${unusedPermissions.slice(0, 3).join(', ')}${unusedPermissions.length > 3 ? '...' : ''}`,
        severity: Severity.LOW,
        filePath: context.filePath,
        suggestion: 'Review declared permissions and remove those not actively used. Request permissions at runtime only when needed.',
      });
    }

    return findings;
  },
};

const androidTaskAffinityVulnerabilityRule: Rule = {
  id: 'ANDROID_TASK_AFFINITY_VULNERABILITY',
  description: 'Android activity with custom task affinity - vulnerable to task hijacking',
  severity: Severity.MEDIUM,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    // Check for activities with custom taskAffinity
    const activityPattern = /<activity[^>]*android:taskAffinity="([^"]*)"[^>]*>/gi;
    const matches = context.xmlContent.matchAll(activityPattern);

    for (const match of matches) {
      const affinity = match[1];

      // Empty taskAffinity is actually secure (prevents hijacking)
      if (affinity === '') continue;

      findings.push({
        ruleId: 'ANDROID_TASK_AFFINITY_VULNERABILITY',
        description: `Activity with custom taskAffinity="${affinity}" - vulnerable to StrandHogg task hijacking`,
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        suggestion: 'Set android:taskAffinity="" (empty string) on activities to prevent task hijacking attacks (StrandHogg). This prevents malicious apps from intercepting your activities.',
      });
    }

    return findings;
  },
};

const androidWebviewDebugEnabledRule: Rule = {
  id: 'ANDROID_WEBVIEW_DEBUG_ENABLED',
  description: 'Android WebView debugging enabled - allows remote inspection',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.java', '.kt'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    const content = context.fileContent;

    if (content.includes('setWebContentsDebuggingEnabled') && content.includes('true')) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('setWebContentsDebuggingEnabled') && lines[i].includes('true')) {
          // Check for __DEV__ guard
          const surroundingCode = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join('\n');
          const hasDevCheck = /__DEV__|BuildConfig\.DEBUG|isDebuggable/i.test(surroundingCode);

          if (!hasDevCheck) {
            findings.push({
              ruleId: 'ANDROID_WEBVIEW_DEBUG_ENABLED',
              description: 'WebView debugging enabled without build type check - allows remote Chrome DevTools inspection',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line: i + 1,
              snippet: lines[i].trim(),
              suggestion: 'Guard WebView debugging with BuildConfig.DEBUG or __DEV__ check. WebView debugging allows attackers to inspect and modify web content.',
            });
          }
        }
      }
    }

    // Also check for react-native-webview debug prop
    if (context.ast) {
      traverse(context.ast, {
        JSXAttribute(path: any) {
          const { node } = path;
          if (
            node.name.type === 'JSXIdentifier' &&
            node.name.name === 'webContentsDebuggingEnabled' &&
            node.value?.type === 'JSXExpressionContainer' &&
            node.value.expression.type === 'BooleanLiteral' &&
            node.value.expression.value === true
          ) {
            const surroundingCode = context.fileContent.substring(
              Math.max(0, (node.start || 0) - 200),
              Math.min(context.fileContent.length, (node.end || 0) + 100)
            );
            const hasDevCheck = /__DEV__|process\.env\.NODE_ENV/.test(surroundingCode);

            if (!hasDevCheck) {
              const line = getLineNumber(context.fileContent, node.start || 0);

              findings.push({
                ruleId: 'ANDROID_WEBVIEW_DEBUG_ENABLED',
                description: 'WebView webContentsDebuggingEnabled={true} without __DEV__ guard',
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Only enable WebView debugging in development: webContentsDebuggingEnabled={__DEV__}',
              });
            }
          }
        },
      });
    }

    return findings;
  },
};

const androidMissingNetworkSecurityConfigRule: Rule = {
  id: 'ANDROID_MISSING_NETWORK_SECURITY_CONFIG',
  description: 'Android manifest missing network security config reference',
  severity: Severity.MEDIUM,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    const hasNetworkSecurityConfig = context.xmlContent.includes('android:networkSecurityConfig');

    // Only flag if the app uses internet permission (is a networked app)
    const hasInternetPermission = context.xmlContent.includes('android.permission.INTERNET');

    if (hasInternetPermission && !hasNetworkSecurityConfig) {
      findings.push({
        ruleId: 'ANDROID_MISSING_NETWORK_SECURITY_CONFIG',
        description: 'Network-enabled app without network_security_config.xml - missing certificate pinning and cleartext traffic control',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        suggestion: 'Add android:networkSecurityConfig="@xml/network_security_config" to <application> tag. Configure certificate pinning and restrict cleartext traffic.',
      });
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
    androidUnprotectedBroadcastReceiverRule,
    androidContentProviderNoPermissionRule,
    insecureKeystoreUsageRule,
    excessivePermissionsRule,
    androidTaskAffinityVulnerabilityRule,
    androidWebviewDebugEnabledRule,
    androidMissingNetworkSecurityConfigRule,
  ],
};
