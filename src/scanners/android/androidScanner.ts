import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';

/** Blank out XML comments (keeping offsets and newlines) so commented-out components are ignored */
function stripXmlComments(xml: string): string {
  return xml.replace(/<!--[\s\S]*?-->/g, m => m.replace(/[^\n]/g, ' '));
}

interface ManifestElement {
  tag: string;
  /** Offset of the opening `<` */
  index: number;
  /** Opening tag only, e.g. `<activity android:name=".Main">` */
  openTag: string;
  /** Opening tag through its closing tag (or just the opening tag when self-closing) */
  text: string;
}

/** Extract components element by element, so a self-closing tag never swallows its neighbour */
function extractElements(xml: string, tags: string[]): ManifestElement[] {
  const elements: ManifestElement[] = [];
  const opening = new RegExp(`<(${tags.join('|')})(?=[\\s>/])((?:"[^"]*"|'[^']*'|[^>"'])*)>`, 'g');
  let m: RegExpExecArray | null;
  while ((m = opening.exec(xml)) !== null) {
    const openTag = m[0];
    const selfClosing = openTag.endsWith('/>');
    let end = m.index + openTag.length;
    if (!selfClosing) {
      const close = xml.indexOf(`</${m[1]}>`, end);
      if (close !== -1) end = close + m[1].length + 3;
    }
    elements.push({ tag: m[1], index: m.index, openTag, text: xml.slice(m.index, end) });
  }
  return elements;
}

/** Value of an attribute in an opening tag, e.g. attrValue(tag, 'android:exported') */
function attrValue(openTag: string, name: string): string | undefined {
  const m = openTag.match(new RegExp(`(?:^|\\s)${name.replace(':', '\\:')}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`));
  return m ? (m[1] ?? m[2]) : undefined;
}

/** Line (1-based) of the first occurrence of `needle`, or undefined */
function lineOf(xml: string, needle: string | RegExp): number | undefined {
  const idx = typeof needle === 'string' ? xml.indexOf(needle) : xml.search(needle);
  return idx === -1 ? undefined : getLineNumber(xml, idx);
}

/** The activity declares MAIN + LAUNCHER, i.e. it is the app icon entry point and must be exported */
function isLauncherComponent(text: string): boolean {
  return /android\.intent\.action\.MAIN/.test(text) && /android\.intent\.category\.LAUNCHER/.test(text);
}

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
        line: lineOf(context.xmlContent, 'android:debuggable="true"'),
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

    const xml = stripXmlComments(context.xmlContent);
    const app = extractElements(xml, ['application'])[0];
    const appTag = app?.openTag ?? xml;

    const hasBackupEnabled = attrValue(appTag, 'android:allowBackup') === 'true';
    const hasBackupFalse = attrValue(appTag, 'android:allowBackup') === 'false';
    // fullBackupContent (API <= 30) / dataExtractionRules (API 31+) let the app exclude data from backups
    const hasBackupRules =
      attrValue(appTag, 'android:fullBackupContent') !== undefined &&
      attrValue(appTag, 'android:fullBackupContent') !== 'false'
      || attrValue(appTag, 'android:dataExtractionRules') !== undefined;

    const sensitiveIndicators = [
      'permission.CAMERA',
      'permission.ACCESS_FINE_LOCATION',
      'permission.READ_CONTACTS',
      'permission.RECORD_AUDIO',
      'SecureStore',
      'biometric',
    ];

    const hasSensitiveContent = sensitiveIndicators.some(indicator => 
      xml.includes(indicator)
    );

    const appLine = app ? getLineNumber(xml, app.index) : undefined;
    const backupLine = lineOf(xml, /android:allowBackup\s*=/) ?? appLine;

    if (hasBackupEnabled && hasSensitiveContent && hasBackupRules) {
      findings.push({
        ruleId: 'ANDROID_BACKUP_ALLOWED',
        description: 'android:allowBackup="true" with fullBackupContent/dataExtractionRules - verify the rules exclude sensitive data',
        severity: Severity.LOW,
        confidence: 'medium',
        filePath: context.filePath,
        line: backupLine,
        suggestion: 'Check that the backup rules exclude tokens, databases and shared preferences holding sensitive data, or set android:allowBackup="false".',
      });
    } else if (hasBackupEnabled && hasSensitiveContent) {
      findings.push({
        ruleId: 'ANDROID_BACKUP_ALLOWED',
        description: 'Backup enabled for app with sensitive data - data can be extracted via ADB',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line: backupLine,
        suggestion: 'Set android:allowBackup="false" or implement android:fullBackupContent rules to exclude sensitive data.',
      });
    } else if (!hasBackupFalse && !hasBackupEnabled && hasSensitiveContent) {
      findings.push({
        ruleId: 'ANDROID_BACKUP_ALLOWED',
        description: 'Backup setting not specified for sensitive app (defaults to true)',
        severity: Severity.LOW,
        ...(hasBackupRules ? { confidence: 'medium' as const } : {}),
        filePath: context.filePath,
        line: appLine,
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

    const xml = stripXmlComments(context.xmlContent);

    for (const el of extractElements(xml, ['activity-alias', 'activity', 'service', 'receiver', 'provider'])) {
      if (attrValue(el.openTag, 'android:exported') !== 'true') continue;
      // The launcher activity has to be exported
      if (el.tag.startsWith('activity') && isLauncherComponent(el.text)) continue;
      if (attrValue(el.openTag, 'android:permission') !== undefined) continue;

      findings.push({
        ruleId: 'ANDROID_EXPORTED_COMPONENT',
        description: `Exported ${el.tag} without permission protection - accessible by any app`,
        severity: Severity.HIGH,
        filePath: context.filePath,
        line: getLineNumber(xml, el.index),
        suggestion: `Add android:permission attribute to exported ${el.tag} or set android:exported="false" if external access is not needed.`,
      });
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
              line: getLineNumber(context.xmlContent, match.index ?? 0),
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

    const xml = stripXmlComments(context.xmlContent);

    for (const receiver of extractElements(xml, ['receiver'])) {
      const hasPermission = attrValue(receiver.openTag, 'android:permission') !== undefined;
      const exportedAttr = attrValue(receiver.openTag, 'android:exported');
      // An explicit exported="false" wins over the presence of an intent-filter
      const isExported = exportedAttr === 'true' ||
                        (exportedAttr === undefined && receiver.text.includes('<intent-filter'));

      if (isExported && !hasPermission) {
        findings.push({
          ruleId: 'ANDROID_UNPROTECTED_RECEIVER',
          description: 'Broadcast receiver is exported without permission - can be triggered by malicious apps',
          severity: Severity.HIGH,
          filePath: context.filePath,
          line: getLineNumber(xml, receiver.index),
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
          line: getLineNumber(context.xmlContent, match.index ?? 0),
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

    const xml = stripXmlComments(context.xmlContent);

    // Common permission keywords to search for in code (matched as whole `_`-separated words)
    const permissionChecks = [
      'CAMERA', 'LOCATION', 'CONTACTS', 'MICROPHONE', 'STORAGE',
      'READ_PHONE_STATE', 'CALL_PHONE', 'SMS', 'BLUETOOTH'
    ];

    const unusedPermissions: string[] = [];
    let firstLine: number | undefined;

    for (const el of extractElements(xml, ['uses-permission', 'uses-permission-sdk-23'])) {
      const permissionName = attrValue(el.openTag, 'android:name');
      if (!permissionName) continue;
      // `tools:node="remove"` strips a permission that a library would otherwise merge in
      if (attrValue(el.openTag, 'tools:node') === 'remove') continue;

      const permissionShortName = permissionName.split('.').pop() || permissionName;
      const padded = `_${permissionShortName}_`;
      const isCommonlyExcessive = permissionChecks.some(check => padded.includes(`_${check}_`));

      if (isCommonlyExcessive) {
        unusedPermissions.push(permissionName);
        firstLine ??= getLineNumber(xml, el.index);
      }
    }

    if (unusedPermissions.length > 0) {
      findings.push({
        ruleId: 'EXCESSIVE_PERMISSIONS',
        description: `Potentially excessive permissions declared: ${unusedPermissions.slice(0, 3).join(', ')}${unusedPermissions.length > 3 ? '...' : ''}`,
        severity: Severity.LOW,
        confidence: 'low',
        filePath: context.filePath,
        line: firstLine,
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

    // Check for activities with custom taskAffinity (commented-out activities are ignored)
    const xml = stripXmlComments(context.xmlContent);

    for (const activity of extractElements(xml, ['activity'])) {
      const affinity = attrValue(activity.openTag, 'android:taskAffinity');

      // Empty taskAffinity is actually secure (prevents hijacking)
      if (affinity === undefined || affinity === '') continue;

      const line = getLineNumber(xml, activity.index);
      findings.push({
        ruleId: 'ANDROID_TASK_AFFINITY_VULNERABILITY',
        description: `Activity with custom taskAffinity="${affinity}" - vulnerable to StrandHogg task hijacking`,
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.xmlContent, line),
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

    const xml = stripXmlComments(context.xmlContent);
    const hasNetworkSecurityConfig = xml.includes('android:networkSecurityConfig');

    // Only flag if the app uses internet permission (is a networked app)
    const hasInternetPermission = xml.includes('android.permission.INTERNET');

    if (hasInternetPermission && !hasNetworkSecurityConfig) {
      const app = extractElements(xml, ['application'])[0];
      const line = app ? getLineNumber(xml, app.index) : undefined;
      findings.push({
        ruleId: 'ANDROID_MISSING_NETWORK_SECURITY_CONFIG',
        description: 'Network-enabled app without network_security_config.xml - missing certificate pinning and cleartext traffic control',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line,
        snippet: line !== undefined ? extractSnippet(context.xmlContent, line) : undefined,
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
