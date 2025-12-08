import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { RuleCategory } from '../types/ruleTypes.js';

const androidCleartextEnabledRule: Rule = {
  id: 'ANDROID_CLEARTEXT_ENABLED',
  description: 'Android cleartext traffic is enabled',
  severity: Severity.HIGH,
  fileTypes: ['.xml'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.xmlContent || !context.filePath.includes('AndroidManifest')) {
      return findings;
    }

    if (context.xmlContent.includes('android:usesCleartextTraffic="true"')) {
      findings.push({
        ruleId: 'ANDROID_CLEARTEXT_ENABLED',
        description: 'android:usesCleartextTraffic is set to true',
        severity: Severity.HIGH,
        filePath: context.filePath,
        suggestion: 'Disable cleartext traffic or use network security config to restrict it to specific domains',
      });
    }

    return findings;
  },
};

const iosAtsDisabledRule: Rule = {
  id: 'IOS_ATS_DISABLED',
  description: 'iOS App Transport Security (ATS) is disabled',
  severity: Severity.HIGH,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent || !context.filePath.includes('Info.plist')) {
      return findings;
    }

    const atsPattern = /<key>NSAppTransportSecurity<\/key>\s*<dict>[\s\S]*?<key>NSAllowsArbitraryLoads<\/key>\s*<true\/>/;
    
    if (atsPattern.test(context.plistContent)) {
      findings.push({
        ruleId: 'IOS_ATS_DISABLED',
        description: 'NSAllowsArbitraryLoads is enabled, disabling ATS',
        severity: Severity.HIGH,
        filePath: context.filePath,
        suggestion: 'Enable ATS and use exception domains only for specific servers that require it',
      });
    }

    return findings;
  },
};

export const manifestRules: RuleGroup = {
  category: RuleCategory.MANIFEST,
  rules: [androidCleartextEnabledRule, iosAtsDisabledRule],
};
