import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { getLineNumber } from '../../utils/stringUtils.js';
import { parsePlist, plistTrue } from '../ios/iosScanner.js';

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

    const attr = 'android:usesCleartextTraffic="true"';
    const index = context.xmlContent.indexOf(attr);
    if (index !== -1) {
      findings.push({
        ruleId: 'ANDROID_CLEARTEXT_ENABLED',
        description: 'android:usesCleartextTraffic is set to true',
        severity: Severity.HIGH,
        filePath: context.filePath,
        line: getLineNumber(context.xmlContent, index),
        suggestion: 'Disable cleartext traffic or use network security config to restrict it to specific domains',
      });
    }

    return findings;
  },
};

/**
 * Keys that make iOS 10+ ignore NSAllowsArbitraryLoads (and use its default, NO) when present with any value.
 * https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads
 */
const ATS_KEYS_OVERRIDING_ARBITRARY_LOADS = [
  'NSAllowsArbitraryLoadsInWebContent',
  'NSAllowsArbitraryLoadsForMedia',
  'NSAllowsLocalNetworking',
];

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

    const ats = parsePlist(context.plistContent)?.get('NSAppTransportSecurity')?.value.dict;
    const arbitraryLoads = ats?.get('NSAllowsArbitraryLoads');
    if (!ats || !arbitraryLoads || !plistTrue(arbitraryLoads)) {
      return findings;
    }

    const line = getLineNumber(context.plistContent, arbitraryLoads.index);
    const overriding = ATS_KEYS_OVERRIDING_ARBITRARY_LOADS.filter(key => ats.has(key));

    if (overriding.length > 0) {
      // iOS 10+ ignores NSAllowsArbitraryLoads here; it only still applies to iOS 9
      findings.push({
        ruleId: 'IOS_ATS_DISABLED',
        description: `NSAllowsArbitraryLoads is true but ignored on iOS 10+ because ${overriding.join(', ')} is present (still applies to iOS 9)`,
        severity: Severity.LOW,
        confidence: 'medium',
        filePath: context.filePath,
        line,
        suggestion: 'Remove NSAllowsArbitraryLoads unless you still ship to iOS 9; the narrower keys already cover the intended exception.',
      });
      return findings;
    }

    findings.push({
      ruleId: 'IOS_ATS_DISABLED',
      description: 'NSAllowsArbitraryLoads is enabled, disabling ATS',
      severity: Severity.HIGH,
      filePath: context.filePath,
      line,
      suggestion: 'Enable ATS and use exception domains only for specific servers that require it',
    });

    return findings;
  },
};

export const manifestRules: RuleGroup = {
  category: RuleCategory.MANIFEST,
  rules: [androidCleartextEnabledRule, iosAtsDisabledRule],
};
