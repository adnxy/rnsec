import { Severity, type Finding } from '../types/findings.js';
import { RuleCategory } from '../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';

const iosUsageDescriptionsMissingRule: Rule = {
  id: 'IOS_USAGE_DESCRIPTIONS_MISSING',
  description: 'Missing iOS usage description - Apple App Store requirement',
  severity: Severity.LOW,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent || !context.filePath.includes('Info.plist')) {
      return findings;
    }

    const requiredDescriptions = [
      { key: 'NSCameraUsageDescription', feature: 'Camera', severity: Severity.LOW },
      { key: 'NSPhotoLibraryUsageDescription', feature: 'Photo Library', severity: Severity.LOW },
      { key: 'NSPhotoLibraryAddUsageDescription', feature: 'Photo Library (Add)', severity: Severity.LOW },
      { key: 'NSMicrophoneUsageDescription', feature: 'Microphone', severity: Severity.LOW },
      { key: 'NSLocationWhenInUseUsageDescription', feature: 'Location (When In Use)', severity: Severity.LOW },
      { key: 'NSLocationAlwaysUsageDescription', feature: 'Location (Always)', severity: Severity.LOW },
      { key: 'NSLocationAlwaysAndWhenInUseUsageDescription', feature: 'Location (Always and When In Use)', severity: Severity.LOW },
      { key: 'NSContactsUsageDescription', feature: 'Contacts', severity: Severity.LOW },
      { key: 'NSCalendarsUsageDescription', feature: 'Calendars', severity: Severity.LOW },
      { key: 'NSRemindersUsageDescription', feature: 'Reminders', severity: Severity.LOW },
      { key: 'NSMotionUsageDescription', feature: 'Motion & Fitness', severity: Severity.LOW },
      { key: 'NSHealthShareUsageDescription', feature: 'Health (Read)', severity: Severity.LOW },
      { key: 'NSHealthUpdateUsageDescription', feature: 'Health (Write)', severity: Severity.LOW },
      { key: 'NSBluetoothAlwaysUsageDescription', feature: 'Bluetooth', severity: Severity.LOW },
      { key: 'NSBluetoothPeripheralUsageDescription', feature: 'Bluetooth Peripheral', severity: Severity.LOW },
      { key: 'NSFaceIDUsageDescription', feature: 'Face ID', severity: Severity.LOW },
      { key: 'NSSpeechRecognitionUsageDescription', feature: 'Speech Recognition', severity: Severity.LOW },
      { key: 'NSAppleMusicUsageDescription', feature: 'Apple Music', severity: Severity.LOW },
    ];

    const frameworkPatterns = [
      { pattern: /<key>UIBackgroundModes<\/key>/i, descriptions: ['NSLocationAlwaysUsageDescription'] },
      { pattern: /AVFoundation/i, descriptions: ['NSCameraUsageDescription', 'NSMicrophoneUsageDescription'] },
      { pattern: /CoreLocation/i, descriptions: ['NSLocationWhenInUseUsageDescription'] },
      { pattern: /Photos/i, descriptions: ['NSPhotoLibraryUsageDescription'] },
      { pattern: /Contacts/i, descriptions: ['NSContactsUsageDescription'] },
    ];

    for (const { key, feature, severity } of requiredDescriptions) {
      const hasKey = context.plistContent.includes(`<key>${key}</key>`);

      if (!hasKey) {
        const frameworkNeeded = frameworkPatterns.find(fp => 
          fp.descriptions.includes(key) && context.plistContent && fp.pattern.test(context.plistContent)
        );

        if (frameworkNeeded) {
          findings.push({
            ruleId: 'IOS_USAGE_DESCRIPTIONS_MISSING',
            description: `Missing ${feature} usage description - Apple App Store requirement`,
            severity,
            filePath: context.filePath,
            suggestion: `Add ${key} to Info.plist with a clear explanation of why ${feature} access is needed. This is required for App Store submission.`,
          });
        }
      } else {
        const descriptionPattern = new RegExp(`<key>${key}</key>\\s*<string>(.*?)</string>`, 'i');
        const match = context.plistContent.match(descriptionPattern);
        
        if (match && match[1] && typeof match[1] === 'string') {
          const description = match[1].trim();
          
          if (description.length < 10 ||
              description.toLowerCase().includes('placeholder') ||
              description.toLowerCase().includes('todo')) {
            findings.push({
              ruleId: 'IOS_USAGE_DESCRIPTIONS_MISSING',
              description: `${feature} usage description is too generic or placeholder: "${description}"`,
              severity: Severity.LOW,
              filePath: context.filePath,
              suggestion: `Provide a meaningful explanation for ${feature} access that users will understand.`,
            });
          }
        }
      }
    }

    return findings;
  },
};

const iosBackgroundModesUnnecessaryRule: Rule = {
  id: 'IOS_BACKGROUND_MODES_UNNECESSARY',
  description: 'Potentially unnecessary background modes enabled',
  severity: Severity.MEDIUM,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent || !context.filePath.includes('Info.plist')) {
      return findings;
    }

    const backgroundModesPattern = /<key>UIBackgroundModes<\/key>\s*<array>([\s\S]*?)<\/array>/i;
    const match = context.plistContent.match(backgroundModesPattern);

    if (match) {
      const modesContent = match[1];
      
      const sensitiveBackgroundModes = [
        { mode: 'location', concern: 'Continuous location tracking drains battery and raises privacy concerns' },
        { mode: 'fetch', concern: 'Background fetch may expose data during background updates' },
        { mode: 'remote-notification', concern: 'Remote notifications can trigger background activity' },
        { mode: 'voip', concern: 'VoIP mode allows persistent connection and background execution' },
        { mode: 'audio', concern: 'Audio mode keeps app active in background' },
      ];

      for (const { mode, concern } of sensitiveBackgroundModes) {
        if (modesContent.includes(mode)) {
          findings.push({
            ruleId: 'IOS_BACKGROUND_MODES_UNNECESSARY',
            description: `Background mode '${mode}' enabled: ${concern}`,
            severity: Severity.LOW,
            filePath: context.filePath,
            suggestion: `Ensure '${mode}' background mode is necessary. Remove if not required to reduce attack surface and improve privacy.`,
          });
        }
      }
    }

    return findings;
  },
};

const iosUniversalLinksMisconfiguredRule: Rule = {
  id: 'IOS_UNIVERSAL_LINKS_MISCONFIGURED',
  description: 'Universal links configured without proper validation',
  severity: Severity.MEDIUM,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent || !context.filePath.includes('Info.plist')) {
      return findings;
    }

    const hasUniversalLinks = context.plistContent.includes('com.apple.developer.associated-domains');

    if (hasUniversalLinks) {
      const domainPattern = /<string>applinks:(.*?)<\/string>/gi;
      const matches = context.plistContent.matchAll(domainPattern);

      for (const match of matches) {
        const domain = match[1];

        if (domain.includes('*') || domain.includes('?')) {
          findings.push({
            ruleId: 'IOS_UNIVERSAL_LINKS_MISCONFIGURED',
            description: `Universal link domain uses wildcard: ${domain} - too permissive`,
            severity: Severity.MEDIUM,
            filePath: context.filePath,
            suggestion: 'Specify exact domains for universal links. Avoid wildcards that could allow unintended domains.',
          });
        }

        if (!domain.includes('.')) {
          findings.push({
            ruleId: 'IOS_UNIVERSAL_LINKS_MISCONFIGURED',
            description: `Universal link domain looks invalid: ${domain}`,
            severity: Severity.LOW,
            filePath: context.filePath,
            suggestion: 'Verify universal link domain is correctly configured with a valid domain name.',
          });
        }
      }
    }

    return findings;
  },
};

const iosCustomUrlSchemeUnprotectedRule: Rule = {
  id: 'IOS_CUSTOM_URL_SCHEME_UNPROTECTED',
  description: 'Custom URL scheme without validation code',
  severity: Severity.MEDIUM,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent || !context.filePath.includes('Info.plist')) {
      return findings;
    }

    const urlTypesPattern = /<key>CFBundleURLTypes<\/key>\s*<array>([\s\S]*?)<\/array>/i;
    const match = context.plistContent.match(urlTypesPattern);

    if (match) {
      const urlTypesContent = match[1];
      const schemePattern = /<key>CFBundleURLSchemes<\/key>\s*<array>([\s\S]*?)<\/array>/gi;
      const schemeMatches = urlTypesContent.matchAll(schemePattern);

      for (const schemeMatch of schemeMatches) {
        findings.push({
          ruleId: 'IOS_CUSTOM_URL_SCHEME_UNPROTECTED',
          description: 'Custom URL scheme detected - ensure deep link validation is implemented',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          suggestion: 'Implement URL validation in application:openURL:options: to prevent deep link exploits. Validate scheme, host, and parameters.',
        });
      }
    }

    return findings;
  },
};

const iosKeychainAccessGroupInsecureRule: Rule = {
  id: 'IOS_KEYCHAIN_ACCESS_GROUP_INSECURE',
  description: 'Keychain access group configuration may expose data',
  severity: Severity.MEDIUM,
  fileTypes: ['.plist', '.entitlements'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent) {
      return findings;
    }

    const keychainPattern = /<key>keychain-access-groups<\/key>\s*<array>([\s\S]*?)<\/array>/i;
    const match = context.plistContent.match(keychainPattern);

    if (match) {
      const groupsContent = match[1];

      if (groupsContent.includes('*')) {
        findings.push({
          ruleId: 'IOS_KEYCHAIN_ACCESS_GROUP_INSECURE',
          description: 'Keychain access group uses wildcard - may allow unintended access',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          suggestion: 'Specify exact keychain access groups instead of using wildcards to prevent data leakage between apps.',
        });
      }
    }

    return findings;
  },
};

const iosDataProtectionMissingRule: Rule = {
  id: 'IOS_DATA_PROTECTION_MISSING',
  description: 'Data protection entitlement not configured for sensitive app',
  severity: Severity.LOW,
  fileTypes: ['.plist', '.entitlements'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent) {
      return findings;
    }

    const hasDataProtection = context.plistContent.includes('NSFileProtectionComplete') ||
                              context.plistContent.includes('com.apple.developer.default-data-protection');

    const sensitiveIndicators = [
      'NSCameraUsageDescription',
      'NSLocationAlwaysUsageDescription',
      'NSHealthShareUsageDescription',
      'NSFaceIDUsageDescription',
    ];

    const hasSensitiveFeatures = sensitiveIndicators.some(indicator => 
      context.plistContent?.includes(indicator)
    );

    if (hasSensitiveFeatures && !hasDataProtection) {
      findings.push({
        ruleId: 'IOS_DATA_PROTECTION_MISSING',
        description: 'Sensitive app without data protection entitlement',
        severity: Severity.LOW,
        filePath: context.filePath,
        suggestion: 'Enable data protection (NSFileProtectionComplete) to encrypt files when device is locked.',
      });
    }

    return findings;
  },
};

const iosAtsExceptionTooPermissiveRule: Rule = {
  id: 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE',
  description: 'App Transport Security exception too permissive',
  severity: Severity.HIGH,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent || !context.filePath.includes('Info.plist')) {
      return findings;
    }

    const exceptionDomainsPattern = /<key>NSExceptionDomains<\/key>\s*<dict>([\s\S]*?)<\/dict>/i;
    const match = context.plistContent.match(exceptionDomainsPattern);

    if (match && match[1]) {
      const domainsContent = match[1];
      const domainPattern = /<key>(.*?)<\/key>/gi;
      const domainMatches = domainsContent.matchAll(domainPattern);

      for (const domainMatch of domainMatches) {
        const domain = domainMatch[1];
        const domainConfigPattern = new RegExp(`<key>${domain}</key>\\s*<dict>([\\s\\S]*?)<\\/dict>`, 'i');
        const domainConfig = domainsContent.match(domainConfigPattern);

        if (domainConfig) {
          const config = domainConfig[1];

          if (config.includes('NSIncludesSubdomains') && config.includes('<true/>')) {
            findings.push({
              ruleId: 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE',
              description: `ATS exception for ${domain} includes all subdomains - too broad`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              suggestion: `Limit ATS exceptions to specific subdomains instead of using NSIncludesSubdomains for ${domain}.`,
            });
          }

          if (config.includes('NSAllowsArbitraryLoadsInWebContent')) {
            findings.push({
              ruleId: 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE',
              description: `NSAllowsArbitraryLoadsInWebContent enabled for ${domain} - allows insecure web content`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              suggestion: 'Avoid NSAllowsArbitraryLoadsInWebContent. Use HTTPS for all web content or specify exact exceptions.',
            });
          }
        }
      }
    }

    return findings;
  },
};

const insecureKeychainUsageRule: Rule = {
  id: 'INSECURE_KEYCHAIN_USAGE',
  description: 'iOS Keychain used without proper accessibility and protection',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.m', '.swift'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    const content = context.fileContent;

    // Check for insecure accessibility attribute
    if (content.includes('kSecAttrAccessibleAlways')) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('kSecAttrAccessibleAlways')) {
          findings.push({
            ruleId: 'INSECURE_KEYCHAIN_USAGE',
            description: 'Keychain item uses kSecAttrAccessibleAlways - accessible even when device is locked',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line: i + 1,
            snippet: lines[i].trim(),
            suggestion: 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or kSecAttrAccessibleAfterFirstUnlock for better security.',
          });
        }
      }
    }

    // Check for missing access control
    const hasKeychainUsage = content.includes('\bSecItemAdd\b') || 
                             content.includes('\bSecItemUpdate\b') ||
                             content.includes('\bsetGenericPassword\b') ||
                             content.includes('\bKeychain\.set\b');
    
    if (hasKeychainUsage) {
      const hasAccessControl = content.includes('kSecAttrAccessControl') ||
                               content.includes('SecAccessControlCreate') ||
                               content.includes('accessControl:') ||
                               content.includes('withAccessControl');
      
      const hasBiometricProtection = content.includes('biometryAny') ||
                                     content.includes('biometryCurrentSet') ||
                                     content.includes('userPresence') ||
                                     content.includes('devicePasscode');

      // Check if it's a sensitive context
      const isSensitiveContext = content.toLowerCase().includes('password') ||
                                 content.toLowerCase().includes('token') ||
                                 content.toLowerCase().includes('secret') ||
                                 content.toLowerCase().includes('key') ||
                                 content.toLowerCase().includes('credential');

      if (isSensitiveContext && !hasAccessControl) {
        findings.push({
          ruleId: 'INSECURE_KEYCHAIN_USAGE',
          description: 'Keychain storing sensitive data without access control flags',
          severity: Severity.HIGH,
          filePath: context.filePath,
          line: 1,
          suggestion: 'Add kSecAttrAccessControl with biometric or device passcode requirement for sensitive keychain items.',
        });
      }

      if (isSensitiveContext && !hasBiometricProtection && !content.includes('WhenUnlocked')) {
        findings.push({
          ruleId: 'INSECURE_KEYCHAIN_USAGE',
          description: 'Keychain item for sensitive data without biometric or passcode protection',
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: 1,
          suggestion: 'Require biometric authentication or device passcode for accessing sensitive keychain items.',
        });
      }
    }

    return findings;
  },
};

export const iosRules: RuleGroup = {
  category: RuleCategory.MANIFEST,
  rules: [
    iosUsageDescriptionsMissingRule,
    iosBackgroundModesUnnecessaryRule,
    iosUniversalLinksMisconfiguredRule,
    iosCustomUrlSchemeUnprotectedRule,
    iosKeychainAccessGroupInsecureRule,
    iosDataProtectionMissingRule,
    iosAtsExceptionTooPermissiveRule,
    insecureKeychainUsageRule,
  ],
};
