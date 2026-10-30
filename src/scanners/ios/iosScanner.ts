import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { ProjectInfo, Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import _traverse from '@babel/traverse';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { toRelativePath } from '../../utils/pathFilters.js';
import { finalizeAbsence, ignoresAtAnchor, isAppSource, lowerCased, type Evidence } from '../../utils/projectEvidence.js';

const traverse = (_traverse as any).default || _traverse;

/** Parsed plist value. Only what the rules below need: booleans, strings, dicts and arrays */
export interface PlistValue {
  kind: 'true' | 'false' | 'string' | 'number' | 'other' | 'dict' | 'array';
  text?: string;
  dict?: Map<string, PlistEntry>;
  items?: PlistValue[];
}

export interface PlistEntry {
  value: PlistValue;
  /** Offset of the `<key>` element in the original text (for line numbers) */
  index: number;
}

/** Blank out XML comments, keeping offsets */
function blankComments(xml: string): string {
  return xml.replace(/<!--[\s\S]*?-->/g, m => m.replace(/[^\n]/g, ' '));
}

/**
 * Depth-aware plist reader. Regexes over plist text cannot tell which `</dict>` closes which
 * dictionary, so nested structures such as NSExceptionDomains need a real walk.
 * Returns the top-level dictionary, or null when the text is not a readable plist.
 */
export function parsePlist(xmlText: string): Map<string, PlistEntry> | null {
  const xml = blankComments(xmlText);
  const tagRe = /<(\/?)([A-Za-z]+)\s*(\/?)>/g;
  const tokens: Array<{ name: string; closing: boolean; selfClose: boolean; start: number; end: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(xml)) !== null) {
    if (m[2] === 'plist') continue;
    tokens.push({ name: m[2], closing: m[1] === '/', selfClose: m[3] === '/', start: m.index, end: m.index + m[0].length });
  }

  let pos = 0;
  const textBetween = (from: number, to: number) => xml.slice(from, to).trim();

  const parseValue = (): PlistValue | null => {
    const t = tokens[pos];
    if (!t || t.closing) return null;
    pos++;
    switch (t.name) {
      case 'true':
        return { kind: 'true' };
      case 'false':
        return { kind: 'false' };
      case 'string':
      case 'integer':
      case 'real':
      case 'date':
      case 'data': {
        if (t.selfClose) return { kind: t.name === 'string' ? 'string' : 'other', text: '' };
        const close = tokens[pos];
        if (!close || !close.closing || close.name !== t.name) return null;
        pos++;
        const text = textBetween(t.end, close.start);
        return { kind: t.name === 'string' ? 'string' : t.name === 'integer' || t.name === 'real' ? 'number' : 'other', text };
      }
      case 'dict': {
        const dict = new Map<string, PlistEntry>();
        if (t.selfClose) return { kind: 'dict', dict };
        while (tokens[pos] && !(tokens[pos].closing && tokens[pos].name === 'dict')) {
          const keyTok = tokens[pos];
          if (keyTok.name !== 'key' || keyTok.closing) return null;
          pos++;
          const keyClose = tokens[pos];
          if (!keyClose || !keyClose.closing || keyClose.name !== 'key') return null;
          pos++;
          const key = textBetween(keyTok.end, keyClose.start);
          const value = parseValue();
          if (!value) return null;
          dict.set(key, { value, index: keyTok.start });
        }
        pos++; // </dict>
        return { kind: 'dict', dict };
      }
      case 'array': {
        const items: PlistValue[] = [];
        if (t.selfClose) return { kind: 'array', items };
        while (tokens[pos] && !(tokens[pos].closing && tokens[pos].name === 'array')) {
          const v = parseValue();
          if (!v) return null;
          items.push(v);
        }
        pos++; // </array>
        return { kind: 'array', items };
      }
      default:
        return null;
    }
  };

  const root = parseValue();
  return root?.kind === 'dict' && root.dict ? root.dict : null;
}

export const plistTrue = (entry: PlistEntry | undefined): boolean => entry?.value.kind === 'true';

/** Hosts for which an ATS exception is a normal development/local-network setup */
export function isLocalOrPrivateHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === 'localhost' || h === '::1' || h === '10.0.2.2' || h === '10.0.3.2') return true;
  if (h.endsWith('.local') || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.lan')) return true;
  const ip = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ip) return false;
  const [a, b] = [Number(ip[1]), Number(ip[2])];
  return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
}


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

    // Framework names are looked for in keys only; `<string>` values ("Upload photos") are free text
    const keysOnly = context.plistContent.replace(/<string>[\s\S]*?<\/string>/g, '<string/>');
    // UIBackgroundModes is also used for push/fetch; only the `location` mode needs an Always description
    const backgroundLocation = /<key>UIBackgroundModes<\/key>\s*<array>(?:(?!<\/array>)[\s\S])*<string>location<\/string>/i;
    const frameworkPatterns = [
      { pattern: backgroundLocation, descriptions: ['NSLocationAlwaysUsageDescription'] },
      { pattern: /AVFoundation/i, descriptions: ['NSCameraUsageDescription', 'NSMicrophoneUsageDescription'] },
      { pattern: /CoreLocation/i, descriptions: ['NSLocationWhenInUseUsageDescription'] },
      { pattern: /Photos/i, descriptions: ['NSPhotoLibraryUsageDescription'] },
      { pattern: /Contacts/i, descriptions: ['NSContactsUsageDescription'] },
    ];

    for (const { key, feature, severity } of requiredDescriptions) {
      const hasKey = context.plistContent.includes(`<key>${key}</key>`);

      if (!hasKey) {
        const frameworkNeeded = frameworkPatterns.find(fp => 
          fp.descriptions.includes(key) && context.plistContent && fp.pattern.test(fp.pattern === backgroundLocation ? context.plistContent : keysOnly)
        );

        if (frameworkNeeded) {
          findings.push({
            ruleId: 'IOS_USAGE_DESCRIPTIONS_MISSING',
            confidence: 'medium',
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
              /\bplaceholder\b/i.test(description) ||
              /\btodo\b/i.test(description)) {
            findings.push({
              ruleId: 'IOS_USAGE_DESCRIPTIONS_MISSING',
              confidence: 'medium',
              description: `${feature} usage description is too generic or placeholder: "${description}"`,
              severity: Severity.LOW,
              filePath: context.filePath,
              line: getLineNumber(context.plistContent, context.plistContent.indexOf(`<key>${key}</key>`)),
              suggestion: `Provide a meaningful explanation for ${feature} access that users will understand.`,
            });
          }
        }
      }
    }

    return findings;
  },
};

/**
 * Packages in the root package.json that need a given UIBackgroundModes entry to work. A mode backed by one of
 * these is in use, not "unnecessary". Only the root package.json is known, so a monorepo app whose
 * dependencies live in a workspace package keeps its findings.
 */
const BACKGROUND_MODE_PACKAGES: Record<string, RegExp> = {
  audio: /^(?:expo-av|expo-audio|react-native-track-player|react-native-sound|react-native-audio-recorder-player|react-native-audio-api|react-native-music-control|@react-native-community\/audio-toolkit)$/,
  voip: /^(?:react-native-callkeep|react-native-voip-push-notification|react-native-webrtc|@livekit\/react-native|@stream-io\/video-react-native-sdk|@daily-co\/react-native-daily-js|react-native-incall-manager|react-native-agora|@twilio\/voice-react-native-sdk|react-native-twilio-video-webrtc)$/,
  location: /^(?:expo-location|react-native-geolocation-service|@react-native-community\/geolocation|react-native-background-geolocation|@transistorsoft\/react-native-background-geolocation|react-native-background-geolocation-android|react-native-location)$/,
  fetch: /^(?:react-native-background-fetch|expo-background-fetch|expo-background-task|expo-task-manager)$/,
  'remote-notification': /^(?:expo-notifications|@react-native-firebase\/messaging|react-native-push-notification|@react-native-community\/push-notification-ios|react-native-notifications|react-native-onesignal|@notifee\/react-native|@braze\/react-native-sdk|react-native-fcm|react-native-push-notification-ios)$/,
};

function isBackedByDependency(mode: string, project: ProjectInfo | undefined): boolean {
  const pattern = BACKGROUND_MODE_PACKAGES[mode];
  return !!pattern && !!project && [...project.dependencies].some(name => pattern.test(name));
}

const iosBackgroundModesUnnecessaryRule: Rule = {
  id: 'IOS_BACKGROUND_MODES_UNNECESSARY',
  description: 'Potentially unnecessary background modes enabled',
  severity: Severity.LOW,
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
          if (isBackedByDependency(mode, context.project)) continue;
          findings.push({
            ruleId: 'IOS_BACKGROUND_MODES_UNNECESSARY',
            confidence: 'low',
            description: `Background mode '${mode}' enabled: ${concern}`,
            severity: Severity.LOW,
            filePath: context.filePath,
            line: getLineNumber(context.plistContent, match.index ?? 0),
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
  fileTypes: ['.plist', '.entitlements'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    const content = context.plistContent;
    const isEntitlements = context.filePath.endsWith('.entitlements');

    if (!content || (!isEntitlements && !context.filePath.includes('Info.plist'))) {
      return findings;
    }

    const entry = parsePlist(content)?.get('com.apple.developer.associated-domains');
    if (!entry || entry.value.kind !== 'array') {
      return findings;
    }
    const line = getLineNumber(content, entry.index);

    for (const item of entry.value.items ?? []) {
      const applink = /^applinks:(.*)$/i.exec(item.text ?? '');
      if (!applink) continue;
      // ?mode=developer / ?mode=managed is Apple's alternate-mode suffix, not part of the host
      const domain = applink[1].replace(/\?mode=.*$/i, '').trim();

      if (domain.includes('*') || domain.includes('?')) {
        findings.push({
          ruleId: 'IOS_UNIVERSAL_LINKS_MISCONFIGURED',
          description: `Universal link domain uses wildcard: ${domain} - too permissive`,
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line,
          suggestion: 'Specify exact domains for universal links. Avoid wildcards that could allow unintended domains.',
        });
      }

      if (!domain.includes('.')) {
        findings.push({
          ruleId: 'IOS_UNIVERSAL_LINKS_MISCONFIGURED',
          description: `Universal link domain looks invalid: ${domain}`,
          severity: Severity.LOW,
          filePath: context.filePath,
          line,
          suggestion: 'Verify universal link domain is correctly configured with a valid domain name.',
        });
      }
    }

    return findings;
  },
};

const iosCustomUrlSchemeUnprotectedRule: Rule = {
  id: 'IOS_CUSTOM_URL_SCHEME_UNPROTECTED',
  description: 'Custom URL scheme without validation code',
  severity: Severity.LOW,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent || !context.filePath.includes('Info.plist')) {
      return findings;
    }

    // CFBundleURLTypes is an array of dicts; each dict's CFBundleURLSchemes is an array of strings
    const urlTypes = parsePlist(context.plistContent)?.get('CFBundleURLTypes');
    const schemes: string[] = [];
    for (const type of urlTypes?.value.items ?? []) {
      for (const scheme of type.dict?.get('CFBundleURLSchemes')?.value.items ?? []) {
        if (scheme.text) schemes.push(scheme.text);
      }
    }

    if (urlTypes && schemes.length > 0) {
      findings.push({
        ruleId: 'IOS_CUSTOM_URL_SCHEME_UNPROTECTED',
        description: `Custom URL scheme detected (${schemes.join(', ')}) - ensure deep link validation is implemented`,
        severity: Severity.LOW,
        // Whether the handler validates URLs cannot be seen from the plist
        confidence: 'low',
        filePath: context.filePath,
        line: getLineNumber(context.plistContent, urlTypes.index),
        suggestion: 'Implement URL validation in application:openURL:options: to prevent deep link exploits. Validate scheme, host, and parameters.',
      });
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
  description: 'App explicitly uses NSFileProtectionNone - files are not encrypted at rest',
  severity: Severity.MEDIUM,
  fileTypes: ['.plist', '.entitlements'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.plistContent) {
      return findings;
    }

    // Only flag explicit use of NSFileProtectionNone which disables encryption.
    // iOS defaults to NSFileProtectionCompleteUntilFirstUserAuthentication since iOS 7,
    // which is secure for most apps. Apple recommends against using the global
    // com.apple.developer.default-data-protection entitlement as it can break
    // background processing. Sensitive data should use Keychain (covered by
    // INSECURE_KEYCHAIN_USAGE) rather than file-level protection entitlements.
    const hasInsecureProtection = context.plistContent.includes('NSFileProtectionNone');

    if (hasInsecureProtection) {
      findings.push({
        ruleId: 'IOS_DATA_PROTECTION_MISSING',
        description: 'App explicitly uses NSFileProtectionNone - files are not encrypted at rest',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        suggestion: 'Remove NSFileProtectionNone. iOS defaults to NSFileProtectionCompleteUntilFirstUserAuthentication which encrypts files at rest. ' +
          'For sensitive data, use Keychain (react-native-keychain/expo-secure-store) with appropriate accessControl. ' +
          'For sensitive files, set protection per-file using FileManager attributes.',
      });
    }

    return findings;
  },
};

/** TLS versions below 1.2 are the ones ATS exceptions should not pin */
const WEAK_TLS_VERSIONS = new Set(['TLSv1.0', 'TLSv1.1']);

const iosAtsExceptionTooPermissiveRule: Rule = {
  id: 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE',
  description: 'App Transport Security exception too permissive',
  severity: Severity.MEDIUM,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.plistContent || !context.filePath.includes('Info.plist')) {
      return findings;
    }

    const plist = parsePlist(context.plistContent);
    const ats = plist?.get('NSAppTransportSecurity')?.value.dict;
    if (!ats) {
      return findings;
    }
    const lineAt = (entry: PlistEntry) => getLineNumber(context.plistContent as string, entry.index);

    // Top-level keys. These are not valid inside an exception domain.
    const webContent = ats.get('NSAllowsArbitraryLoadsInWebContent');
    if (plistTrue(webContent)) {
      findings.push({
        ruleId: 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE',
        description: 'NSAllowsArbitraryLoadsInWebContent enabled - allows insecure web content',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line: lineAt(webContent!),
        suggestion: 'Avoid NSAllowsArbitraryLoadsInWebContent. Use HTTPS for all web content or specify exact exceptions.',
      });
    }
    const media = ats.get('NSAllowsArbitraryLoadsForMedia');
    if (plistTrue(media)) {
      findings.push({
        ruleId: 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE',
        description: 'NSAllowsArbitraryLoadsForMedia enabled - AV media may load over plain HTTP',
        severity: Severity.LOW,
        filePath: context.filePath,
        line: lineAt(media!),
        suggestion: 'Serve media over HTTPS or restrict the exception to the specific media domains.',
      });
    }

    // Per-domain exceptions. A domain entry only matters when it actually weakens ATS.
    const exceptionDomains = ats.get('NSExceptionDomains')?.value.dict;
    for (const [domain, entry] of exceptionDomains ?? []) {
      const config = entry.value.dict;
      if (!config || isLocalOrPrivateHost(domain)) continue;

      const insecureHttp = plistTrue(config.get('NSExceptionAllowsInsecureHTTPLoads')) ||
                           plistTrue(config.get('NSThirdPartyExceptionAllowsInsecureHTTPLoads'));
      const includesSubdomains = plistTrue(config.get('NSIncludesSubdomains'));
      const tls = config.get('NSExceptionMinimumTLSVersion')?.value.text ?? '';
      const noForwardSecrecy = config.get('NSExceptionRequiresForwardSecrecy')?.value.kind === 'false';

      if (insecureHttp && includesSubdomains) {
        findings.push({
          ruleId: 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE',
          description: `ATS exception for ${domain} allows insecure HTTP and includes all subdomains - too broad`,
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: lineAt(entry),
          suggestion: `Limit ATS exceptions to specific subdomains instead of using NSIncludesSubdomains for ${domain}.`,
        });
      }

      if (WEAK_TLS_VERSIONS.has(tls) || noForwardSecrecy) {
        findings.push({
          ruleId: 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE',
          description: `ATS exception for ${domain} weakens transport security (${WEAK_TLS_VERSIONS.has(tls) ? `minimum ${tls}` : 'forward secrecy not required'})`,
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: lineAt(entry),
          suggestion: 'Upgrade the server to TLS 1.2+ with forward secrecy and drop the exception.',
        });
      }
    }

    return findings;
  },
};

const KEYCHAIN_LIB = /^react-native-keychain$/;

/** Local names bound to the module namespace/default export, and to individual named exports. */
function bindingsFor(ast: any, lib: RegExp): { ns: Set<string>; named: Map<string, string> } {
  const ns = new Set<string>();
  const named = new Map<string, string>();
  for (const node of ast.program?.body ?? []) {
    if (node.type !== 'ImportDeclaration' || !lib.test(node.source.value)) continue;
    for (const spec of node.specifiers) {
      if (spec.type === 'ImportSpecifier') {
        const imported = spec.imported.type === 'Identifier' ? spec.imported.name : spec.imported.value;
        named.set(spec.local.name, imported);
      } else {
        ns.add(spec.local.name);
      }
    }
  }
  return { ns, named };
}

function memberName(node: any): string | null {
  if (!node || node.type !== 'MemberExpression') return null;
  if (!node.computed) return node.property.type === 'Identifier' ? node.property.name : null;
  return node.property.type === 'StringLiteral' ? node.property.value : null;
}

/** `Keychain.ACCESSIBLE.ALWAYS`, `ACCESSIBLE.ALWAYS` (named import), or the raw 'AccessibleAlways' value. */
function isKeychainAlways(value: any, b: ReturnType<typeof bindingsFor>): boolean {
  if (value.type === 'StringLiteral') return value.value === 'AccessibleAlways';
  if (memberName(value) !== 'ALWAYS') return false;
  const obj = value.object;
  if (obj.type === 'Identifier') return b.named.get(obj.name) === 'ACCESSIBLE';
  return memberName(obj) === 'ACCESSIBLE' && obj.object.type === 'Identifier' && b.ns.has(obj.object.name);
}

const insecureKeychainUsageRule: Rule = {
  id: 'INSECURE_KEYCHAIN_USAGE',
  description: 'Keychain item accessible even when the device is locked (ALWAYS accessibility)',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.m', '.swift'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    const content = context.fileContent;

    // Native sources: the deprecated kSecAttrAccessibleAlways[ThisDeviceOnly] attribute
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

    // JS/TS: react-native-keychain `accessible` option (expo-secure-store is EXPO_SECURE_STORE_WEAK_OPTIONS)
    if (context.ast && /react-native-keychain/.test(content)) {
      const keychain = bindingsFor(context.ast, KEYCHAIN_LIB);

      traverse(context.ast, {
        ObjectProperty(path: any) {
          const { node } = path;
          const key = node.key.type === 'Identifier' ? node.key.name : node.key.type === 'StringLiteral' ? node.key.value : null;
          if (key !== 'accessible' || !isKeychainAlways(node.value, keychain)) return;

          const line = getLineNumber(content, node.start || 0);
          findings.push({
            ruleId: 'INSECURE_KEYCHAIN_USAGE',
            description: `Keychain item uses react-native-keychain ACCESSIBLE.ALWAYS - readable even while the device is locked (deprecated, least secure option)`,
            severity: Severity.MEDIUM,
            confidence: 'high',
            filePath: context.filePath,
            line,
            snippet: extractSnippet(content, line),
            reason: 'ALWAYS makes the item readable regardless of device lock state, so secrets can be extracted from a locked device or an unencrypted backup.',
            suggestion: 'Use WHEN_UNLOCKED_THIS_DEVICE_ONLY (or AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY if background access is required).',
          });
        },
      });
    }

    return findings;
  },
};

const iosInsecurePasteboardUsageRule: Rule = {
  id: 'IOS_INSECURE_PASTEBOARD_USAGE',
  description: 'Sensitive data written to iOS pasteboard (shared across apps)',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.m', '.swift'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    const content = context.fileContent;

    // Check for UIPasteboard with sensitive data in native code
    if (content.includes('UIPasteboard') || content.includes('pasteboard')) {
      const surroundingLower = content.toLowerCase();
      const sensitivePatterns = ['password', 'token', 'secret', 'apikey', 'credential', 'ssn', 'creditcard', 'cardnumber'];
      const hasSensitiveContext = sensitivePatterns.some(p => surroundingLower.includes(p));

      if (hasSensitiveContext) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes('UIPasteboard') || lines[i].toLowerCase().includes('pasteboard')) {
            findings.push({
              ruleId: 'IOS_INSECURE_PASTEBOARD_USAGE',
              description: 'Sensitive data written to pasteboard - accessible by all apps on device',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line: i + 1,
              snippet: lines[i].trim(),
              suggestion: 'Set UIPasteboard.general.setItems with expiration date. On iOS 14+ other apps cannot read pasteboard without user notification, but data persists across app launches.',
            });
            break;
          }
        }
      }
    }

    return findings;
  },
};

/** Keywords that make an App/index file look like a sensitive app */
const SNAPSHOT_SENSITIVE_INDICATORS = [
  'payment', 'banking', 'financial', 'fintech', 'healthcare',
  'medical', 'crypto', 'wallet', 'insurance',
];

/** Packages that hide the app switcher snapshot or block capture */
const SNAPSHOT_PROTECTION_PACKAGES = [
  'react-native-privacy-snapshot',
  'react-native-screen-protection',
  'react-native-capture-protection',
  'expo-screen-capture',
  'react-native-prevent-screenshot',
  'react-native-screenshot-prevent',
];

/** Names of a view/library that covers the screen while the app is inactive (a bare "overlay" or "cover" is far too common) */
const JS_PRIVACY_COVER = /blurview|blur-view|react-native-blur|@react-native-community\/blur|privacy[\s_-]?(?:screen|overlay|cover|shield|view)|secure[\s_-]?view|snapshot[\s_-]?(?:cover|overlay|protect)|app[\s_-]?(?:cover|shield)/;

const JS_FILE = /\.(?:js|jsx|ts|tsx)$/;
const IOS_NATIVE_FILE = /\.(?:m|mm|swift)$/;
const SNAPSHOT_FILES = /\.(?:js|jsx|ts|tsx|m|mm|swift)$/;

/**
 * Does this file hide the app switcher snapshot? JS: a protection package, an AppState handler for
 * `inactive`/`background` that covers the screen, or the iOS lifecycle names (as before). Native iOS:
 * a resign-active / enter-background handler in a file that also puts a view over the window. A bare
 * `applicationDidBecomeActive` / `applicationDidEnterBackground` (present in most AppDelegates for
 * unrelated reasons) is not protection.
 */
export function hasSnapshotProtection(content: string, filePath: string): boolean {
  const lower = lowerCased(content);
  if (IOS_NATIVE_FILE.test(filePath)) {
    return (
      /(?:applicationwillresignactive|scenewillresignactive|applicationdidenterbackground|scenedidenterbackground)/.test(lower) &&
      /(?:uivisualeffectview|uiblureffect|addsubview|overlay|privacy|snapshot|blur)/.test(lower)
    ) || /(?:rnprivacysnapshot|screenprotector|ignoresnapshotonnextapplicationlaunch)/.test(lower);
  }
  if (!JS_FILE.test(filePath)) return false;
  return (
    SNAPSHOT_PROTECTION_PACKAGES.some(pkg => lower.includes(pkg)) ||
    (lower.includes('appstate') && /['"](?:inactive|background)['"]/.test(lower) && JS_PRIVACY_COVER.test(lower)) ||
    /applyblureffect|privacy[\s_-]?(?:screen|overlay|cover|shield)/.test(lower) ||
    lower.includes('applicationdidbecomeactive') ||
    lower.includes('applicationwillresignactive') ||
    (lower.includes('screencapture') && lower.includes('prevent'))
  );
}

/**
 * Absence-of-feature check, reported once per project (see projectEvidence.ts): candidates are App/index
 * files that mention a sensitive domain; any snapshot protection anywhere in the project (JS, AppDelegate,
 * a protection package) means no finding.
 */
let snapshotCandidates: Evidence[] = [];
let snapshotProtected = false;

const iosMissingAppSnapshotProtectionRule: Rule = {
  id: 'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
  description: 'Sensitive app without app snapshot protection on backgrounding',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.m', '.mm', '.swift'],
  beginScan: () => {
    snapshotCandidates = [];
    snapshotProtected = false;
  },
  apply: async (context: RuleContext): Promise<Finding[]> => {
    if (!isAppSource(context) || !SNAPSHOT_FILES.test(context.filePath)) return [];
    if (hasSnapshotProtection(context.fileContent, context.filePath)) {
      snapshotProtected = true;
      return [];
    }
    if (!JS_FILE.test(context.filePath)) return [];

    // Only check entry-point/App files
    const relPath = toRelativePath(context.filePath, context.project?.rootDir);
    const isApp = /App\.(tsx|ts|jsx|js)$/.test(relPath);
    if (!isApp && !relPath.includes('index.')) return [];

    const content = context.fileContent.toLowerCase();
    if (!SNAPSHOT_SENSITIVE_INDICATORS.some(indicator => content.includes(indicator))) return [];
    if (ignoresAtAnchor(context.fileContent, 'IOS_MISSING_APP_SNAPSHOT_PROTECTION')) return [];

    snapshotCandidates.push({ filePath: context.filePath, priority: isApp ? 0 : 1 });
    return [];
  },
  finalize: async (project?: ProjectInfo): Promise<Finding[]> =>
    finalizeAbsence({
      ruleId: 'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
      severity: Severity.LOW,
      headline: 'Sensitive app without app snapshot protection - iOS takes screenshots when backgrounding, and no blur/privacy handler or protection package was found in the project',
      suggestion: 'Add a blur overlay or splash screen when app enters background state to prevent iOS from capturing sensitive screen content in the app switcher.',
      project,
      candidates: snapshotCandidates,
      protectionSeen: snapshotProtected,
      protectionPackages: SNAPSHOT_PROTECTION_PACKAGES,
      protectionFiles: SNAPSHOT_FILES,
      hasProtection: hasSnapshotProtection,
    }),
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
    iosInsecurePasteboardUsageRule,
    iosMissingAppSnapshotProtectionRule,
  ],
};
