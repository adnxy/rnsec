import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { getLineNumber } from '../../utils/stringUtils.js';

/** Replace plist comments with spaces (newlines kept) so offsets and line numbers stay accurate. */
function blankComments(xml: string): string {
  return xml.replace(/<!--[\s\S]*?(-->|$)/g, m => m.replace(/[^\n]/g, ' '));
}

const keyTrue = (plist: string, key: string): RegExpExecArray | null =>
  new RegExp(`<key>\\s*${key}\\s*</key>\\s*<true\\s*/>`).exec(plist);

const fileSharingRule: Rule = {
  id: 'IOS_FILE_SHARING_ENABLED',
  description: 'iOS file sharing enabled - app Documents directory is exposed via Finder/Files',
  severity: Severity.LOW,
  fileTypes: ['.plist'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    if (!context.plistContent || !/(^|[\\/])Info\.plist$/.test(context.filePath)) return [];

    const plist = blankComments(context.plistContent);
    const sharing = keyTrue(plist, 'UIFileSharingEnabled');
    if (!sharing) return [];

    // In-place document opening additionally lets other apps edit files directly in the sandbox.
    const inPlace = keyTrue(plist, 'LSSupportsOpeningDocumentsInPlace') !== null;
    return [{
      ruleId: 'IOS_FILE_SHARING_ENABLED',
      description: inPlace
        ? 'UIFileSharingEnabled and LSSupportsOpeningDocumentsInPlace are both true - Documents directory is readable and editable by other apps and users'
        : 'UIFileSharingEnabled is true - Documents directory is exposed through Finder/iTunes and the Files app',
      severity: inPlace ? Severity.MEDIUM : Severity.LOW,
      filePath: context.filePath,
      line: getLineNumber(plist, sharing.index),
      reason: 'Anything stored in the Documents directory (caches, databases, tokens) can be browsed and copied from a paired or unlocked device. Often intentional for document-based apps.',
      suggestion: 'Disable UIFileSharingEnabled unless users must import/export files, and keep sensitive data outside Documents (e.g. Library/Application Support with file protection or the Keychain).',
      confidence: 'medium',
    }];
  },
};

export const iosPlistExtraRules: RuleGroup = {
  category: RuleCategory.MANIFEST,
  rules: [fileSharingRule],
};
