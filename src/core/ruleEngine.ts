import type { Finding } from '../types/findings.js';
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { parseJSFile, parseJsonSafe } from './astParser.js';
import { readFileContent } from '../utils/fileUtils.js';
import { walkProjectFiles } from './fileWalker.js';

export class RuleEngine {
  private ruleGroups: RuleGroup[] = [];

  registerRuleGroup(group: RuleGroup): void {
    this.ruleGroups.push(group);
  }

  getAllRules(): Rule[] {
    return this.ruleGroups.flatMap(group => group.rules);
  }

  async runRulesOnProject(
    rootDir: string,
    progressCallback?: (progress: { current: number; total: number }) => void
  ): Promise<Finding[]> {
    const allFindings: Finding[] = [];

    const fileGroup = await walkProjectFiles(rootDir);
    const allFiles = [
      ...fileGroup.jsFiles,
      ...fileGroup.jsonFiles,
      ...fileGroup.xmlFiles,
      ...fileGroup.plistFiles,
    ];

    const totalFiles = allFiles.length;

    for (let i = 0; i < allFiles.length; i++) {
      const filePath = allFiles[i];
      
      if (progressCallback) {
        progressCallback({ current: i + 1, total: totalFiles });
      }

      const findings = await this.scanFile(filePath);
      allFindings.push(...findings);
    }

    return allFindings;
  }

  private async scanFile(filePath: string): Promise<Finding[]> {
    try {
      const fileContent = await readFileContent(filePath);
      const findings: Finding[] = [];

      const context = await this.prepareContext(filePath, fileContent);
      const applicableRules = this.getApplicableRules(filePath);

      for (const rule of applicableRules) {
        try {
          const ruleFindings = await rule.apply(context);
          findings.push(...ruleFindings);
        } catch (error) {
          console.error(`Error applying rule ${rule.id} to ${filePath}:`, error);
        }
      }

      return findings;
    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
      return [];
    }
  }

  private async prepareContext(
    filePath: string,
    fileContent: string
  ): Promise<RuleContext> {
    const context: RuleContext = {
      filePath,
      fileContent,
    };

    if (filePath.match(/\.(js|jsx|ts|tsx)$/)) {
      const parseResult = await parseJSFile(filePath, fileContent);
      if (parseResult.success) {
        context.ast = parseResult.ast;
      }
    } else if (filePath.endsWith('.json')) {
      const config = parseJsonSafe(fileContent);
      if (config) {
        context.config = config;
      }
    } else if (filePath.endsWith('.xml')) {
      context.xmlContent = fileContent;
    } else if (filePath.endsWith('.plist')) {
      context.plistContent = fileContent;
    }

    return context;
  }

  private getApplicableRules(filePath: string): Rule[] {
    const allRules = this.getAllRules();
    return allRules.filter(rule =>
      rule.fileTypes.some(type => filePath.endsWith(type))
    );
  }
}

