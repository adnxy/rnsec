import fg from 'fast-glob';
import { resolve } from 'path';
import type { Finding, IgnoredFinding } from '../types/findings.js';
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { parseJSFile, parseJsonSafe } from './astParser.js';
import { readFileContent } from '../utils/fileUtils.js';
import { walkProjectFiles } from './fileWalker.js';
import { isInDebugContext } from '../utils/stringUtils.js';

/**
 * Rule engine responsible for running security rules against project files
 */
export class RuleEngine {
  private ruleGroups: RuleGroup[] = [];
  private ignoredRules: Set<string> = new Set();
  private skippedFiles: number = 0;
  private excludedPaths: string[] = [];
  private ignoredFindings: IgnoredFinding[] = [];
  private ignoredFindingPaths: Set<string>[] = [];

  /**
   * Register a group of security rules
   * @param group - The rule group to register
   */
  registerRuleGroup(group: RuleGroup): void {
    this.ruleGroups.push(group);
  }

  /**
   * Set ignored rules
   * @param ignoredRules - Array of rule IDs to ignore
   */
  setIgnoredRules(ignoredRules: string[]): void {
    this.ignoredRules = new Set(ignoredRules);
  }

  /**
   * Get ignored rules
   * @returns Array of ignored rule IDs
   */
  getIgnoredRules(): string[] {
    return Array.from(this.ignoredRules);
  }

  /**
   * Set excluded paths
   * @param exclude - Array of glob patterns to exclude
   */
  setExcludedPaths(exclude: string[]): void {
    this.excludedPaths = exclude;
  }

  /**
   * Get excluded paths
   * @returns Array of glob patterns
   */
  getExcludedPaths(): string[] {
    return this.excludedPaths;
  }

  /**
   * Set finding-level ignores scoped by rule, path and optional line
   * @param ignoredFindings - Finding ignore definitions from configuration
   * @param rootDir - Project root used to resolve path globs
   */
  async setIgnoredFindings(
    ignoredFindings: IgnoredFinding[],
    rootDir: string
  ): Promise<void> {
    const resolvedRoot = resolve(rootDir);
    this.ignoredFindings = ignoredFindings;
    this.ignoredFindingPaths = await Promise.all(
      ignoredFindings.map(async ignoredFinding => {
        const matchedPaths = await fg(ignoredFinding.path, {
          cwd: resolvedRoot,
          absolute: true,
        });
        return new Set(matchedPaths.map(filePath => resolve(filePath)));
      })
    );
  }

  /**
   * Get configured finding-level ignores
   */
  getIgnoredFindings(): IgnoredFinding[] {
    return this.ignoredFindings;
  }

  /**
   * Get all registered rules from all rule groups, excluding ignored ones
   * @returns Array of all rules
   */
  getAllRules(): Rule[] {
    return this.ruleGroups.flatMap(group => group.rules).filter(rule => !this.ignoredRules.has(rule.id));
  }

  /**
   * Run all registered rules on specific files
   * @param filePaths - Array of specific file paths to scan
   * @param progressCallback - Optional callback for progress updates
   * @returns Scan results with findings and file count
   */
  async runRulesOnFiles(
    filePaths: string[],
    progressCallback?: (progress: { current: number; total: number }) => void
  ): Promise<{ findings: Finding[]; scannedFiles: number; skippedFiles?: number }> {
    const allFindings: Finding[] = [];
    this.skippedFiles = 0;

    const totalFiles = filePaths.length;

    for (let i = 0; i < filePaths.length; i++) {
      const filePath = filePaths[i];
      
      if (progressCallback) {
        progressCallback({ current: i + 1, total: totalFiles });
      }

      const findings = await this.scanFile(filePath);
      allFindings.push(...findings);
    }

    return { 
      findings: allFindings, 
      scannedFiles: totalFiles,
      skippedFiles: this.skippedFiles > 0 ? this.skippedFiles : undefined
    };
  }

  /**
   * Run all registered rules on a project
   * @param rootDir - Root directory of the project to scan
   * @param progressCallback - Optional callback for progress updates
   * @returns Scan results with findings and file count
   */
  async runRulesOnProject(
    rootDir: string,
    progressCallback?: (progress: { current: number; total: number }) => void
  ): Promise<{ findings: Finding[]; scannedFiles: number; skippedFiles?: number }> {
    const allFindings: Finding[] = [];
    this.skippedFiles = 0;

    const fileGroup = await walkProjectFiles(rootDir, this.excludedPaths);
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

    return {
      findings: allFindings,
      scannedFiles: totalFiles,
      skippedFiles: this.skippedFiles > 0 ? this.skippedFiles : undefined
    };
  }

  /**
   * Scan a single file with all applicable rules
   * @param filePath - Path to the file to scan
   * @returns Array of findings for this file
   */
  private async scanFile(filePath: string): Promise<Finding[]> {
    try {
      const fileContent = await readFileContent(filePath);
      const findings: Finding[] = [];

      const context = await this.prepareContext(filePath, fileContent);
      const applicableRules = this.getApplicableRules(filePath);

      for (const rule of applicableRules) {
        try {
          const ruleFindings = await rule.apply(context);
          findings.push(...this.filterIgnoredFindings(ruleFindings));
        } catch (error) {
          // Silently continue - rule errors shouldn't stop the scan
        }
      }

      // Post-process findings to detect debug context
      return this.enrichFindingsWithDebugContext(findings, fileContent);
    } catch (error: any) {
      // Show minimal warning for file read errors
      this.skippedFiles++;

      const fileName = filePath.split('/').pop();
      const errorType = error.code || error.message?.split(':')[0] || 'Error';

      if (process.env.RNSEC_VERBOSE) {
        console.warn(`⚠️  Warning: Could not scan ${fileName} (${errorType})`);
      }

      return [];
    }
  }

  /**
   * Filter findings ignored for a matching rule, path and optional line
   */
  private filterIgnoredFindings(findings: Finding[]): Finding[] {
    return findings.filter(finding =>
      !this.ignoredFindings.some((ignoredFinding, index) =>
        ignoredFinding.ruleId === finding.ruleId &&
        this.ignoredFindingPaths[index]?.has(resolve(finding.filePath)) &&
        (ignoredFinding.line === undefined || ignoredFinding.line === finding.line)
      )
    );
  }

  /**
   * Filter out findings that are in debug/development context
   * @param findings - Array of findings to filter
   * @param fileContent - Content of the file being scanned
   * @returns Filtered findings excluding debug context
   */
  private enrichFindingsWithDebugContext(findings: Finding[], fileContent: string): Finding[] {
    return findings.filter(finding => {
      const inDebugContext = isInDebugContext(
        fileContent,
        finding.snippet,
        finding.filePath
      );

      // Exclude findings that are in debug context (dev only, not production issues)
      return !inDebugContext;
    });
  }

  /**
   * Prepare the context for rule execution
   * @param filePath - Path to the file
   * @param fileContent - Content of the file
   * @returns Rule context with parsed AST or configuration
   */
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

  /**
   * Get rules applicable to a specific file based on file type
   * @param filePath - Path to the file
   * @returns Array of applicable rules
   */
  private getApplicableRules(filePath: string): Rule[] {
    const allRules = this.getAllRules();
    return allRules.filter(rule =>
      rule.fileTypes.some(type => filePath.endsWith(type))
    );
  }
}
