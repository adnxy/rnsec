import type { Finding } from '../types/findings.js';
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { parseJSFile, parseJsonSafe } from './astParser.js';
import { readFileContent } from '../utils/fileUtils.js';
import { walkProjectFiles } from './fileWalker.js';
import { isInDebugContext } from '../utils/stringUtils.js';
import { ScanCache } from './cache.js';
import pLimit from 'p-limit';

// Default concurrency for parallel file processing
const DEFAULT_CONCURRENCY = 10;

/**
 * Extended scan result with cache statistics
 */
export interface ScanResult {
  findings: Finding[];
  scannedFiles: number;
  skippedFiles?: number;
  cachedFiles?: number;
}

/**
 * Rule engine responsible for running security rules against project files
 */
export class RuleEngine {
  private ruleGroups: RuleGroup[] = [];
  private ignoredRules: Set<string> = new Set();
  private skippedFiles: number = 0;
  private excludedPaths: string[] = [];
  private concurrency: number = DEFAULT_CONCURRENCY;
  private cache: ScanCache | null = null;
  private cachedFiles: number = 0;

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
   * Set concurrency level for parallel file processing
   * @param concurrency - Number of files to process in parallel
   */
  setConcurrency(concurrency: number): void {
    this.concurrency = Math.max(1, concurrency);
  }

  /**
   * Get current concurrency level
   * @returns Current concurrency setting
   */
  getConcurrency(): number {
    return this.concurrency;
  }

  /**
   * Enable caching for incremental scans
   * @param projectDir - Project directory for cache storage
   * @param version - Version string for cache invalidation
   */
  async enableCache(projectDir: string, version: string): Promise<void> {
    this.cache = new ScanCache(projectDir, version);
    await this.cache.load();
  }

  /**
   * Disable caching
   */
  disableCache(): void {
    this.cache = null;
  }

  /**
   * Save cache to disk (call after scan completes)
   */
  async saveCache(): Promise<void> {
    if (this.cache) {
      await this.cache.save();
    }
  }

  /**
   * Clear the cache
   */
  async clearCache(): Promise<void> {
    if (this.cache) {
      this.cache.clear();
      await this.cache.save();
    }
  }

  /**
   * Check if caching is enabled
   */
  isCacheEnabled(): boolean {
    return this.cache !== null && this.cache.isEnabled();
  }

  /**
   * Get all registered rules from all rule groups, excluding ignored ones
   * @returns Array of all rules
   */
  getAllRules(): Rule[] {
    return this.ruleGroups.flatMap(group => group.rules).filter(rule => !this.ignoredRules.has(rule.id));
  }

  /**
   * Run all registered rules on specific files with parallel processing
   * @param filePaths - Array of specific file paths to scan
   * @param progressCallback - Optional callback for progress updates
   * @returns Scan results with findings and file count
   */
  async runRulesOnFiles(
    filePaths: string[],
    progressCallback?: (progress: { current: number; total: number }) => void
  ): Promise<ScanResult> {
    this.skippedFiles = 0;
    this.cachedFiles = 0;

    const totalFiles = filePaths.length;
    let completed = 0;

    // Create a limiter for controlled parallelism
    const limit = pLimit(this.concurrency);

    // Create scan promises with concurrency control
    const scanPromises = filePaths.map(filePath =>
      limit(async () => {
        const findings = await this.scanFile(filePath);
        completed++;
        
        if (progressCallback) {
          progressCallback({ current: completed, total: totalFiles });
        }
        
        return findings;
      })
    );

    // Execute all scans in parallel with concurrency limit
    const results = await Promise.all(scanPromises);
    const allFindings = results.flat();

    // Save cache after scan
    await this.saveCache();

    return { 
      findings: allFindings, 
      scannedFiles: totalFiles,
      skippedFiles: this.skippedFiles > 0 ? this.skippedFiles : undefined,
      cachedFiles: this.cachedFiles > 0 ? this.cachedFiles : undefined,
    };
  }

  /**
   * Run all registered rules on a project with parallel processing
   * @param rootDir - Root directory of the project to scan
   * @param progressCallback - Optional callback for progress updates
   * @returns Scan results with findings and file count
   */
  async runRulesOnProject(
    rootDir: string,
    progressCallback?: (progress: { current: number; total: number }) => void
  ): Promise<ScanResult> {
    this.skippedFiles = 0;
    this.cachedFiles = 0;

    const fileGroup = await walkProjectFiles(rootDir, this.excludedPaths);
    const allFiles = [
      ...fileGroup.jsFiles,
      ...fileGroup.jsonFiles,
      ...fileGroup.xmlFiles,
      ...fileGroup.plistFiles,
    ];

    const totalFiles = allFiles.length;
    let completed = 0;

    // Create a limiter for controlled parallelism
    const limit = pLimit(this.concurrency);

    // Create scan promises with concurrency control
    const scanPromises = allFiles.map(filePath =>
      limit(async () => {
        const findings = await this.scanFile(filePath);
        completed++;
        
        if (progressCallback) {
          progressCallback({ current: completed, total: totalFiles });
        }
        
        return findings;
      })
    );

    // Execute all scans in parallel with concurrency limit
    const results = await Promise.all(scanPromises);
    const allFindings = results.flat();

    // Save cache after scan
    await this.saveCache();

    return {
      findings: allFindings,
      scannedFiles: totalFiles,
      skippedFiles: this.skippedFiles > 0 ? this.skippedFiles : undefined,
      cachedFiles: this.cachedFiles > 0 ? this.cachedFiles : undefined,
    };
  }

  /**
   * Scan a single file with all applicable rules
   * Uses cache when available to skip unchanged files
   * @param filePath - Path to the file to scan
   * @returns Array of findings for this file
   */
  private async scanFile(filePath: string): Promise<Finding[]> {
    try {
      const fileContent = await readFileContent(filePath);
      
      // Check cache first
      if (this.cache) {
        const contentHash = this.cache.getContentHash(fileContent);
        
        if (this.cache.isValid(filePath, contentHash)) {
          const cachedFindings = this.cache.getFindings(filePath);
          if (cachedFindings !== null) {
            this.cachedFiles++;
            return cachedFindings;
          }
        }
        
        // Not cached or invalid - scan and cache
        const findings = await this.scanFileContent(filePath, fileContent);
        this.cache.set(filePath, contentHash, findings);
        return findings;
      }
      
      // No cache - scan directly
      return this.scanFileContent(filePath, fileContent);
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
   * Scan file content with all applicable rules
   * @param filePath - Path to the file
   * @param fileContent - Content of the file
   * @returns Array of findings for this file
   */
  private async scanFileContent(filePath: string, fileContent: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    const context = await this.prepareContext(filePath, fileContent);
    const applicableRules = this.getApplicableRules(filePath);

    for (const rule of applicableRules) {
      try {
        const ruleFindings = await rule.apply(context);
        findings.push(...ruleFindings);
      } catch (error) {
        // Silently continue - rule errors shouldn't stop the scan
      }
    }

    // Post-process findings to detect debug context
    return this.enrichFindingsWithDebugContext(findings, fileContent);
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
