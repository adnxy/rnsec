import { resolve, join } from 'path';
import type { Finding } from '../types/findings.js';
import type { ProjectInfo, Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { parseJSFile, parseJsonSafe } from './astParser.js';
import { readFileContent } from '../utils/fileUtils.js';
import { walkProjectFiles, isCollectedFile } from './fileWalker.js';
import { collectDevOnlyRanges, isLineInRanges } from '../utils/devGuards.js';
import { isNonProductionPath, matchesExcludeGlobs, globToRegExp, toRelativePath, isNonAppSourcePath, isGeneratedBundlePath, isGeneratedBundleContent } from '../utils/pathFilters.js';
import { filterGitIgnored } from '../utils/gitUtils.js';
import { resolveAndroidTargetSdk } from '../utils/androidSdk.js';
import { languageForPath } from '../utils/nativeCode.js';
import { collectNativeDevOnlyRanges } from '../utils/nativeGuards.js';
import { parseSuppressions, isSuppressed } from '../utils/suppression.js';

/**
 * Rules that describe the same underlying problem from different angles. When
 * several rules of one family fire on the same line, only the first (most
 * specific) is kept.
 */
const DEDUP_FAMILIES: string[][] = [
  // provider-specific secret over the generic "variable looks like a secret"
  ['API_KEY_EXPOSED', 'HARDCODED_SECRETS'],
  ['OBFUSCATED_EVAL_EXECUTION', 'EVAL_USAGE', 'INSECURE_DESERIALIZATION'],
  ['WEAK_TLS_CONFIGURATION', 'CERT_PINNING_DISABLED'],
  ['ANDROID_UNPROTECTED_RECEIVER', 'ANDROID_EXPORTED_COMPONENT'],
  // a committed service-account file is reported once, on its private_key line
  ['COMMITTED_CREDENTIAL_FILE', 'API_KEY_EXPOSED', 'HARDCODED_SECRETS'],
  // the context-specific rule says more than the generic "variable looks like a secret"
  ['MMKV_UNENCRYPTED_SENSITIVE_DATA', 'HARDCODED_SECRETS'],
  ['JWT_INSECURE_SIGNING', 'HARDCODED_SECRETS'],
  ['HARDCODED_BASIC_AUTH_CREDENTIALS', 'HARDCODED_SECRETS'],
  ['BUNDLED_ENV_SECRET', 'HARDCODED_SECRETS'],
  ['TEST_CREDENTIALS_IN_CODE', 'HARDCODED_SECRETS'],
  // provider knowledge (e.g. a Firebase web key is public by design) beats a name-based guess
  ['API_KEY_EXPOSED', 'EXPO_SENSITIVE_CONFIG_EXPOSED', 'HARDCODED_SECRETS'],
  ['API_KEY_EXPOSED', 'EAS_JSON_SECRET_IN_ENV', 'HARDCODED_SECRETS'],
  ['WEAK_CIPHER_OR_MODE', 'HARDCODED_ENCRYPTION_KEY'],
  ['HARDCODED_ENCRYPTION_KEY', 'HARDCODED_SECRETS'],
  ['SENSITIVE_LOGGING', 'SENSITIVE_DATA_IN_ERROR_MESSAGES'],
  // a cleartext URL to a bare public IP is one issue, reported by the URL rule
  // usePKCE: false in expo-auth-session code: the Expo-specific rule owns it
  ['EXPO_AUTH_SESSION_NO_PKCE', 'OAUTH_INSECURE_FLOW'],
  ['INSECURE_HTTP_URL', 'HARDCODED_IP_ADDRESS'],
  ['INSECURE_WEBSOCKET', 'HARDCODED_IP_ADDRESS'],
];

/** Generic suffixes that do not select the file kinds matched by SPECIFIC_ONLY_FILE */
const GENERIC_FILE_TYPES = new Set(['.json', '.xml', '.properties', '.js', '.ts', '.jsx', '.tsx']);
const SPECIFIC_ONLY_FILE =
  /(^|[\\/])(package-lock\.json|npm-shrinkwrap\.json|firebase\.json|credentials\.json|[^\\/]*\.rules\.json|sentry\.properties|keystore\.properties|signing\.properties)$|[\\/]src[\\/][^\\/]+[\\/]res[\\/]xml[\\/](?!network_security_config\.xml$)[^\\/]+\.xml$/;

/**
 * Rule engine responsible for running security rules against project files
 */
export class RuleEngine {
  private ruleGroups: RuleGroup[] = [];
  private ignoredRules: Set<string> = new Set();
  private skippedFiles: number = 0;
  private excludedPaths: string[] = [];
  private rootDir: string | undefined;
  private suppressedCount: number = 0;
  private projectInfo: ProjectInfo | undefined;
  private respectGitignore = true;

  /**
   * Skip files that git ignores (default true). Tracked files are always scanned.
   * @param respect - false to scan git-ignored files too
   */
  setRespectGitignore(respect: boolean): void {
    this.respectGitignore = respect;
  }

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
   * @param rootDir - Project root, used to apply the same excludes as a full scan
   * @returns Scan results with findings and file count
   */
  async runRulesOnFiles(
    inputFilePaths: string[],
    progressCallback?: (progress: { current: number; total: number }) => void,
    rootDir?: string
  ): Promise<{ findings: Finding[]; scannedFiles: number; skippedFiles?: number; suppressedCount?: number }> {
    const allFindings: Finding[] = [];
    this.skippedFiles = 0;
    this.suppressedCount = 0;
    this.rootDir = rootDir ? resolve(rootDir) : undefined;
    this.projectInfo = await this.loadProjectInfo();
    this.beginScan();

    const candidates = inputFilePaths.filter(
      filePath =>
        isCollectedFile(filePath) &&
        !isNonProductionPath(filePath, this.rootDir) &&
        !matchesExcludeGlobs(filePath, this.excludedPaths, this.rootDir)
    );
    const filePaths =
      this.respectGitignore && this.rootDir ? await filterGitIgnored(candidates, this.rootDir) : candidates;
    const totalFiles = filePaths.length;

    for (let i = 0; i < filePaths.length; i++) {
      const filePath = filePaths[i];
      
      if (progressCallback) {
        progressCallback({ current: i + 1, total: totalFiles });
      }

      const findings = await this.scanFile(filePath);
      allFindings.push(...findings);
    }
    allFindings.push(...(await this.finalizeRules()));

    return {
      findings: this.dedupeFindings(allFindings),
      scannedFiles: totalFiles,
      skippedFiles: this.skippedFiles > 0 ? this.skippedFiles : undefined,
      suppressedCount: this.suppressedCount > 0 ? this.suppressedCount : undefined,
    };
  }

  private beginScan(): void {
    for (const rule of this.getAllRules()) rule.beginScan?.();
  }

  /** Run every rule's `finalize` hook; findings with file + line honour `rnsec-ignore` in that file. */
  private async finalizeRules(): Promise<Finding[]> {
    const out: Finding[] = [];
    const suppressionCache = new Map<string, ReturnType<typeof parseSuppressions> | null>();
    for (const rule of this.getAllRules()) {
      if (!rule.finalize) continue;
      let findings: Finding[] = [];
      try {
        findings = await rule.finalize(this.projectInfo);
      } catch (error) {
        if (process.env.RNSEC_VERBOSE) {
          console.warn(`⚠️  Rule ${rule.id} failed in finalize: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      for (const finding of findings) {
        if (finding.filePath && finding.line !== undefined) {
          if (!suppressionCache.has(finding.filePath)) {
            suppressionCache.set(
              finding.filePath,
              await readFileContent(finding.filePath).then(parseSuppressions, () => null)
            );
          }
          const map = suppressionCache.get(finding.filePath);
          if (map && isSuppressed(map, finding.ruleId, finding.line)) {
            this.suppressedCount++;
            continue;
          }
        }
        out.push(finding);
      }
    }
    return out;
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
  ): Promise<{ findings: Finding[]; scannedFiles: number; skippedFiles?: number; suppressedCount?: number; unverifiedFiles?: number }> {
    const allFindings: Finding[] = [];
    this.skippedFiles = 0;
    this.suppressedCount = 0;
    this.rootDir = resolve(rootDir);
    this.projectInfo = await this.loadProjectInfo();
    this.beginScan();

    let unverifiedFiles = 0;
    const fileGroup = await walkProjectFiles(rootDir, this.excludedPaths, {
      respectGitignore: this.respectGitignore,
      onUnverifiedFiles: count => { unverifiedFiles = count; },
    });
    const allFiles = [
      ...fileGroup.jsFiles,
      ...fileGroup.jsonFiles,
      ...fileGroup.xmlFiles,
      ...fileGroup.plistFiles,
      ...fileGroup.envFiles,
      ...fileGroup.gradleFiles,
      ...fileGroup.registryFiles,
      ...fileGroup.credentialFiles,
      ...fileGroup.nativeFiles,
      ...fileGroup.entitlementFiles,
      ...fileGroup.firebaseRuleFiles,
      ...fileGroup.lockfiles,
      ...fileGroup.credentialPropertyFiles,
      ...fileGroup.resXmlFiles,
    ].filter(filePath => !isNonProductionPath(filePath, this.rootDir));

    const totalFiles = allFiles.length;

    for (let i = 0; i < allFiles.length; i++) {
      const filePath = allFiles[i];

      if (progressCallback) {
        progressCallback({ current: i + 1, total: totalFiles });
      }

      const findings = await this.scanFile(filePath);
      allFindings.push(...findings);
    }
    allFindings.push(...(await this.finalizeRules()));

    return {
      findings: this.dedupeFindings(allFindings),
      scannedFiles: totalFiles,
      skippedFiles: this.skippedFiles > 0 ? this.skippedFiles : undefined,
      suppressedCount: this.suppressedCount > 0 ? this.suppressedCount : undefined,
      unverifiedFiles: unverifiedFiles > 0 ? unverifiedFiles : undefined,
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
          findings.push(...ruleFindings);
        } catch (error) {
          // A rule crash must not stop the scan, but it must not look like a clean result either
          if (process.env.RNSEC_VERBOSE) {
            const reason = error instanceof Error ? error.message : String(error);
            console.warn(`⚠️  Rule ${rule.id} failed on ${filePath}: ${reason}`);
          }
        }
      }

      return this.postProcessFindings(findings, context, fileContent);
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
   * Drop findings that sit in development-only code or carry an `rnsec-ignore`
   * comment. Suppression is always local to the finding's own line or block;
   * nothing elsewhere in the file can hide it.
   */
  private postProcessFindings(findings: Finding[], context: RuleContext, fileContent: string): Finding[] {
    if (findings.length === 0) return findings;

    const devRanges = context.language
      ? collectNativeDevOnlyRanges(fileContent, context.language)
      : collectDevOnlyRanges(context.ast);
    const suppressions = parseSuppressions(fileContent);

    return findings.filter(finding => {
      // path-level, for every rule: findings in tests, vendored code and Android debug source sets never ship
      if (isNonProductionPath(finding.filePath, this.rootDir)) return false;
      if (isLineInRanges(finding.line, devRanges)) return false;
      if (isSuppressed(suppressions, finding.ruleId, finding.line)) {
        this.suppressedCount++;
        return false;
      }
      return true;
    });
  }

  /**
   * Remove findings that report the same thing twice: exact repeats of
   * (rule, file, line, description), and overlapping secret-family rules.
   */
  private dedupeFindings(findings: Finding[]): Finding[] {
    const seen = new Set<string>();
    const exact = findings.filter(f => {
      const key = `${f.ruleId}|${f.filePath}|${f.line ?? ''}|${f.description}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // A rule may belong to several families. A finding is dropped when, in any of its families,
    // a higher-priority (earlier) rule reports on the same file and line.
    // The "Generic ..." patterns of API_KEY_EXPOSED are as weak as HARDCODED_SECRETS, so they yield to
    // context-specific rules in exactly the same way (while provider-specific matches do not).
    const GENERIC_KEY = 'API_KEY_EXPOSED:generic';
    const idOf = (f: Finding) =>
      f.ruleId === 'API_KEY_EXPOSED' && /^Generic /.test(f.description) ? GENERIC_KEY : f.ruleId;
    const families = DEDUP_FAMILIES.flatMap(family =>
      family.indexOf('HARDCODED_SECRETS') > 0
        ? [family, family.map(id => (id === 'HARDCODED_SECRETS' ? GENERIC_KEY : id))]
        : [family]
    );

    // as before: any API_KEY_EXPOSED match on a line outranks the generic HARDCODED_SECRETS
    families.push([GENERIC_KEY, 'HARDCODED_SECRETS']);

    const familiesOf = new Map<string, string[][]>();
    families.forEach(family =>
      family.forEach(id => familiesOf.set(id, [...(familiesOf.get(id) ?? []), family]))
    );

    const rulesOnLine = new Map<string, Set<string>>();
    for (const f of exact) {
      if (f.line === undefined) continue;
      const key = `${f.filePath}:${f.line}`;
      (rulesOnLine.get(key) ?? rulesOnLine.set(key, new Set()).get(key)!).add(idOf(f));
    }

    return exact.filter(f => {
      const myFamilies = familiesOf.get(idOf(f));
      if (!myFamilies || f.line === undefined) return true;
      const present = rulesOnLine.get(`${f.filePath}:${f.line}`)!;
      return !myFamilies.some(family =>
        family.slice(0, family.indexOf(idOf(f))).some(higher => present.has(higher))
      );
    });
  }

  /** Read dependency names from the root package.json, if there is one. */
  private async loadProjectInfo(): Promise<ProjectInfo | undefined> {
    if (!this.rootDir) return undefined;
    try {
      const pkg = parseJsonSafe(await readFileContent(join(this.rootDir, 'package.json')).catch(() => ''));
      const androidTargetSdk = await resolveAndroidTargetSdk(this.rootDir);
      const stripsConsoleInRelease = await this.detectConsoleStripping(pkg);
      const dependencies = new Set<string>();
      for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
        Object.keys(pkg?.[field] ?? {}).forEach(name => dependencies.add(name));
      }
      return { rootDir: this.rootDir, dependencies, androidTargetSdk, stripsConsoleInRelease };
    } catch {
      return undefined;
    }
  }

  /** True when a root babel config mentions `transform-remove-console` (plain text search). */
  private async detectConsoleStripping(pkg: Record<string, any> | null): Promise<boolean> {
    if (pkg?.babel && JSON.stringify(pkg.babel).includes('transform-remove-console')) return true;
    for (const name of ['babel.config.js', 'babel.config.cjs', 'babel.config.mjs', 'babel.config.json', '.babelrc', '.babelrc.js']) {
      try {
        if ((await readFileContent(join(this.rootDir!, name))).includes('transform-remove-console')) return true;
      } catch {
        // config not present
      }
    }
    return false;
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
      project: this.projectInfo,
      isNonAppSource: isNonAppSourcePath(filePath, this.rootDir) || isNonProductionPath(filePath, this.rootDir),
      isGeneratedBundle:
        isGeneratedBundlePath(filePath) ||
        (/\.(js|jsx|ts|tsx)$/.test(filePath) && isGeneratedBundleContent(fileContent)),
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
    } else if (filePath.endsWith('.plist') || filePath.endsWith('.entitlements')) {
      context.plistContent = fileContent;
    } else {
      const language = languageForPath(filePath);
      if (language) context.language = language;
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
    const fileName = filePath.split('/').pop() ?? '';
    const isEnvFile = fileName.startsWith('.env');
    // Lockfiles, Firebase rules, EAS credentials and extra res/xml files are huge or off-topic for rules
    // written for `.json` / `.xml`: they only reach rules that name them (e.g. 'yarn.lock', '.rules.json')
    const specificOnly = SPECIFIC_ONLY_FILE.test(filePath);
    return allRules.filter(rule =>
      rule.fileTypes.some(type => {
        if (type.startsWith('.env')) return isEnvFile;
        if (type.includes('*')) return globToRegExp(type).test(toRelativePath(filePath, this.rootDir));
        if (specificOnly && GENERIC_FILE_TYPES.has(type)) return false;
        return filePath.endsWith(type);
      })
    );
  }
}
