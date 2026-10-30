#!/usr/bin/env node

import { Command, CommanderError } from 'commander';
import { resolve } from 'path';
import { existsSync, statSync } from 'fs';
import chalk from 'chalk';
import ora, { Ora } from 'ora';
import boxen from 'boxen';
import gradient from 'gradient-string';
import { RuleEngine } from '../core/ruleEngine.js';
import { Reporter } from '../core/reporter.js';
import { HtmlReporter } from '../core/htmlReporter.js';
import { MarkdownReporter } from '../core/markdownReporter.js';
import { storageRules } from '../scanners/security/storageScanner.js';
import { networkRules } from '../scanners/security/networkScanner.js';
import { loggingRules } from '../scanners/security/loggingScanner.js';
import { configRules } from '../scanners/security/configScanner.js';
import { manifestRules } from '../scanners/android/manifestScanner.js';
import { authenticationRules } from '../scanners/security/authenticationScanner.js';
import { cryptoRules } from '../scanners/security/cryptoScanner.js';
import { reactNativeRules } from '../scanners/react-native/reactNativeScanner.js';
import { webviewRules } from '../scanners/security/webviewScanner.js';
import { secretsRules } from '../scanners/security/secretsScanner.js';
import { debugRules } from '../scanners/security/debugScanner.js';
import { androidRules } from '../scanners/android/androidScanner.js';
import { iosRules } from '../scanners/ios/iosScanner.js';
import { npmVulnerabilityRules, setNpmScannerConfig } from '../scanners/modules/npmScanner.js';
import { rnSecurityRules } from '../scanners/security/rnSecurityScanner.js';
import { dependencySourceRules } from '../scanners/modules/dependencySourceScanner.js';
import { networkSecurityConfigRules } from '../scanners/android/networkSecurityConfigScanner.js';
import { iosPlistExtraRules } from '../scanners/ios/iosPlistExtraScanner.js';
import { rnExtraRules } from '../scanners/security/rnExtraScanner.js';
import { expoConfigRules } from '../scanners/security/expoConfigScanner.js';
import { gradleRules } from '../scanners/android/gradleScanner.js';
import { registryConfigRules } from '../scanners/modules/registryConfigScanner.js';
import { credentialFileRules } from '../scanners/security/credentialFilesScanner.js';
import { SarifReporter } from '../core/sarifReporter.js';
import { assignFingerprints, readBaseline, resolveRepoRoot, writeBaseline } from '../core/baseline.js';
import { Severity, SEVERITY_ORDER } from '../types/findings.js';
import type { ScanResult, Finding, Confidence, RuleError } from '../types/findings.js';
import { VERSION, DEFAULT_REPORT_FILENAMES, EXIT_CODES } from '../constants.js';
import { readRnsecConfig } from '../utils/fileUtils.js';
import { getChangedFiles, isGitRepository } from '../utils/gitUtils.js';
import { enrichFindings, getRuleStandards } from '../standards/owasp/index.js';
import { buildCoverage, detectProjectPlatforms } from '../standards/owasp/coverage.js';

const securityGradient = gradient(['#ff0000', '#ff6b6b', '#ff8888']);

// `rnsec scan --format json | head` closes the pipe early. That is the reader's choice, not a scan failure:
// stop quietly and keep the exit code the scan already decided (0 or 1), instead of an EPIPE stack trace.
process.stdout.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EPIPE') process.exit(process.exitCode ?? EXIT_CODES.SUCCESS);
  throw err;
});

const program = new Command();

interface ScanOptions {
  path: string;
  json?: boolean;
  html?: string;
  output?: string;
  silent?: boolean;
  changedFiles?: string;
  md?: string;
  minConfidence?: string;
  failOn?: string;
  sarif?: string;
  baseline?: string;
  writeBaseline?: string;
  gitignore?: boolean;
  format?: string;
  owasp?: boolean;
}

/**
 * Registers all security rule groups with the rule engine
 */
function registerAllRules(engine: RuleEngine): void {
  engine.registerRuleGroup(storageRules);
  engine.registerRuleGroup(networkRules);
  engine.registerRuleGroup(loggingRules);
  engine.registerRuleGroup(configRules);
  engine.registerRuleGroup(manifestRules);
  engine.registerRuleGroup(authenticationRules);
  engine.registerRuleGroup(cryptoRules);
  engine.registerRuleGroup(reactNativeRules);
  engine.registerRuleGroup(webviewRules);
  engine.registerRuleGroup(secretsRules);
  engine.registerRuleGroup(debugRules);
  engine.registerRuleGroup(androidRules);
  engine.registerRuleGroup(iosRules);
  engine.registerRuleGroup(npmVulnerabilityRules);
  engine.registerRuleGroup(rnSecurityRules);
  engine.registerRuleGroup(dependencySourceRules);
  engine.registerRuleGroup(networkSecurityConfigRules);
  engine.registerRuleGroup(iosPlistExtraRules);
  engine.registerRuleGroup(rnExtraRules);
  engine.registerRuleGroup(expoConfigRules);
  engine.registerRuleGroup(gradleRules);
  engine.registerRuleGroup(registryConfigRules);
  engine.registerRuleGroup(credentialFileRules);
}

/**
 * Informational messages. When stdout carries a machine-readable report (--json, --format json|sarif),
 * it must stay pure, so they go to stderr.
 */
function info(message: string, machine?: boolean): void {
  (machine ? console.error : console.log)(message);
}

/** Ids of every registered rule, including ones disabled via ignoredRules */
function allRuleIds(): Set<string> {
  const engine = new RuleEngine();
  registerAllRules(engine);
  return new Set(engine.getAllRules().map(r => r.id));
}

const CONFIDENCE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

function parseMinConfidence(value: string | undefined): Confidence {
  if (value === 'low' || value === 'medium' || value === 'high') return value;
  if (value !== undefined) {
    console.error(chalk.red(`Error: --min-confidence must be low, medium or high (got "${value}")`));
    process.exit(EXIT_CODES.ERROR);
  }
  return 'low';
}

type FailOn = 'critical' | 'high' | 'medium' | 'low' | 'none';

// Severities that make the scan fail for each --fail-on level: the level itself and everything above it
const FAIL_ON_SEVERITIES: Record<FailOn, Severity[]> = {
  critical: SEVERITY_ORDER.slice(0, 1),
  high: SEVERITY_ORDER.slice(0, 2),
  medium: SEVERITY_ORDER.slice(0, 3),
  low: SEVERITY_ORDER.slice(0, 4),
  none: [],
};

type OutputFormat = 'console' | 'json' | 'sarif';

/**
 * --format selects what stdout carries: the console report (default), JSON (same as --json) or SARIF 2.1.0.
 * json and sarif are machine formats: no banner/spinner, no default report files, notes go to stderr.
 */
function parseFormat(format: string | undefined, json: boolean | undefined): OutputFormat {
  if (format !== undefined && format !== 'console' && format !== 'json' && format !== 'sarif') {
    fatal(`--format must be json, sarif or console (got "${format}")`);
  }
  if (json && format !== undefined && format !== 'json') {
    fatal(`--json cannot be combined with --format ${format}`);
  }
  return json ? 'json' : (format as OutputFormat | undefined) ?? 'console';
}

/** Findings in a stable order: file, line, column, rule, description (plain comparison, not locale-aware) */
function compareFindings(a: Finding, b: Finding): number {
  const cmp = (x: string | number, y: string | number) => (x < y ? -1 : x > y ? 1 : 0);
  return (
    cmp(a.filePath, b.filePath) ||
    cmp(a.line ?? 0, b.line ?? 0) ||
    cmp(a.column ?? 0, b.column ?? 0) ||
    cmp(a.ruleId, b.ruleId) ||
    cmp(a.description, b.description)
  );
}

function parseFailOn(value: string | undefined, source: string): FailOn | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'string' && value in FAIL_ON_SEVERITIES) return value as FailOn;
  fatal(`${source} must be critical, high, medium, low or none (got "${value}")`);
}

function fatal(message: string, spinner?: Ora | null): never {
  spinner?.stop();
  console.error(chalk.red(`Error: ${message}`));
  process.exit(EXIT_CODES.ERROR);
}

/** Validates the `severityOverrides` config and returns it with normalized severities */
function parseSeverityOverrides(raw: unknown, spinner?: Ora | null): Record<string, Severity> {
  const overrides: Record<string, Severity> = {};
  if (raw === undefined || raw === null) return overrides;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    fatal('"severityOverrides" in the config must be an object of { "RULE_ID": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" }', spinner);
  }
  for (const [ruleId, value] of Object.entries(raw as Record<string, unknown>)) {
    const severity = typeof value === 'string' ? value.toUpperCase() : '';
    if (!SEVERITY_ORDER.includes(severity as Severity)) {
      fatal(`severityOverrides["${ruleId}"] must be CRITICAL, HIGH, MEDIUM or LOW (got ${JSON.stringify(value)})`, spinner);
    }
    overrides[ruleId] = severity as Severity;
  }
  return overrides;
}

/**
 * Prints the application banner
 */
function printBanner(): void {
  console.log('\n');
  const banner = securityGradient('█████╗ ███╗   ██╗███████╗███████╗ ██████╗\n██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝\n██████╔╝██╔██╗ ██║███████╗█████╗  ██║     \n██╔══██╗██║╚██╗██║╚════██║██╔══╝  ██║     \n██║  ██║██║ ╚████║███████║███████╗╚██████╗\n╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝');
  
  const box = boxen(banner, {
    padding: 1,
    margin: { top: 0, bottom: 0, left: 2, right: 2 },
    borderStyle: 'round',
    borderColor: 'red',
    backgroundColor: '#000000',
  });
  
  console.log(box);
  console.log(chalk.white.bold('  React Native & Expo Security Scanner'));
  console.log(chalk.gray('  Professional-grade static analysis tool\n'));
}

// Before any .command(): subcommands copy this setting when they are created
program.exitOverride();

program
  .name('rnsec')
  .description('🔍 React Native & Expo Security Scanner')
  .version(VERSION);

program
  .command('scan')
  .description('Scan the project for security issues')
  .option('-p, --path <path>', 'Path to project root', '.')
  .option('--json', 'Output results as JSON')
  .option('--format <format>', 'What stdout carries: console (default), json (same as --json) or sarif (SARIF 2.1.0; notes go to stderr). json and sarif skip the default HTML/JSON report files')
  .option('--html <filename>', 'Generate HTML report (e.g., report.html)')
  .option('--output <filename>', 'Save JSON results to file (console format only; with --json or --format the JSON is on stdout)')
  .option('--silent', 'Suppress console output')
  .option('--changed-files <ref>', 'Scan only files changed since git reference (branch, commit, or tag)')
  .option('--md <filename>', 'Generate Markdown report for PR comments (e.g., security-report.md)')
  .option('--min-confidence <level>', 'Only report findings at or above this confidence (low, medium, high)', 'low')
  .option('--fail-on <level>', 'Exit with code 1 when a finding at or above this severity is reported (critical, high, medium, low, none; default high, which includes critical)')
  .option('--sarif <filename>', 'Write a SARIF 2.1.0 report to a file (e.g., rnsec.sarif); also written with --format sarif')
  .option('--owasp', 'Add OWASP MASVS/MASWE/MASTG/CWE data to findings and a MASVS coverage section (static analysis only)')
  .option('--baseline <filename>', 'Ignore findings listed in this baseline file')
  .option('--write-baseline <filename>', 'Write the current findings to a baseline file and exit 0')
  .option('--no-gitignore', 'Also scan files that git ignores')
  .action(async (options: ScanOptions) => {
    try {
      const targetPath = options.path;
      const cliFailOn = parseFailOn(options.failOn, '--fail-on');
      const format = parseFormat(options.format, options.json);
      const machine = format !== 'console';

      // A mistyped path must not look like a clean scan of zero files
      if (!existsSync(targetPath) || !statSync(targetPath).isDirectory()) {
        fatal(`--path "${targetPath}" is not a directory`);
      }
      
      if (!options.silent && !machine) {
        printBanner();
      }

      // Handle --changed-files option
      if (options.changedFiles) {
        if (options.changedFiles.startsWith('-')) {
          console.error(chalk.red(`Error: invalid --changed-files reference "${options.changedFiles}": it must not start with "-"`));
          process.exit(EXIT_CODES.ERROR);
        }

        const isGitRepo = await isGitRepository(targetPath);
        if (!isGitRepo) {
          console.error(chalk.red('Error: --changed-files option requires a git repository'));
          process.exit(EXIT_CODES.ERROR);
        }

        if (!options.silent) {
          info(chalk.cyan(`Scanning files changed since: ${options.changedFiles}`), machine);
        }
      }

      const engine = new RuleEngine();
      
      let spinner: Ora | null = null;
      if (!options.silent && !machine) {
        spinner = ora({
          text: chalk.cyan('Initializing security scanner...'),
          spinner: 'dots12',
        }).start();
      }

      // Load configuration
      const config = await readRnsecConfig(targetPath);
      
      const failOn: FailOn = cliFailOn ?? parseFailOn(config?.failOn, '"failOn" in the config') ?? 'high';
      const severityOverrides = parseSeverityOverrides(config?.severityOverrides, spinner);
      if (config?.owasp !== undefined && typeof config.owasp !== 'boolean') {
        fatal('"owasp" in the config must be true or false', spinner);
      }
      const owasp = options.owasp === true || config?.owasp === true;
      const baselinePath = options.baseline ?? (config?.baseline ? resolve(targetPath, config.baseline) : undefined);

      // Pass config to npm scanner
      setNpmScannerConfig(config);
      
      if (config?.ignoredRules) {
        engine.setIgnoredRules(config.ignoredRules);
        if (config.ignoredRules.length > 0 && !options.silent) {
          info(chalk.yellow(`ℹ Ignoring ${config.ignoredRules.length} rule(s): ${config.ignoredRules.join(', ')}`), machine);
        }
      }

      if (config?.exclude) {
        engine.setExcludedPaths(config.exclude);
        if (config.exclude.length > 0 && !options.silent) {
          info(chalk.yellow(`ℹ Excluding ${config.exclude.length} path(s): ${config.exclude.join(', ')}`), machine);
        }
      }
      
      // Show npm scanning status
      if (config?.npmVulnerabilityScanning?.enabled === false && !options.silent) {
        info(chalk.yellow('ℹ NPM vulnerability scanning is disabled'), machine);
      }

      engine.setRespectGitignore(options.gitignore !== false && config?.respectGitignore !== false);

      registerAllRules(engine);

      const unknownOverrides = Object.keys(severityOverrides).filter(
        id => !allRuleIds().has(id)
      );
      if (unknownOverrides.length > 0) {
        console.error(chalk.yellow(`⚠️  severityOverrides lists unknown rule id(s): ${unknownOverrides.join(', ')}`));
      }

      if (spinner) {
        spinner.succeed(chalk.green('Security rules loaded'));
        spinner = ora({
          text: chalk.cyan('Discovering project files...'),
          spinner: 'dots12',
        }).start();
      }

      const startTime = Date.now();

      if (spinner) {
        spinner.text = chalk.cyan('Analyzing source code...');
      }

      let scanResult: { findings: Finding[]; scannedFiles: number; skippedFiles?: number; suppressedCount?: number; unverifiedFiles?: number; ruleErrors?: RuleError[]; parseFailures?: number };

      if (options.changedFiles) {
        const changedFiles = await getChangedFiles(options.changedFiles, targetPath);

        if (changedFiles.length === 0) {
          if (!options.silent) {
            info(chalk.yellow('No files changed since the specified reference.'), machine);
          }
          scanResult = { findings: [], scannedFiles: 0 };
        } else {
          if (!options.silent) {
            info(chalk.cyan(`📁 Found ${changedFiles.length} changed file(s) to scan`), machine);
          }
          scanResult = await engine.runRulesOnFiles(changedFiles, (progress) => {
            if (spinner) {
              spinner.text = chalk.cyan(`Scanning: ${progress.current}/${progress.total} files`);
            }
          }, targetPath);
        }
      } else {
        scanResult = await engine.runRulesOnProject(targetPath, (progress) => {
          if (spinner) {
            spinner.text = chalk.cyan(`Scanning: ${progress.current}/${progress.total} files`);
          }
        });
      }

      const duration = Date.now() - startTime;

      if (spinner) {
        spinner.succeed(chalk.green(`Scan completed in ${(duration / 1000).toFixed(2)}s`));
      }
      
      // Show skipped files warning if any
      if (scanResult.skippedFiles && scanResult.skippedFiles > 0 && !options.silent) {
        info(chalk.yellow(`⚠️  ${scanResult.skippedFiles} file(s) skipped due to read errors (use RNSEC_VERBOSE=1 for details)`), machine);
      }

      // Always stderr, so --json stdout stays pure JSON
      if (scanResult.unverifiedFiles && !options.silent) {
        console.error(chalk.yellow(`Note: ${scanResult.unverifiedFiles} file(s) (.env, credential or registry config) were not checked: ${resolve(targetPath)} is not a git repository and rnsec only reports these when git tracks them.`));
      }

      // Always stderr (stdout stays pure), even with --silent: a rule that crashed means a result that is not complete
      const ruleErrors = scanResult.ruleErrors ?? [];
      const parseFailures = scanResult.parseFailures ?? 0;
      if (ruleErrors.length > 0 || parseFailures > 0) {
        const parts = [
          ruleErrors.length > 0 ? `${ruleErrors.length} rule error(s) in ${[...new Set(ruleErrors.map(e => e.ruleId))].join(', ')}` : '',
          parseFailures > 0 ? `${parseFailures} file(s) failed to parse` : '',
        ].filter(Boolean);
        console.error(chalk.yellow(`⚠️  Scan incomplete: ${parts.join('; ')} (details in the JSON report, or run with RNSEC_VERBOSE=1)`));
      }

      scanResult.findings.sort(compareFindings);
      const minConfidence = parseMinConfidence(options.minConfidence);
      const repoRoot = await resolveRepoRoot(targetPath);
      // Fingerprint the full set so occurrence indices don't depend on --min-confidence
      assignFingerprints(scanResult.findings, repoRoot);
      for (const f of scanResult.findings) {
        const override = severityOverrides[f.ruleId];
        if (override) f.severity = override;
      }

      const meetsConfidence = (f: Finding) => CONFIDENCE_RANK[f.confidence ?? 'high'] >= CONFIDENCE_RANK[minConfidence];
      let findings = scanResult.findings.filter(meetsConfidence);

      if (options.writeBaseline) {
        await writeBaseline(options.writeBaseline, findings, repoRoot);
        info(chalk.green(`Baseline with ${findings.length} finding(s) written to ${resolve(options.writeBaseline)}`), machine);
      }

      let baselinedCount = 0;
      if (baselinePath) {
        let known: Set<string>;
        try {
          known = await readBaseline(baselinePath);
        } catch (error) {
          fatal(error instanceof Error ? error.message : String(error));
        }
        const remaining = findings.filter(f => !known.has(f.fingerprint!));
        baselinedCount = findings.length - remaining.length;
        findings = remaining;
        if (baselinedCount > 0 && !options.silent) {
          info(chalk.yellow(`ℹ ${baselinedCount} finding(s) hidden by baseline ${baselinePath}`), machine);
        }
      }

      let owaspReport: ScanResult['owasp'];
      if (owasp) {
        enrichFindings(findings);
        // npm rules that the config switched off did not run; neither did ignored ones (getAllRules skips those)
        const notRun = new Set(
          config?.npmVulnerabilityScanning?.enabled === false ? npmVulnerabilityRules.rules.map(r => r.id) : []
        );
        owaspReport = buildCoverage({
          findings,
          ranRuleIds: engine.getAllRules().map(r => r.id).filter(id => !notRun.has(id)),
          hiddenRuleIds: scanResult.findings.filter(f => !meetsConfidence(f)).map(f => f.ruleId),
          platforms: detectProjectPlatforms(resolve(targetPath)),
          scope: options.changedFiles ? 'changed-files' : 'project',
        });
      }

      const result: ScanResult = {
        findings,
        suppressedCount: scanResult.suppressedCount,
        baselinedCount: baselinedCount > 0 ? baselinedCount : undefined,
        ...(ruleErrors.length > 0 ? { ruleErrors } : {}),
        ...(parseFailures > 0 ? { parseFailures } : {}),
        scannedFiles: scanResult.scannedFiles,
        duration,
        timestamp: new Date(),
        ignoredRules: engine.getIgnoredRules(),
        ...(owaspReport ? { owasp: owaspReport } : {}),
      };

      const htmlPath = options.html || (!machine ? DEFAULT_REPORT_FILENAMES.HTML : null);
      const jsonPath = options.output || (!machine ? DEFAULT_REPORT_FILENAMES.JSON : null);
      const mdPath = options.md;

      const generatedReports: { html?: string; json?: string; md?: string; sarif?: string } = {};

      if (htmlPath && !machine) {
        const htmlReporter = new HtmlReporter();
        const { resolve } = await import('path');
        const absolutePath = resolve(htmlPath);
        await htmlReporter.generateReport(result, htmlPath);
        generatedReports.html = absolutePath;
      }

      if (jsonPath && !machine) {
        const fs = await import('fs/promises');
        const { resolve } = await import('path');
        const absolutePath = resolve(jsonPath);
        await fs.writeFile(jsonPath, JSON.stringify(result, null, 2));
        generatedReports.json = absolutePath;
      }

      if (mdPath) {
        const markdownReporter = new MarkdownReporter();
        const fs = await import('fs/promises');
        const { resolve } = await import('path');
        const absolutePath = resolve(mdPath);
        const markdownContent = markdownReporter.generateReport(result);
        await fs.writeFile(absolutePath, markdownContent);
        generatedReports.md = absolutePath;
      }

      // One document for stdout (--format sarif) and the --sarif file, so they are identical
      let sarifText: string | undefined;
      if (options.sarif || format === 'sarif') {
        sarifText = new SarifReporter().render(result.findings, engine.getAllRules(), { repoRoot, severityOverrides });
      }
      if (options.sarif) {
        const fs = await import('fs/promises');
        await fs.writeFile(options.sarif, sarifText!);
        generatedReports.sarif = resolve(options.sarif);
      }

      if (format === 'sarif') {
        process.stdout.write(sarifText!);
      } else {
        new Reporter({
          json: format === 'json',
          silent: options.silent,
          generatedReports,
        }).report(result);
      }

      const failing = result.findings.filter(f => FAIL_ON_SEVERITIES[failOn].includes(f.severity)).length;
      if (failing > 0 && !options.writeBaseline) {
        // Set the code instead of exiting: process.exit() can cut off piped stdout (e.g. large --json output)
        process.exitCode = EXIT_CODES.HIGH_SEVERITY_FOUND;
      }
    } catch (error) {
      console.error(chalk.red('\n❌ Error during scan:'), error);
      process.exit(EXIT_CODES.ERROR);
    }
  });

program
  .command('rules')
  .description('List all available security rules')
  .option('--owasp', 'Show each rule with its OWASP MASVS and MASWE ids')
  .action((options: { owasp?: boolean }) => {
    const engine = new RuleEngine();
    
    registerAllRules(engine);

    const rules = engine.getAllRules();
    const reporter = new Reporter();

    if (options.owasp) {
      const byId = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
      reporter.listRulesOwasp(
        rules
          .map(r => {
            const s = getRuleStandards(r.id);
            return { id: r.id, title: s?.title ?? r.description, severity: r.severity, masvs: s?.masvs ?? [], maswe: s?.maswe ?? [] };
          })
          .sort((a, b) => byId(a.id, b.id))
      );
      return;
    }
    
    reporter.listRules(
      rules.map(r => ({
        id: r.id,
        description: r.description,
        severity: r.severity,
      }))
    );
  });

// Usage errors from commander (unknown option, missing value) are exit 2 like every other error;
// --help and --version stay 0
program.parseAsync(process.argv).catch(error => {
  if (error instanceof CommanderError) {
    process.exitCode = error.exitCode === 0 ? EXIT_CODES.SUCCESS : EXIT_CODES.ERROR;
    return;
  }
  console.error(chalk.red('\n❌ Error:'), error);
  process.exit(EXIT_CODES.ERROR);
});

