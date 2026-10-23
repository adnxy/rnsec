#!/usr/bin/env node

import { Command } from 'commander';
import { resolve } from 'path';
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
import { Severity } from '../types/findings.js';
import type { ScanResult, Finding, Confidence } from '../types/findings.js';
import { VERSION, DEFAULT_REPORT_FILENAMES, EXIT_CODES } from '../constants.js';
import { readRnsecConfig } from '../utils/fileUtils.js';
import { getChangedFiles, isGitRepository } from '../utils/gitUtils.js';

const securityGradient = gradient(['#ff0000', '#ff6b6b', '#ff8888']);

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
 * Informational messages. With --json, stdout must stay pure JSON, so they go to stderr.
 */
function info(message: string, json?: boolean): void {
  (json ? console.error : console.log)(message);
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

type FailOn = 'high' | 'medium' | 'low' | 'none';

// Severities that make the scan fail for each --fail-on level
const FAIL_ON_SEVERITIES: Record<FailOn, Severity[]> = {
  high: [Severity.HIGH],
  medium: [Severity.HIGH, Severity.MEDIUM],
  low: [Severity.HIGH, Severity.MEDIUM, Severity.LOW],
  none: [],
};

function parseFailOn(value: string | undefined, source: string): FailOn | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'string' && value in FAIL_ON_SEVERITIES) return value as FailOn;
  fatal(`${source} must be high, medium, low or none (got "${value}")`);
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
    fatal('"severityOverrides" in the config must be an object of { "RULE_ID": "HIGH" | "MEDIUM" | "LOW" }', spinner);
  }
  for (const [ruleId, value] of Object.entries(raw as Record<string, unknown>)) {
    const severity = typeof value === 'string' ? value.toUpperCase() : '';
    if (severity !== Severity.HIGH && severity !== Severity.MEDIUM && severity !== Severity.LOW) {
      fatal(`severityOverrides["${ruleId}"] must be HIGH, MEDIUM or LOW (got ${JSON.stringify(value)})`, spinner);
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

program
  .name('rnsec')
  .description('🔍 React Native & Expo Security Scanner')
  .version(VERSION);

program
  .command('scan')
  .description('Scan the project for security issues')
  .option('-p, --path <path>', 'Path to project root', '.')
  .option('--json', 'Output results as JSON')
  .option('--html <filename>', 'Generate HTML report (e.g., report.html)')
  .option('--output <filename>', 'Save JSON results to file')
  .option('--silent', 'Suppress console output')
  .option('--changed-files <ref>', 'Scan only files changed since git reference (branch, commit, or tag)')
  .option('--md <filename>', 'Generate Markdown report for PR comments (e.g., security-report.md)')
  .option('--min-confidence <level>', 'Only report findings at or above this confidence (low, medium, high)', 'low')
  .option('--fail-on <level>', 'Exit with code 1 when a finding at or above this severity is reported (high, medium, low, none)')
  .option('--sarif <filename>', 'Generate a SARIF 2.1.0 report (e.g., rnsec.sarif)')
  .option('--baseline <filename>', 'Ignore findings listed in this baseline file')
  .option('--write-baseline <filename>', 'Write the current findings to a baseline file and exit 0')
  .option('--no-gitignore', 'Also scan files that git ignores')
  .action(async (options: ScanOptions) => {
    try {
      const targetPath = options.path;
      const cliFailOn = parseFailOn(options.failOn, '--fail-on');
      
      if (!options.silent && !options.json) {
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
          info(chalk.cyan(`Scanning files changed since: ${options.changedFiles}`), options.json);
        }
      }

      const engine = new RuleEngine();
      
      let spinner: Ora | null = null;
      if (!options.silent && !options.json) {
        spinner = ora({
          text: chalk.cyan('Initializing security scanner...'),
          spinner: 'dots12',
        }).start();
      }

      // Load configuration
      const config = await readRnsecConfig(targetPath);
      
      const failOn: FailOn = cliFailOn ?? parseFailOn(config?.failOn, '"failOn" in the config') ?? 'high';
      const severityOverrides = parseSeverityOverrides(config?.severityOverrides, spinner);
      const baselinePath = options.baseline ?? (config?.baseline ? resolve(targetPath, config.baseline) : undefined);

      // Pass config to npm scanner
      setNpmScannerConfig(config);
      
      if (config?.ignoredRules) {
        engine.setIgnoredRules(config.ignoredRules);
        if (config.ignoredRules.length > 0 && !options.silent) {
          info(chalk.yellow(`ℹ Ignoring ${config.ignoredRules.length} rule(s): ${config.ignoredRules.join(', ')}`), options.json);
        }
      }

      if (config?.exclude) {
        engine.setExcludedPaths(config.exclude);
        if (config.exclude.length > 0 && !options.silent) {
          info(chalk.yellow(`ℹ Excluding ${config.exclude.length} path(s): ${config.exclude.join(', ')}`), options.json);
        }
      }
      
      // Show npm scanning status
      if (config?.npmVulnerabilityScanning?.enabled === false && !options.silent) {
        info(chalk.yellow('ℹ NPM vulnerability scanning is disabled'), options.json);
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

      let scanResult: { findings: Finding[]; scannedFiles: number; skippedFiles?: number; suppressedCount?: number; unverifiedFiles?: number };

      if (options.changedFiles) {
        const changedFiles = await getChangedFiles(options.changedFiles, targetPath);

        if (changedFiles.length === 0) {
          if (!options.silent) {
            info(chalk.yellow('No files changed since the specified reference.'), options.json);
          }
          scanResult = { findings: [], scannedFiles: 0 };
        } else {
          if (!options.silent) {
            info(chalk.cyan(`📁 Found ${changedFiles.length} changed file(s) to scan`), options.json);
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
        info(chalk.yellow(`⚠️  ${scanResult.skippedFiles} file(s) skipped due to read errors (use RNSEC_VERBOSE=1 for details)`), options.json);
      }

      // Always stderr, so --json stdout stays pure JSON
      if (scanResult.unverifiedFiles && !options.silent) {
        console.error(chalk.yellow(`Note: ${scanResult.unverifiedFiles} file(s) (.env, credential or registry config) were not checked: ${resolve(targetPath)} is not a git repository and rnsec only reports these when git tracks them.`));
      }

      const minConfidence = parseMinConfidence(options.minConfidence);
      const repoRoot = await resolveRepoRoot(targetPath);
      // Fingerprint the full set so occurrence indices don't depend on --min-confidence
      assignFingerprints(scanResult.findings, repoRoot);
      for (const f of scanResult.findings) {
        const override = severityOverrides[f.ruleId];
        if (override) f.severity = override;
      }

      let findings = scanResult.findings.filter(f => CONFIDENCE_RANK[f.confidence ?? 'high'] >= CONFIDENCE_RANK[minConfidence]);

      if (options.writeBaseline) {
        await writeBaseline(options.writeBaseline, findings, repoRoot);
        info(chalk.green(`Baseline with ${findings.length} finding(s) written to ${resolve(options.writeBaseline)}`), options.json);
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
          info(chalk.yellow(`ℹ ${baselinedCount} finding(s) hidden by baseline ${baselinePath}`), options.json);
        }
      }

      const result: ScanResult = {
        findings,
        suppressedCount: scanResult.suppressedCount,
        baselinedCount: baselinedCount > 0 ? baselinedCount : undefined,
        scannedFiles: scanResult.scannedFiles,
        duration,
        timestamp: new Date(),
        ignoredRules: engine.getIgnoredRules(),
      };

      const htmlPath = options.html || (!options.json ? DEFAULT_REPORT_FILENAMES.HTML : null);
      const jsonPath = options.output || (!options.json ? DEFAULT_REPORT_FILENAMES.JSON : null);
      const mdPath = options.md;

      const generatedReports: { html?: string; json?: string; md?: string; sarif?: string } = {};

      if (htmlPath && !options.json) {
        const htmlReporter = new HtmlReporter();
        const { resolve } = await import('path');
        const absolutePath = resolve(htmlPath);
        await htmlReporter.generateReport(result, htmlPath);
        generatedReports.html = absolutePath;
      }

      if (jsonPath && !options.json) {
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

      if (options.sarif) {
        await new SarifReporter().writeReport(options.sarif, result.findings, engine.getAllRules(), { repoRoot, severityOverrides });
        generatedReports.sarif = resolve(options.sarif);
      }

      const reporter = new Reporter({
        json: options.json,
        silent: options.silent,
        generatedReports,
      });

      reporter.report(result);

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
  .action(() => {
    const engine = new RuleEngine();
    
    registerAllRules(engine);

    const rules = engine.getAllRules();
    const reporter = new Reporter();
    
    reporter.listRules(
      rules.map(r => ({
        id: r.id,
        description: r.description,
        severity: r.severity,
      }))
    );
  });

program.parse(process.argv);

