#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora, { Ora } from 'ora';
import boxen from 'boxen';
import gradient from 'gradient-string';
import { RuleEngine } from '../core/ruleEngine.js';
import { Reporter } from '../core/reporter.js';
import { HtmlReporter } from '../core/htmlReporter.js';
import { storageRules } from '../scanners/storageScanner.js';
import { networkRules } from '../scanners/networkScanner.js';
import { loggingRules } from '../scanners/loggingScanner.js';
import { configRules } from '../scanners/configScanner.js';
import { manifestRules } from '../scanners/manifestScanner.js';
import { authenticationRules } from '../scanners/authenticationScanner.js';
import { cryptoRules } from '../scanners/cryptoScanner.js';
import { reactNativeRules } from '../scanners/reactNativeScanner.js';
import { webviewRules } from '../scanners/webviewScanner.js';
import { secretsRules } from '../scanners/secretsScanner.js';
import { debugRules } from '../scanners/debugScanner.js';
import { androidRules } from '../scanners/androidScanner.js';
import { iosRules } from '../scanners/iosScanner.js';
import { npmVulnerabilityRules, setNpmScannerConfig } from '../scanners/npmScanner.js';
import type { ScanResult } from '../types/findings.js';
import { VERSION, DEFAULT_REPORT_FILENAMES, EXIT_CODES } from '../constants.js';
import { readRnsecConfig } from '../utils/fileUtils.js';

const securityGradient = gradient(['#ff0000', '#ff6b6b', '#ff8888']);

const program = new Command();

interface ScanOptions {
  path: string;
  json?: boolean;
  html?: string;
  output?: string;
  silent?: boolean;
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
  .action(async (options: ScanOptions) => {
    try {
      const targetPath = options.path;
      
      if (!options.silent && !options.json) {
        printBanner();
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
      
      // Pass config to npm scanner
      setNpmScannerConfig(config);
      
      if (config?.ignoredRules) {
        engine.setIgnoredRules(config.ignoredRules);
        if (config.ignoredRules.length > 0 && !options.silent) {
          console.log(chalk.yellow(`ℹ Ignoring ${config.ignoredRules.length} rule(s): ${config.ignoredRules.join(', ')}`));
        }
      }
      
      // Show npm scanning status
      if (config?.npmVulnerabilityScanning?.enabled === false && !options.silent) {
        console.log(chalk.yellow('ℹ NPM vulnerability scanning is disabled'));
      }

      registerAllRules(engine);

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

      const scanResult = await engine.runRulesOnProject(targetPath, (progress) => {
        if (spinner) {
          spinner.text = chalk.cyan(`Scanning: ${progress.current}/${progress.total} files`);
        }
      });

      const duration = Date.now() - startTime;

      if (spinner) {
        spinner.succeed(chalk.green(`Scan completed in ${(duration / 1000).toFixed(2)}s`));
      }
      
      // Show skipped files warning if any
      if (scanResult.skippedFiles && scanResult.skippedFiles > 0 && !options.silent) {
        console.log(chalk.yellow(`⚠️  ${scanResult.skippedFiles} file(s) skipped due to read errors (use RNSEC_VERBOSE=1 for details)`));
      }

      const result: ScanResult = {
        findings: scanResult.findings,
        scannedFiles: scanResult.scannedFiles,
        duration,
        timestamp: new Date(),
        ignoredRules: engine.getIgnoredRules(),
      };

      const htmlPath = options.html || (!options.json ? DEFAULT_REPORT_FILENAMES.HTML : null);
      const jsonPath = options.output || (!options.json ? DEFAULT_REPORT_FILENAMES.JSON : null);

      const generatedReports: { html?: string; json?: string } = {};

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

      const reporter = new Reporter({
        json: options.json,
        silent: options.silent,
        generatedReports,
      });

      reporter.report(result);

      const highSeverityCount = result.findings.filter(f => f.severity === 'HIGH').length;
      if (highSeverityCount > 0) {
        process.exit(EXIT_CODES.HIGH_SEVERITY_FOUND);
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

