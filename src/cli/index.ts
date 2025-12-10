#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
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
import type { ScanResult } from '../types/findings.js';

const securityGradient = gradient(['#ff0000', '#ff6b6b', '#ff8888']);

const program = new Command();

program
  .name('rnsec')
  .description('🔍 React Native & Expo Security Scanner')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan the project for security issues')
  .option('-p, --path <path>', 'Path to project root', '.')
  .option('--json', 'Output results as JSON')
  .option('--html <filename>', 'Generate HTML report (e.g., report.html)')
  .option('--output <filename>', 'Save JSON results to file')
  .option('--silent', 'Suppress console output')
  .action(async (options) => {
    try {
      const targetPath = options.path as string;
      
      if (!options.silent && !options.json) {
        printBanner();
      }

      const engine = new RuleEngine();
      
      let spinner: any;
      if (!options.silent && !options.json) {
        spinner = ora({
          text: chalk.cyan('Initializing security scanner...'),
          spinner: 'dots12',
        }).start();
      }

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

      const findings = await engine.runRulesOnProject(targetPath, (progress) => {
        if (spinner) {
          spinner.text = chalk.cyan(`Scanning: ${progress.current}/${progress.total} files`);
        }
      });

      const duration = Date.now() - startTime;

      if (spinner) {
        spinner.succeed(chalk.green(`Scan completed in ${(duration / 1000).toFixed(2)}s`));
      }

      const result: ScanResult = {
        findings,
        scannedFiles: 0,
        duration,
        timestamp: new Date(),
      };

      const htmlPath = options.html || (!options.json ? 'rnsec-report.html' : null);
      const jsonPath = options.output || (!options.json ? 'rnsec-report.json' : null);

      let generatedReports: { html?: string; json?: string } = {};

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

      const highSeverityCount = findings.filter(f => f.severity === 'HIGH').length;
      if (highSeverityCount > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('\n❌ Error during scan:'), error);
      process.exit(1);
    }
  });

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
  .command('rules')
  .description('List all available security rules')
  .action(() => {
    const engine = new RuleEngine();
    
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

