import chalk from 'chalk';
import boxen from 'boxen';
import gradient from 'gradient-string';
import type { Finding, Severity, ScanResult } from '../types/findings.js';

export interface ReporterOptions {
  json?: boolean;
  silent?: boolean;
  generatedReports?: {
    html?: string;
    json?: string;
  };
}

const securityGradient = gradient(['#ff0000', '#ff6b6b']);
const successGradient = gradient(['#00ff00', '#00cc00']);
const warningGradient = gradient(['#ffaa00', '#ff8800']);

export class Reporter {
  private options: ReporterOptions;

  constructor(options: ReporterOptions = {}) {
    this.options = options;
  }

  report(result: ScanResult): void {
    if (this.options.json) {
      this.reportJson(result);
      return;
    }

    if (this.options.silent) {
      return;
    }

    if (result.findings.length > 40) {
      this.reportCompact(result);
    } else {
      this.reportPretty(result);
    }
  }

  private reportCompact(result: ScanResult): void {
    console.log('\n');
    
    const { findings } = result;

    if (findings.length === 0) {
      this.printSuccessReport(result);
      return;
    }

    this.printSecurityHeader(findings.length);

    const grouped = this.groupBySeverity(findings);

    if (grouped.HIGH.length > 0) {
      this.printSeverityGroup('HIGH', grouped.HIGH, chalk.red);
    }

    if (grouped.MEDIUM.length > 0) {
      this.printSeverityGroup('MEDIUM', grouped.MEDIUM, chalk.yellow);
    }

    if (grouped.LOW.length > 0) {
      this.printSeverityGroup('LOW', grouped.LOW, chalk.blue);
    }

    this.printDetailedSummary(result);
    this.printReportFooter(result);
  }

  private reportJson(result: ScanResult): void {
    console.log(JSON.stringify(result, null, 2));
  }

  private reportPretty(result: ScanResult): void {
    console.log('\n');
    
    const { findings } = result;

    if (findings.length === 0) {
      this.printSuccessReport(result);
      return;
    }

    this.printSecurityHeader(findings.length);
    console.log('\n');

    const grouped = this.groupBySeverity(findings);

    if (grouped.HIGH.length > 0) {
      this.printSeverityGroup('HIGH', grouped.HIGH, chalk.red);
    }

    // Print MEDIUM severity
    if (grouped.MEDIUM.length > 0) {
      this.printSeverityGroup('MEDIUM', grouped.MEDIUM, chalk.yellow);
    }

    // Print LOW severity
    if (grouped.LOW.length > 0) {
      this.printSeverityGroup('LOW', grouped.LOW, chalk.blue);
    }

    console.log('\n');
    this.printSummary(result);
  }

  private groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
    return findings.reduce(
      (acc, finding) => {
        acc[finding.severity].push(finding);
        return acc;
      },
      {
        HIGH: [] as Finding[],
        MEDIUM: [] as Finding[],
        LOW: [] as Finding[],
      }
    );
  }

  private printSeverityGroup(
    severity: string,
    findings: Finding[],
    color: typeof chalk.red
  ): void {
    const icons = {
      HIGH: '🔴',
      MEDIUM: '🟡',
      LOW: '🔵',
    };
    const icon = icons[severity as keyof typeof icons] || '●';
    
    // Section header
    console.log('');
    const headerLine = `  ${icon} ${severity} SEVERITY - ${findings.length} ${findings.length === 1 ? 'ISSUE' : 'ISSUES'}`;
    console.log(color.bold(headerLine));
    console.log(chalk.gray('  ' + '─'.repeat(60)));
    console.log('');

    // Get background colors for each severity
    const backgrounds = {
      HIGH: { bg: chalk.bgRgb(60, 20, 20), text: chalk.rgb(255, 200, 200), badge: chalk.bgRgb(180, 40, 40).white.bold },
      MEDIUM: { bg: chalk.bgRgb(70, 50, 15), text: chalk.rgb(255, 220, 150), badge: chalk.bgRgb(200, 120, 30).black.bold },
      LOW: { bg: chalk.bgRgb(70, 65, 15), text: chalk.rgb(255, 245, 150), badge: chalk.bgRgb(200, 180, 40).black.bold },
    };
    
    const theme = backgrounds[severity as keyof typeof backgrounds] || backgrounds.HIGH;

    // Print each finding with soft background
    findings.forEach((finding, index) => {
      // Get terminal width or default to 100
      const terminalWidth = process.stdout.columns || 100;
      const contentWidth = Math.min(terminalWidth - 4, 120);
      
      // Create the finding block with background
      const badge = theme.badge(` ${severity} `);
      const title = finding.description || finding.ruleId;
      const titleLength = title.length + severity.length + 4; // badge + spaces
      
      // Top line: badge + title with background
      const topLine = `  ${badge} ${theme.text(title)}`;
      const topPadding = ' '.repeat(Math.max(0, contentWidth - titleLength - 2));
      console.log(theme.bg(topLine + topPadding));
      
      // Location line with background
      const location = this.formatFilePath(finding.filePath);
      const lineInfo = finding.line ? `:${finding.line}` : '';
      const locationText = `      ${chalk.white(location)}${chalk.gray(lineInfo)}`;
      const locationLength = location.length + lineInfo.length + 6;
      const locPadding = ' '.repeat(Math.max(0, contentWidth - locationLength));
      console.log(theme.bg(locationText + locPadding));
      
      // Add some spacing
      console.log('');
    });
  }

  private formatFilePath(filePath: string): string {
    const parts = filePath.split('/');
    if (parts.length > 3) {
      return '.../' + parts.slice(-3).join('/');
    }
    return filePath;
  }

  private printSecurityHeader(findingsCount: number): void {
    const headerText = '  SECURITY VULNERABILITIES DETECTED  ';
    const box = boxen(securityGradient(headerText), {
      padding: 1,
      margin: 1,
      borderStyle: 'double',
      borderColor: 'red',
      backgroundColor: '#1a1a1a',
    });
    console.log(box);
    
    // More prominent issue count
    console.log('');
    console.log(chalk.red.bold(`  ⚠️  ${findingsCount} SECURITY ${findingsCount === 1 ? 'ISSUE' : 'ISSUES'} FOUND`));
    console.log('');

    // Show reports at the top
    if (this.options.generatedReports) {
      this.printReportsLinks(true);
    }
  }

  private printSuccessReport(result: ScanResult): void {
    const headerText = '  SECURITY SCAN COMPLETE  ';
    const box = boxen(successGradient(headerText), {
      padding: 1,
      margin: 1,
      borderStyle: 'double',
      borderColor: 'green',
      backgroundColor: '#1a1a1a',
    });
    console.log(box);
    
    console.log('');
    console.log(chalk.green.bold('  ✓ NO SECURITY VULNERABILITIES DETECTED'));
    console.log(chalk.green('  Your React Native app passed all 20 security checks!'));
    console.log('');
    this.printDetailedSummary(result);
    this.printReportFooter(result);
  }

  private printSummary(result: ScanResult): void {
    console.log('\n');
    this.printDetailedSummary(result);
  }

  private printDetailedSummary(result: ScanResult): void {
    const { findings } = result;
    const high = findings.filter(f => f.severity === 'HIGH').length;
    const medium = findings.filter(f => f.severity === 'MEDIUM').length;
    const low = findings.filter(f => f.severity === 'LOW').length;

    console.log('');
    console.log(chalk.bold.white('  ╔═══════════════════════════════════════════════════════════╗'));
    console.log(chalk.bold.white('  ║                      SCAN SUMMARY                         ║'));
    console.log(chalk.bold.white('  ╚═══════════════════════════════════════════════════════════╝'));
    console.log('');
    
    // Visual dashboard
    const highBar = high > 0 ? '█'.repeat(Math.min(high, 20)) : '─';
    const medBar = medium > 0 ? '█'.repeat(Math.min(medium, 20)) : '─';
    const lowBar = low > 0 ? '█'.repeat(Math.min(low, 20)) : '─';
    
    console.log(chalk.bold.white('  Security Issues:'));
    console.log(`    🔴 ${chalk.red.bold('High:'.padEnd(10))} ${high.toString().padStart(3)} ${high > 0 ? chalk.red(highBar) : chalk.gray(highBar)}`);
    console.log(`    🟡 ${chalk.yellow.bold('Medium:'.padEnd(10))} ${medium.toString().padStart(3)} ${medium > 0 ? chalk.yellow(medBar) : chalk.gray(medBar)}`);
    console.log(`    🔵 ${chalk.blue.bold('Low:'.padEnd(10))} ${low.toString().padStart(3)} ${low > 0 ? chalk.blue(lowBar) : chalk.gray(lowBar)}`);
    console.log(`    ${chalk.gray('─'.repeat(40))}`);
    console.log(`    ${chalk.bold.white('Total:'.padEnd(13))} ${this.getColoredCount(findings.length).toString().padStart(3)}`);
    console.log('');
    
    // Performance metrics
    console.log(chalk.bold.white('  Scan Performance:'));
    console.log(`    ⚡ Duration:    ${chalk.cyan((result.duration / 1000).toFixed(3))}s`);
    console.log(`    📁 Files:       ${chalk.cyan(result.scannedFiles || 'N/A')}`);
    console.log(`    🕐 Completed:   ${chalk.gray(result.timestamp.toLocaleString())}`);
    console.log('');

    // Risk assessment
    if (findings.length > 0 && high > 0) {
      const riskLevel = high >= 10 ? 'CRITICAL' : high >= 5 ? 'HIGH' : 'ELEVATED';
      console.log(chalk.red.bold(`  ⚠️  RISK LEVEL: ${riskLevel}`));
      console.log(chalk.red('  Immediate action required. High severity vulnerabilities detected.'));
    } else if (findings.length > 0 && medium > 0) {
      console.log(chalk.yellow.bold('  ⚠️  RISK LEVEL: MODERATE'));
      console.log(chalk.yellow('  Review and address security issues when possible.'));
    } else if (findings.length > 0) {
      console.log(chalk.blue.bold('  ℹ️  RISK LEVEL: LOW'));
      console.log(chalk.blue('  Minor issues detected. Address as part of regular maintenance.'));
    } else {
      console.log(chalk.green.bold('  ✓ RISK LEVEL: SECURE'));
      console.log(chalk.green('  No security vulnerabilities detected. Great job!'));
    }
    
    console.log('');
  }

  private printReportsLinks(isTop: boolean = false): void {
    const { html, json } = this.options.generatedReports || {};
    
    if (!html && !json) return;

    if (isTop) {
      console.log(chalk.cyan.bold('  📊 DETAILED REPORTS AVAILABLE'));
      console.log(chalk.gray('  ─────────────────────────────────────────────────────────────'));
    } else {
      console.log('');
      console.log(chalk.bold.white('  ╔═══════════════════════════════════════════════════════════╗'));
      console.log(chalk.bold.white('  ║                  DETAILED REPORTS                         ║'));
      console.log(chalk.bold.white('  ╚═══════════════════════════════════════════════════════════╝'));
    }
    
    console.log('');
    
    if (html) {
      console.log(chalk.green.bold('  🌐 HTML Report (Click to open):'));
      console.log(chalk.cyan.underline(`     file://${html}`));
      console.log(chalk.gray(`     Interactive report with filters and full details`));
      console.log('');
    }
    
    if (json) {
      console.log(chalk.green.bold('  📄 JSON Report:'));
      console.log(chalk.white(`     ${json}`));
      console.log(chalk.gray(`     Machine-readable format for CI/CD integration`));
      console.log('');
    }
    
    if (!isTop) {
      console.log(chalk.gray('  💡 Tip: Cmd/Ctrl + Click the links above to open them'));
    }
    
    console.log('');
  }

  private printReportFooter(result: ScanResult): void {
    if (this.options.generatedReports) {
      this.printReportsLinks(false);
    }
    console.log('');
  }

  private getColoredCount(count: number): string {
    if (count === 0) return chalk.green.bold('0');
    if (count < 5) return chalk.yellow.bold(count.toString());
    return chalk.red.bold(count.toString());
  }

  listRules(rules: Array<{ id: string; description: string; severity: Severity }>): void {
    console.log('\n');
    const headerText = '  SECURITY RULES DATABASE  ';
    const box = boxen(gradient(['#4facfe', '#00f2fe'])(headerText), {
      padding: 1,
      margin: 1,
      borderStyle: 'double',
      borderColor: 'cyan',
      backgroundColor: '#1a1a1a',
    });
    console.log(box);
    console.log('');

    const grouped = {
      HIGH: rules.filter(r => r.severity === 'HIGH'),
      MEDIUM: rules.filter(r => r.severity === 'MEDIUM'),
      LOW: rules.filter(r => r.severity === 'LOW'),
    };

    Object.entries(grouped).forEach(([severity, ruleList]) => {
      if (ruleList.length === 0) return;
      
      const icons = { HIGH: '🔴', MEDIUM: '🟡', LOW: '🔵' };
      const icon = icons[severity as keyof typeof icons];
      const color = severity === 'HIGH' ? chalk.red : severity === 'MEDIUM' ? chalk.yellow : chalk.blue;
      
      console.log(color.bold(`  ${icon} ${severity} SEVERITY - ${ruleList.length} rules`));
      console.log(chalk.gray('  ' + '─'.repeat(60)));
      console.log('');
      
      ruleList.forEach((rule) => {
        console.log(`    ${color('▸')} ${chalk.bold.white(rule.id)}`);
        console.log(`      ${chalk.gray(rule.description)}`);
        console.log('');
      });
    });

    console.log(chalk.gray('  ─'.repeat(60)));
    console.log(chalk.cyan.bold(`  📊 Total: ${rules.length} security rules loaded`));
    console.log('');
  }
}

