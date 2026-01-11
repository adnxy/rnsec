import { writeFile, readFile } from "fs/promises";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import type { Finding, Severity, ScanResult } from "../types/findings.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export class HtmlReporter {
  private templateCache: string | null = null;

  async generateReport(result: ScanResult, outputPath: string): Promise<void> {
    const html = await this.buildHtml(result);
    await writeFile(resolve(outputPath), html, "utf-8");
  }

  private async loadTemplate(): Promise<string> {
    if (this.templateCache) {
      return this.templateCache;
    }
    const templatePath = resolve(__dirname, "template.html");
    this.templateCache = await readFile(templatePath, "utf-8");
    return this.templateCache;
  }

  private groupFindings(findings: Finding[]): Map<string, Finding[]> {
    const grouped = new Map<string, Finding[]>();
    
    for (const finding of findings) {
      const key = `${finding.ruleId}::${finding.description}`;
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(finding);
    }
    
    return grouped;
  }

  private async getPackageVersion(): Promise<string> {
    try {
      const packageJsonPath = resolve(__dirname, "..", "..", "package.json");

      const packageFile = JSON.parse(
        await readFile(packageJsonPath, "utf8"),
      ) as { version?: string };

      return packageFile.version || "";
    } catch {
      return "";
    }
  }

  private async buildHtml(result: ScanResult): Promise<string> {
    const { findings } = result;
    const high = findings.filter((f) => f.severity === "HIGH");
    const medium = findings.filter((f) => f.severity === "MEDIUM");
    const low = findings.filter((f) => f.severity === "LOW");

    const bodyContent = this.buildBodyContent(result, high, medium, low);
    const template = await this.loadTemplate();
    const version = await this.getPackageVersion();

    return template
      .replace("{{REPORT_DATE}}", result.timestamp.toLocaleDateString())
      .replace("{{BODY_CONTENT}}", bodyContent)
      .replace("{{VERSION}}", version);
  }

  private buildBodyContent(result: ScanResult, high: Finding[], medium: Finding[], low: Finding[]): string {
    const { findings, ignoredRules } = result;

    const ignoredRulesSection = ignoredRules && ignoredRules.length > 0 ? `
    <div class="ignored-rules">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>
      <span>Ignoring ${ignoredRules.length} rule(s): ${ignoredRules.join(', ')}</span>
    </div>
    ` : '';

    return `${ignoredRulesSection}<div class="scan-status">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>
      <span>Scan completed in <span class="scan-status-text">${(result.duration / 1000).toFixed(1)}s</span> <span class="divider">•</span> <span class="scan-status-text">${result.scannedFiles || 0} files analyzed</span></span>
    </div>

    <div class="header">
      <div class="header-left">
        <div class="header-icon">
          <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
          </svg>
        </div>
        <div>
          <h1>Static Analysis Report</h1>
          <div class="header-subtitle">RNSEC - React Native & Expo Security Scanner</div>
        </div>
      </div>
      <div class="header-info">
        <div class="info-item">${result.timestamp.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} • ${result.timestamp.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })}</div>
      </div>
    </div>
    
    <div class="summary">
      <div class="summary-card total active" onclick="filterBySeverity('all')" data-filter="all">
        <div class="number">${findings.length}</div>
        <h3>Total</h3>
      </div>
      <div class="summary-card high" onclick="filterBySeverity('high')" data-filter="high">
        <div class="number">${high.length}</div>
        <h3>High</h3>
      </div>
      <div class="summary-card medium" onclick="filterBySeverity('medium')" data-filter="medium">
        <div class="number">${medium.length}</div>
        <h3>Medium</h3>
      </div>
      <div class="summary-card low" onclick="filterBySeverity('low')" data-filter="low">
        <div class="number">${low.length}</div>
        <h3>Low</h3>
      </div>
    </div>
    
    ${findings.length > 0 ? `
    <div class="findings">
      ${this.renderFindings(high, "HIGH")}
      ${this.renderFindings(medium, "MEDIUM")}
      ${this.renderFindings(low, "LOW")}
    </div>
    ` : `
    <div class="no-findings">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>
      <h2>No Security Issues Found!</h2>
      <p>Your React Native app passed all security checks.</p>
    </div>
    `}`;
  }

  private renderFindings(findings: Finding[], severityLabel: string): string {
    const grouped = this.groupFindings(findings);
    const result: string[] = [];

    for (const [key, groupedFindings] of grouped) {
      const firstFinding = groupedFindings[0];
      const count = groupedFindings.length;
      const severityClass = severityLabel.toLowerCase();

      if (count === 1) {
        result.push(this.renderSingleFinding(firstFinding, severityLabel));
        continue;
      }

      const allInDebug = groupedFindings.every(f => f.isDebugContext);
      const someInDebug = groupedFindings.some(f => f.isDebugContext);
      
      result.push(`
      <div class="finding-group ${severityClass}" data-severity="${severityClass}">
        <div class="group-header">
          <div class="finding-left">
            <span class="severity-badge ${severityClass}">
              <span class="severity-icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
              </span>
              ${severityLabel}
            </span>
            <div class="finding-title">
              ${this.escapeHtml(firstFinding.description || firstFinding.ruleId)}
              <span class="occurrence-count">${count} occurrence${count > 1 ? 's' : ''}</span>
              ${allInDebug ? `
                <span class="debug-badge">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                  Debug Only
                </span>
              ` : someInDebug ? `
                <span class="debug-badge">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                  Some in Debug
                </span>
              ` : ''}
            </div>
          </div>
          <svg class="expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg>
        </div>
        
        <div class="instances-container">
          <div class="instances-list">
            ${groupedFindings.map(finding => this.renderFindingInstance(finding, severityLabel)).join('')}
          </div>
        </div>
      </div>
      `);
    }

    return result.join('');
  }

  private renderSingleFinding(finding: Finding, severityLabel: string): string {
    const severityClass = severityLabel.toLowerCase();
    return `
      <div class="finding-group ${severityClass}" data-severity="${severityClass}">
        ${this.renderFindingInstance(finding, severityLabel, true)}
      </div>
    `;
  }

  private renderFindingInstance(finding: Finding, severityLabel: string, isStandalone: boolean = false): string {
    const severityClass = severityLabel.toLowerCase();
    
    if (isStandalone) {
      return `
        <div class="group-header">
          <div class="finding-left">
            <span class="severity-badge ${severityClass}">
              <span class="severity-icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
              </span>
              ${severityLabel}
            </span>
            <div class="finding-title">
              ${this.escapeHtml(finding.description || finding.ruleId)}
              ${finding.category === 'npm' ? `
                <span class="npm-badge">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"></path>
                  </svg>
                  NPM
                </span>
              ` : ''}
              ${finding.isDebugContext ? `
                <span class="debug-badge">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                  Debug Only
                </span>
              ` : ''}
            </div>
          </div>
          <svg class="expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg>
        </div>
        
        <div class="instances-container">
          <div class="instances-list">
            ${this.renderFindingContent(finding, severityLabel, true)}
          </div>
        </div>
      `;
    }
    
    return `
      <div class="finding">
        <div class="finding-header">
          <div class="finding-left">
            <div class="finding-location" style="margin: 0; display: flex; align-items: center; gap: 8px;">
              <div style="display: flex; align-items: center; gap: 8px; flex: 1; flex-wrap: wrap;">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                <span class="file-path">${this.escapeHtml(finding.filePath)}</span>
                ${finding.line ? `<span class="line-number-badge">Line ${finding.line}</span>` : ''}
              </div>
              ${finding.isDebugContext ? `
                <span class="debug-badge" style="margin: 0;">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                  Debug
                </span>
              ` : ''}
            </div>
          </div>
          <svg class="expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg>
        </div>
        
        <div class="finding-content">
          ${this.renderFindingContent(finding, severityLabel, false)}
        </div>
      </div>
    `;
  }

  private renderFindingContent(finding: Finding, severityLabel: string, isStandalone: boolean): string {
    return `
      <div class="finding-content-inner">
        ${!isStandalone && finding.description ? `
          <div class="finding-description">${this.escapeHtml(finding.description)}</div>
        ` : ''}
            
        ${isStandalone ? `
            <div class="finding-location">
              <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
              </svg>
            <span class="file-path">${this.escapeHtml(finding.filePath)}</span>
            ${finding.line ? `<span class="line-number-badge">Line ${finding.line}</span>` : ''}
            </div>
        ` : ''}
            
        ${finding.snippet ? `
            <div class="code-snippet">
            ${this.formatCodeSnippet(finding.snippet, finding.line, severityLabel)}
          </div>
        ` : ''}
        
        ${finding.reason ? `
          <div class="reason-box">
            <div class="reason-title">
              ⚠️ Why this matters
            </div>
            <div class="reason-text">${this.escapeHtml(finding.reason)}</div>
          </div>
        ` : ''}
            
        ${finding.suggestion ? `
            <div class="suggestion">
              <div class="suggestion-title">
                💡 Recommendation
              </div>
            <div class="suggestion-text">${this.escapeHtml(finding.suggestion)}</div>
          </div>
        ` : ''}
      </div>
    `;
  }

  private formatCodeSnippet(snippet: string, targetLine: number | undefined, severity: string): string {
    const lines = snippet.split('\n');
    const startLine = targetLine ? Math.max(1, targetLine - 2) : 1;
    
    return lines.map((line, index) => {
      const lineNumber = startLine + index;
      const isHighlighted = lineNumber === targetLine;
      const severityClass = severity.toLowerCase();
      
      return `<div class="code-line ${isHighlighted ? `highlighted ${severityClass}` : ''}">
  <span class="line-number">${lineNumber}</span>
  <span class="line-content">${this.escapeHtml(line)}</span>
</div>`;
    }).join('');
  }

  private escapeHtml(text: string): string {
    const map: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };
    return text.replace(/[&<>"']/g, (m) => map[m]);
  }
}
