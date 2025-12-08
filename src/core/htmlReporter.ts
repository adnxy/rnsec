import { writeFile } from 'fs/promises';
import { resolve } from 'path';
import type { Finding, Severity, ScanResult } from '../types/findings.js';

export class HtmlReporter {
  async generateReport(result: ScanResult, outputPath: string): Promise<void> {
    const html = this.buildHtml(result);
    await writeFile(resolve(outputPath), html, 'utf-8');
  }

  private buildHtml(result: ScanResult): string {
    const { findings } = result;
    const high = findings.filter(f => f.severity === 'HIGH');
    const medium = findings.filter(f => f.severity === 'MEDIUM');
    const low = findings.filter(f => f.severity === 'LOW');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>React Native Security Report - ${result.timestamp.toLocaleDateString()}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', 'Roboto', sans-serif;
      background: #0a0e1a;
      min-height: 100vh;
      color: #e4e6eb;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    
    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 40px 20px 80px;
    }
    
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 32px;
      padding: 0 8px;
    }
    
    .header h1 {
      font-size: 32px;
      font-weight: 600;
      color: #ffffff;
      letter-spacing: -0.5px;
    }

    .header-info {
      display: flex;
      align-items: center;
      gap: 12px;
      color: #9ca3af;
      font-size: 14px;
    }

    .info-divider {
      opacity: 0.5;
    }
    
    .summary {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1px;
      background: #1a1f2e;
      border: 1px solid #1a1f2e;
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 32px;
    }
    
    .summary-card {
      background: #141824;
      padding: 48px 32px;
      text-align: center;
      transition: all 0.3s ease;
      border-right: 1px solid #1a1f2e;
      cursor: pointer;
      position: relative;
    }

    .summary-card:last-child {
      border-right: none;
    }
    
    .summary-card:hover {
      background: #1a1f2e;
      transform: translateY(-2px);
    }

    .summary-card.active {
      background: #1f2937;
      box-shadow: inset 0 0 0 2px rgba(59, 130, 246, 0.3);
    }

    .summary-card.active::after {
      content: '';
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, #3b82f6, #60a5fa);
    }
    
    .summary-card .number {
      font-size: 64px;
      font-weight: 700;
      line-height: 1;
      letter-spacing: -2px;
      margin-bottom: 12px;
    }
    
    .summary-card.high .number { color: #ef4444; }
    .summary-card.medium .number { color: #f97316; }
    .summary-card.low .number { color: #eab308; }
    .summary-card.total .number { color: #60a5fa; }
    
    .summary-card h3 {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #9ca3af;
      font-weight: 500;
    }
    
    .findings {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    
    .finding {
      background: #141824;
      border: 1px solid #1f2937;
      border-radius: 12px;
      overflow: hidden;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    
    .finding:hover {
      border-color: #374151;
      background: #1a1f2e;
    }
    
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 24px 28px;
      gap: 20px;
    }
    
    .finding-left {
      display: flex;
      align-items: center;
      gap: 16px;
      flex: 1;
      min-width: 0;
    }
    
    .severity-badge {
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      white-space: nowrap;
      flex-shrink: 0;
    }
    
    .severity-badge.high {
      background: rgba(239, 68, 68, 0.15);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    
    .severity-badge.medium {
      background: rgba(249, 115, 22, 0.15);
      color: #f97316;
      border: 1px solid rgba(249, 115, 22, 0.3);
    }
    
    .severity-badge.low {
      background: rgba(234, 179, 8, 0.15);
      color: #eab308;
      border: 1px solid rgba(234, 179, 8, 0.3);
    }
    
    .finding-title {
      font-size: 16px;
      font-weight: 500;
      color: #f3f4f6;
      letter-spacing: -0.2px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    
    .expand-icon {
      color: #6b7280;
      transition: transform 0.3s ease;
      flex-shrink: 0;
      width: 20px;
      height: 20px;
    }
    
    .finding.expanded .expand-icon {
      transform: rotate(90deg);
    }
    
    .finding-content {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.3s ease;
      border-top: 1px solid transparent;
    }
    
    .finding.expanded .finding-content {
      max-height: 2000px;
      border-top-color: #1f2937;
    }
    
    .finding-content-inner {
      padding: 24px 28px;
    }
    
    .finding-description {
      color: #9ca3af;
      font-size: 15px;
      line-height: 1.6;
      margin-bottom: 20px;
    }
    
    .finding-location {
      display: flex;
      align-items: center;
      gap: 10px;
      color: #6b7280;
      font-size: 13px;
      margin-bottom: 20px;
      font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
    }
    
    .finding-location svg {
      width: 16px;
      height: 16px;
      flex-shrink: 0;
    }
    
    .code-snippet {
      background: #0d1117;
      border: 1px solid #1f2937;
      padding: 16px 20px;
      border-radius: 8px;
      margin-bottom: 20px;
      overflow-x: auto;
    }
    
    .code-snippet pre {
      font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
      font-size: 13px;
      line-height: 1.6;
      color: #e4e6eb;
    }
    
    .suggestion {
      background: rgba(34, 197, 94, 0.08);
      border: 1px solid rgba(34, 197, 94, 0.2);
      border-left: 3px solid #22c55e;
      padding: 16px 20px;
      border-radius: 8px;
    }
    
    .suggestion-title {
      font-weight: 600;
      color: #22c55e;
      margin-bottom: 8px;
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .suggestion-text {
      color: #9ca3af;
      line-height: 1.6;
      font-size: 14px;
    }
    
    .no-findings {
      text-align: center;
      padding: 120px 40px;
      background: #141824;
      border-radius: 12px;
      border: 1px solid #1f2937;
    }
    
    .no-findings svg {
      width: 64px;
      height: 64px;
      margin-bottom: 20px;
      color: #22c55e;
    }
    
    .no-findings h2 {
      font-size: 28px;
      margin-bottom: 12px;
      font-weight: 600;
      color: #f3f4f6;
    }
    
    .no-findings p {
      font-size: 16px;
      color: #9ca3af;
    }

    .footer {
      text-align: center;
      margin-top: 48px;
      padding-top: 32px;
      border-top: 1px solid #1f2937;
      color: #6b7280;
      font-size: 13px;
    }

    .footer .logo {
      font-size: 20px;
      font-weight: 700;
      margin-bottom: 12px;
      color: #f3f4f6;
      letter-spacing: -0.5px;
    }
    
    @media (max-width: 1024px) {
      .summary {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 768px) {
      .header {
        flex-direction: column;
        align-items: flex-start;
        gap: 12px;
      }

      .summary {
        grid-template-columns: 1fr;
      }

      .summary-card {
        border-right: none;
        border-bottom: 1px solid #1a1f2e;
        padding: 36px 24px;
      }

      .summary-card:last-child {
        border-bottom: none;
      }

      .summary-card .number {
        font-size: 48px;
      }
      
      .finding-header {
        padding: 20px;
      }

      .finding-content-inner {
        padding: 20px;
      }
      
      .finding-title {
        font-size: 14px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Security Analysis Report</h1>
      <div class="header-info">
        <div class="info-item">v1.0.0</div>
        <div class="info-divider">•</div>
        <div class="info-item">${result.timestamp.toLocaleDateString()} ${result.timestamp.toLocaleTimeString()}</div>
      </div>
    </div>
    
    <div class="summary">
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
      <div class="summary-card total active" onclick="filterBySeverity('all')" data-filter="all">
        <div class="number">${findings.length}</div>
        <h3>Total</h3>
      </div>
    </div>
    
    ${findings.length > 0 ? `
    <div class="findings">
      ${this.renderFindings(high, 'HIGH')}
      ${this.renderFindings(medium, 'MEDIUM')}
      ${this.renderFindings(low, 'LOW')}
    </div>
    ` : `
    <div class="no-findings">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>
      <h2>No Security Issues Found!</h2>
      <p>Your React Native app passed all security checks.</p>
    </div>
    `}

    <div class="footer">
      <div class="logo">rnsec</div>
      <p>React Native & Expo Security Scanner</p>
      <p style="margin-top: 8px; opacity: 0.6;">
        Scanned ${result.scannedFiles || 'N/A'} files in ${(result.duration / 1000).toFixed(2)}s · ${result.timestamp.toLocaleString()}
      </p>
    </div>
  </div>
  
  <script>
    let currentFilter = 'all';

    function toggleFinding(element) {
      element.classList.toggle('expanded');
    }

    function filterBySeverity(severity) {
      currentFilter = severity;
      const findings = document.querySelectorAll('.finding');
      const cards = document.querySelectorAll('.summary-card');
      
      // Update active state on cards
      cards.forEach(card => {
        if (card.dataset.filter === severity) {
          card.classList.add('active');
        } else {
          card.classList.remove('active');
        }
      });
      
      // Filter findings
      findings.forEach(finding => {
        if (severity === 'all') {
          finding.style.display = 'block';
        } else if (finding.classList.contains(severity)) {
          finding.style.display = 'block';
        } else {
          finding.style.display = 'none';
        }
      });

      // Scroll to findings section smoothly
      const findingsSection = document.querySelector('.findings');
      if (findingsSection && severity !== 'all') {
        findingsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }

    // Add click handlers to all findings
    document.querySelectorAll('.finding').forEach(finding => {
      finding.addEventListener('click', function(e) {
        // Don't toggle if clicking on code snippet or links
        if (e.target.closest('.code-snippet') || e.target.tagName === 'A') {
          return;
        }
        toggleFinding(this);
      });
    });
  </script>
</body>
</html>`;
  }

  private renderFindings(findings: Finding[], severityLabel: string): string {
    return findings.map((finding, index) => `
      <div class="finding ${severityLabel.toLowerCase()}" data-severity="${severityLabel.toLowerCase()}">
        <div class="finding-header">
          <div class="finding-left">
            <span class="severity-badge ${severityLabel.toLowerCase()}">${severityLabel}</span>
            <div class="finding-title">${this.escapeHtml(finding.description || finding.ruleId)}</div>
          </div>
          <svg class="expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg>
        </div>
        
        <div class="finding-content">
          <div class="finding-content-inner">
            ${finding.description && finding.description !== finding.ruleId ? `
              <div class="finding-description">${this.escapeHtml(finding.description)}</div>
            ` : ''}
            
            <div class="finding-location">
              <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
              </svg>
              <span>${this.escapeHtml(finding.filePath)}${finding.line ? ':' + finding.line : ''}</span>
            </div>
            
            ${finding.snippet ? `
            <div class="code-snippet">
              <pre>${this.escapeHtml(finding.snippet)}</pre>
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
        </div>
      </div>
    `).join('');
  }

  private escapeHtml(text: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;',
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  }
}
