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
      font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'SF Pro Display', 'Helvetica Neue', sans-serif;
      background: #f8f9fa;
      min-height: 100vh;
      padding: 0;
      color: #1a202c;
      line-height: 1.6;
      font-weight: 400;
      letter-spacing: -0.01em;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    
    .container {
      max-width: 1400px;
      margin: 0 auto;
      background: white;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    
    .header {
      background: #0f172a;
      color: white;
      padding: 64px 48px 56px;
      text-align: center;
      position: relative;
      border-bottom: 3px solid #dc2626;
    }
    
    .header h1 {
      font-size: 48px;
      margin-bottom: 16px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: white;
    }
    
    .header .subtitle {
      font-size: 20px;
      font-weight: 500;
      color: rgba(255,255,255,0.9);
      margin-bottom: 16px;
      letter-spacing: -0.01em;
    }
    
    .header p {
      font-size: 14px;
      color: rgba(255,255,255,0.75);
      margin-top: 12px;
      font-weight: 400;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .summary {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 0;
      background: white;
      border-bottom: 1px solid #e2e8f0;
    }
    
    .summary-card {
      background: white;
      padding: 40px 32px;
      text-align: center;
      transition: all 0.25s ease;
      position: relative;
      border-right: 1px solid #e2e8f0;
    }
    
    .summary-card:last-child {
      border-right: none;
    }
    
    .summary-card:hover {
      background: #f7fafc;
      transform: translateY(-2px);
    }
    
    .summary-card h3 {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      color: #718096;
      margin-bottom: 12px;
      font-weight: 700;
    }
    
    .summary-card .number {
      font-size: 56px;
      font-weight: 800;
      line-height: 1;
      letter-spacing: -0.02em;
    }
    
    .summary-card.high .number { color: #dc2626; }
    .summary-card.medium .number { color: #ea580c; }
    .summary-card.low .number { color: #2563eb; }
    .summary-card.total .number { color: #0f172a; }
    
    .filters {
      padding: 24px 48px;
      background: #f8f9fa;
      border-bottom: 1px solid #e2e8f0;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      position: sticky;
      top: 0;
      z-index: 100;
      backdrop-filter: saturate(180%) blur(20px);
      background: rgba(248,249,250,0.95);
    }
    
    .filter-btn {
      padding: 10px 20px;
      border: 1.5px solid #cbd5e0;
      background: white;
      border-radius: 8px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s ease;
      color: #475569;
      letter-spacing: 0.3px;
    }
    
    .filter-btn:hover {
      background: white;
      border-color: #0f172a;
      color: #0f172a;
      box-shadow: 0 2px 8px rgba(15,23,42,0.15);
    }
    
    .filter-btn.active {
      background: #0f172a;
      color: white;
      border-color: #0f172a;
      box-shadow: 0 4px 12px rgba(15,23,42,0.3);
    }
    
    .findings {
      padding: 48px 48px 80px;
      background: #f8f9fa;
    }
    
    .finding {
      background: white;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 28px 32px;
      margin-bottom: 20px;
      transition: all 0.25s ease;
      position: relative;
    }
    
    .finding::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 4px;
      border-radius: 12px 0 0 12px;
    }
    
    .finding:hover {
      box-shadow: 0 8px 24px rgba(0,0,0,0.08);
      transform: translateY(-2px);
      border-color: #cbd5e0;
    }
    
    .finding.high::before {
      background: linear-gradient(180deg, #dc2626 0%, #ef4444 100%);
    }
    
    .finding.medium::before {
      background: linear-gradient(180deg, #ea580c 0%, #f97316 100%);
    }
    
    .finding.low::before {
      background: linear-gradient(180deg, #2563eb 0%, #3b82f6 100%);
    }
    
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 16px;
      padding-left: 20px;
    }
    
    .finding-title {
      font-size: 18px;
      font-weight: 700;
      color: #0f172a;
      margin-bottom: 8px;
      letter-spacing: -0.01em;
    }
    
    .severity-badge {
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
    }
    
    .severity-badge.high {
      background: #dc2626;
      color: white;
    }
    
    .severity-badge.medium {
      background: #ea580c;
      color: white;
    }
    
    .severity-badge.low {
      background: #2563eb;
      color: white;
    }
    
    .finding-description {
      color: #86868b;
      margin-bottom: 16px;
      line-height: 1.52947;
      font-size: 17px;
    }
    
    .finding-location {
      display: flex;
      align-items: center;
      gap: 10px;
      color: #64748b;
      font-size: 13px;
      margin-bottom: 20px;
      margin-left: 20px;
      font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
      font-weight: 400;
    }
    
    .finding-location svg {
      width: 16px;
      height: 16px;
      color: #94a3b8;
    }
    
    .code-snippet {
      background: #1e293b;
      border: 1px solid #334155;
      padding: 20px 24px;
      border-radius: 10px;
      margin: 20px 0;
      overflow-x: auto;
    }
    
    .code-snippet pre {
      font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
      font-size: 13px;
      line-height: 1.7;
      color: #e2e8f0;
    }
    
    .suggestion {
      background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
      border-left: 4px solid #10b981;
      padding: 20px 24px;
      border-radius: 10px;
      margin-top: 20px;
      border: 1px solid #a7f3d0;
    }
    
    .suggestion-title {
      font-weight: 700;
      color: #065f46;
      margin-bottom: 8px;
      font-size: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .suggestion-title::before {
      content: '💡';
      font-size: 16px;
    }
    
    .suggestion-text {
      color: #047857;
      line-height: 1.7;
      font-size: 14px;
    }
    
    .footer {
      background: #f8f9fa;
      padding: 48px 48px;
      text-align: center;
      color: #64748b;
      border-top: 1px solid #e2e8f0;
    }
    
    .footer .logo {
      font-size: 28px;
      font-weight: 800;
      margin-bottom: 16px;
      color: #0f172a;
      letter-spacing: -0.02em;
    }
    
    .footer p {
      margin-bottom: 8px;
      font-size: 13px;
      line-height: 1.6;
    }
    
    .footer strong {
      color: #0f172a;
      font-weight: 600;
    }
    
    .no-findings {
      text-align: center;
      padding: 120px 40px;
      background: white;
    }
    
    .no-findings svg {
      width: 96px;
      height: 96px;
      margin-bottom: 24px;
      color: #34c759;
    }
    
    .no-findings h2 {
      font-size: 40px;
      margin-bottom: 12px;
      font-weight: 600;
      color: #1d1d1f;
      letter-spacing: -0.03em;
    }
    
    .no-findings p {
      font-size: 19px;
      color: #86868b;
      font-weight: 400;
    }
    
    .section-title {
      font-size: 28px;
      font-weight: 600;
      color: #1d1d1f;
      margin: 40px 0 24px;
      letter-spacing: -0.03em;
      padding-left: 40px;
      background: white;
      padding-top: 32px;
    }
    
    @media print {
      body {
        background: white;
        padding: 0;
      }
      
      .container {
        box-shadow: none;
      }
      
      .filters {
        display: none;
      }
      
      .finding {
        break-inside: avoid;
      }
    }
    
    @media (max-width: 768px) {
      .header h1 {
        font-size: 48px;
      }
      
      .header .subtitle {
        font-size: 21px;
      }
      
      .summary {
        grid-template-columns: 1fr 1fr;
      }
      
      .summary-card .number {
        font-size: 56px;
      }
      
      .findings {
        padding: 24px 20px 40px;
      }
      
      .finding {
        padding: 24px 20px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>React Native Security Report</h1>
      <p class="subtitle">Static Security Analysis</p>
      <p>Generated ${result.timestamp.toLocaleDateString()} at ${result.timestamp.toLocaleTimeString()}</p>
    </div>
    
    <div class="summary">
      <div class="summary-card high">
        <h3>High Severity</h3>
        <div class="number">${high.length}</div>
      </div>
      <div class="summary-card medium">
        <h3>Medium Severity</h3>
        <div class="number">${medium.length}</div>
      </div>
      <div class="summary-card low">
        <h3>Low Severity</h3>
        <div class="number">${low.length}</div>
      </div>
      <div class="summary-card total">
        <h3>Total Issues</h3>
        <div class="number">${findings.length}</div>
      </div>
    </div>
    
    ${findings.length > 0 ? `
    <div class="filters">
      <button class="filter-btn active" onclick="filterFindings('all')">All (${findings.length})</button>
      <button class="filter-btn" onclick="filterFindings('high')">High (${high.length})</button>
      <button class="filter-btn" onclick="filterFindings('medium')">Medium (${medium.length})</button>
      <button class="filter-btn" onclick="filterFindings('low')">Low (${low.length})</button>
    </div>
    
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
      <p><strong>Scan Details:</strong> ${result.scannedFiles || 'N/A'} files scanned in ${(result.duration / 1000).toFixed(2)}s</p>
      <p>React Native & Expo Security Scanner</p>
      <p style="margin-top: 16px; font-size: 12px; opacity: 0.6;">
        Professional-grade static analysis for mobile applications
      </p>
    </div>
  </div>
  
  <script>
    function filterFindings(severity) {
      const findings = document.querySelectorAll('.finding');
      const buttons = document.querySelectorAll('.filter-btn');
      
      buttons.forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
      
      findings.forEach(finding => {
        if (severity === 'all' || finding.classList.contains(severity)) {
          finding.style.display = 'block';
        } else {
          finding.style.display = 'none';
        }
      });
    }
  </script>
</body>
</html>`;
  }

  private renderFindings(findings: Finding[], severityLabel: string): string {
    return findings.map((finding, index) => `
      <div class="finding ${severityLabel.toLowerCase()}" data-severity="${severityLabel.toLowerCase()}">
        <div class="finding-header">
          <div>
            <div class="finding-title">${finding.ruleId}</div>
            <div class="finding-description">${this.escapeHtml(finding.description)}</div>
          </div>
          <span class="severity-badge ${severityLabel.toLowerCase()}">${severityLabel}</span>
        </div>
        
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

