import type { Finding } from '../types/findings.js';

export interface ScanComparison {
  newIssues: Finding[];
  resolvedIssues: Finding[];
  persistentIssues: Finding[];
}

/**
 * Compare two sets of findings to identify new, resolved, and persistent issues
 */
export function compareScans(
  currentFindings: Finding[],
  previousFindings: Finding[]
): ScanComparison {
  const newIssues: Finding[] = [];
  const resolvedIssues: Finding[] = [];
  const persistentIssues: Finding[] = [];

  // Create a map of previous findings for quick lookup
  const previousMap = new Map<string, Finding>();
  previousFindings.forEach(finding => {
    const key = getFindingKey(finding);
    previousMap.set(key, finding);
  });

  // Check current findings
  currentFindings.forEach(finding => {
    const key = getFindingKey(finding);
    if (previousMap.has(key)) {
      persistentIssues.push(finding);
      previousMap.delete(key);
    } else {
      newIssues.push(finding);
    }
  });

  // Remaining items in previousMap are resolved
  resolvedIssues.push(...previousMap.values());

  return {
    newIssues,
    resolvedIssues,
    persistentIssues,
  };
}

/**
 * Generate a unique key for a finding based on rule ID, file path, and line number
 */
function getFindingKey(finding: Finding): string {
  return `${finding.ruleId}:${finding.filePath}:${finding.line || 0}`;
}

/**
 * Generate comparison summary markdown
 */
export function generateComparisonSummary(comparison: ScanComparison): string {
  if (comparison.newIssues.length === 0 && comparison.resolvedIssues.length === 0) {
    return '';
  }

  let summary = '\n### 📊 Changes Since Last Scan\n\n';
  
  if (comparison.newIssues.length > 0) {
    summary += `- 🆕 **${comparison.newIssues.length} new issue${comparison.newIssues.length === 1 ? '' : 's'}** introduced\n`;
  }
  
  if (comparison.resolvedIssues.length > 0) {
    summary += `- ✅ **${comparison.resolvedIssues.length} issue${comparison.resolvedIssues.length === 1 ? '' : 's'}** resolved\n`;
  }
  
  if (comparison.persistentIssues.length > 0) {
    summary += `- 🔄 **${comparison.persistentIssues.length} existing issue${comparison.persistentIssues.length === 1 ? '' : 's'}** still present\n`;
  }
  
  summary += '\n';
  
  return summary;
}
