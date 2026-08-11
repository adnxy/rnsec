export enum Severity {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

export interface Finding {
  ruleId: string;
  description: string;
  severity: Severity;
  filePath: string;
  line?: number;
  column?: number;
  snippet?: string;
  reason?: string; // Why this security issue matters
  suggestion?: string;
  isDebugContext?: boolean;
  category?: string; // e.g., "npm", "config", "code"
}

export interface IgnoredFinding {
  ruleId: string;
  path: string;
  line?: number;
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: number;
  duration: number;
  timestamp: Date;
  ignoredRules?: string[];
  ignoredFindings?: IgnoredFinding[];
}
