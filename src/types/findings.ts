export enum Severity {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

export type Confidence = 'high' | 'medium' | 'low';

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
  /** How likely this is a real issue (heuristic/absence rules report `low`). Missing = high. */
  confidence?: Confidence;
  /** Stable identity (sha256) used by baselines and SARIF; independent of line numbers */
  fingerprint?: string;
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: number;
  duration: number;
  timestamp: Date;
  ignoredRules?: string[];
  /** Findings dropped by `rnsec-ignore` comments */
  suppressedCount?: number;
  /** Findings dropped because their fingerprint is listed in the baseline */
  baselinedCount?: number;
}

