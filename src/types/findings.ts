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
  suggestion?: string;
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: number;
  duration: number;
  timestamp: Date;
}

