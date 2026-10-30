export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

/** Highest first; the rank of a severity is its index */
export const SEVERITY_ORDER: Severity[] = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW];

export type Confidence = 'high' | 'medium' | 'low';

/** OWASP data attached to a finding by `--owasp` (from the central rule mapping) */
export interface FindingStandards {
  masvs: string[];
  maswe: string[];
  mastg: string[];
  cwe: number[];
  /** How well the rule's check matches the mapped weakness (not the finding's own `confidence`) */
  confidence: Confidence;
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
  /** How likely this is a real issue (heuristic/absence rules report `low`). Missing = high. */
  confidence?: Confidence;
  /** Stable identity (sha256) used by baselines and SARIF; independent of line numbers */
  fingerprint?: string;
  /** Only with `--owasp`: short rule title, platforms the rule targets, and its MASVS/MASWE/MASTG/CWE mapping */
  title?: string;
  platform?: string[];
  standards?: FindingStandards;
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
  /** Only with `--owasp` */
  owasp?: OwaspReport;
}

/** MASVS coverage of a scan (see src/standards/owasp/coverage.ts) */
export type ControlStatus = 'failed' | 'checked' | 'checked-heuristic' | 'not-applicable' | 'not-assessed';

export interface ControlCoverage {
  id: string;
  statement: string;
  status: ControlStatus;
  /** Enabled rules that map to this control */
  rules: string[];
  findings: number;
  reason?: string;
}

export interface OwaspReport {
  standards: { masvs: string; maswe: string; mastg: string };
  /** `changed-files` when only part of the project was scanned */
  scope: 'project' | 'changed-files';
  summary: {
    controls: number;
    failed: number;
    checked: number;
    checkedHeuristic: number;
    notApplicable: number;
    notAssessed: number;
    /** Enabled, applicable rules that map to at least one MASVS control */
    automatedRules: number;
  };
  controls: ControlCoverage[];
  disclaimer: string;
}

