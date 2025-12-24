export const VERSION = '1.0.0';

export const DEFAULT_REPORT_FILENAMES = {
  HTML: 'rnsec-report.html',
  JSON: 'rnsec-report.json',
} as const;

export const SEVERITY_THRESHOLDS = {
  FINDINGS_COMPACT_MODE: 40,
  MAX_BAR_LENGTH: 20,
  RISK_CRITICAL: 10,
  RISK_HIGH: 5,
} as const;

export const TERMINAL = {
  DEFAULT_WIDTH: 100,
  MAX_CONTENT_WIDTH: 120,
  SEPARATOR_LENGTH: 60,
} as const;

export const EXIT_CODES = {
  SUCCESS: 0,
  HIGH_SEVERITY_FOUND: 1,
  ERROR: 1,
} as const;

export const FILE_EXTENSIONS = {
  JAVASCRIPT: ['.js', '.jsx'] as const,
  TYPESCRIPT: ['.ts', '.tsx'] as const,
  CONFIG: ['.json'] as const,
  ANDROID: ['.xml'] as const,
  IOS: ['.plist'] as const,
} as const;

export const ALL_JS_EXTENSIONS = [...FILE_EXTENSIONS.JAVASCRIPT, ...FILE_EXTENSIONS.TYPESCRIPT] as const;

