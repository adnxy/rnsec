import type { Node } from '@babel/types';
import type { Finding, Severity } from './findings.js';

/** Project-wide facts, resolved once per scan from the root package.json */
export interface ProjectInfo {
  rootDir: string;
  /** Names from dependencies, devDependencies, peerDependencies and optionalDependencies */
  dependencies: Set<string>;
  /** Android targetSdkVersion, see `resolveAndroidTargetSdk`; undefined when it cannot be determined */
  androidTargetSdk?: number;
  /** Root babel config (babel.config.*, .babelrc*, package.json "babel") references `transform-remove-console` */
  stripsConsoleInRelease: boolean;
  /**
   * True for `--changed-files` scans: `apply` only saw the changed files. A `finalize` hook that must know about
   * the whole project ("no protection anywhere") then has to ask `listProjectFiles` instead of trusting what it collected.
   */
  partialScan?: boolean;
  /**
   * Only set when `partialScan` is true. Every source file a full scan of this project would visit (same walker,
   * excludes and .gitignore handling, test/vendored paths removed), resolved lazily and cached.
   */
  listProjectFiles?: () => Promise<string[]>;
}

/** Source language of a native file (`.java`, `.kt`, `.swift`, `.m`/`.mm`) */
export type NativeLanguage = 'java' | 'kotlin' | 'swift' | 'objc';

export interface RuleContext {
  filePath: string;
  fileContent: string;
  ast?: Node;
  config?: Record<string, any>;
  xmlContent?: string;
  plistContent?: string;
  /** Set for `.java`, `.kt`, `.swift`, `.m` and `.mm` files (their text is in `fileContent`) */
  language?: NativeLanguage;
  /** Undefined only when no scan root is known; `dependencies` is empty without a root package.json */
  project?: ProjectInfo;
  /** File never ships in the app binary (scripts/, e2e/, detox/, tools/, ci/, fastlane/, tests, root config files). Signal only. */
  isNonAppSource?: boolean;
  /** Minified / generated JS (very long lines, bundle banner, `*.bundle.js`, `*.min.js`, `res/raw/*.js`). Signal only. */
  isGeneratedBundle?: boolean;
}

export interface Rule {
  id: string;
  description: string;
  severity: Severity;
  fileTypes: string[];
  apply: (context: RuleContext) => Promise<Finding[]>;
  /** Called once before every scan (full or --changed-files): reset per-scan state here */
  beginScan?: () => void;
  /** Called once after all files of a scan were processed; findings are deduped and `rnsec-ignore`d like the others */
  finalize?: (project?: ProjectInfo) => Promise<Finding[]>;
}

export enum RuleCategory {
  STORAGE = 'STORAGE',
  NETWORK = 'NETWORK',
  LOGGING = 'LOGGING',
  CONFIG = 'CONFIG',
  MANIFEST = 'MANIFEST',
}

export interface RuleGroup {
  category: RuleCategory;
  rules: Rule[];
}

export interface RnsecConfig {
  ignoredRules?: string[];
  npmVulnerabilityScanning?: {
    enabled?: boolean;
    dataSource?: 'npm-audit' | 'hardcoded';
    excludeDevDependencies?: boolean;
  };
  exclude?: string[]
  /** Exit non-zero when a finding at or above this level is reported (default: high) */
  failOn?: 'critical' | 'high' | 'medium' | 'low' | 'none';
  /** Per-rule severity overrides, e.g. { "INSECURE_HTTP_URL": "LOW" } */
  severityOverrides?: Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>;
  /** Path to a baseline file (relative to the scan root); listed findings are not reported */
  baseline?: string;
  /** Skip files that git ignores (default true; tracked files are always scanned) */
  respectGitignore?: boolean;
  /** Same as --owasp: attach MASVS/MASWE/MASTG/CWE data and a MASVS coverage section to the report */
  owasp?: boolean;
  // Future: other config options
}
