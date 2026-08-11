import type { Node } from '@babel/types';
import type { Finding, IgnoredFinding, Severity } from './findings.js';

export interface RuleContext {
  filePath: string;
  fileContent: string;
  ast?: Node;
  config?: Record<string, any>;
  xmlContent?: string;
  plistContent?: string;
}

export interface Rule {
  id: string;
  description: string;
  severity: Severity;
  fileTypes: string[];
  apply: (context: RuleContext) => Promise<Finding[]>;
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
  ignoredFindings?: IgnoredFinding[];
  npmVulnerabilityScanning?: {
    enabled?: boolean;
    dataSource?: 'npm-audit' | 'hardcoded';
    excludeDevDependencies?: boolean;
  };
  exclude?: string[];
  // Future: other config options
}
