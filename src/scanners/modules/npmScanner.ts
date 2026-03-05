import { exec } from 'child_process';
import { promisify } from 'util';
import type { Rule, RuleContext, RuleGroup, RnsecConfig } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';

const execAsync = promisify(exec);

// Global config for npm scanning - set by CLI
let globalRnsecConfig: RnsecConfig | null = null;

export function setNpmScannerConfig(config: RnsecConfig | null) {
  globalRnsecConfig = config;
}

/**
 * Check if npm vulnerability scanning is enabled
 */
function isNpmScanningEnabled(): boolean {
  // Default to enabled if not specified
  if (!globalRnsecConfig?.npmVulnerabilityScanning) {
    return true; // Default: enabled
  }
  
  return globalRnsecConfig.npmVulnerabilityScanning.enabled !== false;
}

/**
 * npm audit result types
 */
interface NpmAuditVulnerability {
  name: string;
  severity: 'info' | 'low' | 'moderate' | 'high' | 'critical';
  via: Array<{
    title: string;
    url: string;
    severity: string;
  }>;
  range: string;
  fixAvailable: boolean | { name: string; version: string };
}

interface NpmAuditResult {
  vulnerabilities: Record<string, NpmAuditVulnerability>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
      total: number;
    };
  };
}

/**
 * Known vulnerable packages (fallback when npm audit is not available)
 */
interface VulnerablePackage {
  name: string;
  vulnerableVersions: string[];
  severity: Severity;
  cve?: string;
  description: string;
  fixVersion?: string;
}

const KNOWN_VULNERABLE_PACKAGES: VulnerablePackage[] = [
  {
    name: 'lodash',
    vulnerableVersions: ['<4.17.21'],
    severity: Severity.HIGH,
    cve: 'CVE-2021-23337',
    description: 'Command injection vulnerability in lodash',
    fixVersion: '4.17.21',
  },
  {
    name: 'axios',
    vulnerableVersions: ['<0.21.1'],
    severity: Severity.MEDIUM,
    cve: 'CVE-2020-28168',
    description: 'SSRF vulnerability in axios',
    fixVersion: '0.21.1',
  },
  {
    name: 'minimist',
    vulnerableVersions: ['<1.2.6'],
    severity: Severity.MEDIUM,
    cve: 'CVE-2021-44906',
    description: 'Prototype pollution vulnerability',
    fixVersion: '1.2.6',
  },
  {
    name: 'node-fetch',
    vulnerableVersions: ['<2.6.7', '<3.0.0'],
    severity: Severity.HIGH,
    cve: 'CVE-2022-0235',
    description: 'Information exposure vulnerability',
    fixVersion: '2.6.7',
  },
  {
    name: 'express',
    vulnerableVersions: ['<4.17.3'],
    severity: Severity.MEDIUM,
    cve: 'CVE-2022-24999',
    description: 'Open redirect vulnerability',
    fixVersion: '4.17.3',
  },
  {
    name: 'trim',
    vulnerableVersions: ['<0.0.3'],
    severity: Severity.HIGH,
    cve: 'CVE-2020-7753',
    description: 'Regular expression denial of service',
    fixVersion: '0.0.3',
  },
];

/**
 * Run npm audit and parse results
 */
async function runNpmAudit(projectPath: string): Promise<NpmAuditResult | null> {
  // Check if npm audit is disabled
  if (globalRnsecConfig?.npmVulnerabilityScanning?.dataSource === 'hardcoded') {
    return null; // Skip npm audit, use hardcoded only
  }

  try {
    // Run npm audit with JSON output
    const { stdout } = await execAsync('npm audit --json', {
      cwd: projectPath,
      timeout: 10000, // 10 second timeout
    });
    
    return JSON.parse(stdout);
  } catch (error: any) {
    // npm audit exits with code 1 if vulnerabilities found
    if (error.stdout) {
      try {
        return JSON.parse(error.stdout);
      } catch (e) {
        // Failed to parse JSON
        return null;
      }
    }
    
    // npm not available or other error
    return null;
  }
}

/**
 * Convert npm audit severity to our severity enum
 */
function convertNpmSeverity(npmSeverity: string): Severity {
  switch (npmSeverity) {
    case 'critical':
    case 'high':
      return Severity.HIGH;
    case 'moderate':
      return Severity.MEDIUM;
    case 'low':
    case 'info':
    default:
      return Severity.LOW;
  }
}

/**
 * Check if a version matches a vulnerable version pattern
 */
function isVulnerableVersion(version: string, pattern: string): boolean {
  const cleanVersion = version.replace(/^[~^>=<]/, '').trim();
  
  if (pattern.startsWith('<')) {
    const targetVersion = pattern.substring(1);
    return compareVersions(cleanVersion, targetVersion) < 0;
  }
  
  return false;
}

/**
 * Simple semantic version comparison
 */
function compareVersions(v1: string, v2: string): number {
  const parts1 = v1.split('.').map(Number);
  const parts2 = v2.split('.').map(Number);
  
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const part1 = parts1[i] || 0;
    const part2 = parts2[i] || 0;
    
    if (part1 < part2) return -1;
    if (part1 > part2) return 1;
  }
  
  return 0;
}

/**
 * Find the line number where a package is defined in package.json
 */
function findPackageLine(content: string, packageName: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${packageName}"`)) {
      return i + 1;
    }
  }
  return 1;
}

/**
 * Find the line number where a scripts key (e.g. postinstall) appears in package.json
 */
function findScriptKeyLine(content: string, scriptKey: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${scriptKey}"`)) {
      return i + 1;
    }
  }
  return 1;
}

/**
 * Supply chain: detect suspicious lifecycle scripts (postinstall/preinstall) that run
 * node on non-standard paths or use || true to hide failures (common in malicious commits).
 */
const suspiciousLifecycleScriptRule: Rule = {
  id: 'SUSPICIOUS_LIFECYCLE_SCRIPT',
  description: 'Suspicious npm lifecycle script - possible supply chain attack',
  severity: Severity.HIGH,
  fileTypes: ['package.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.config || !context.filePath.endsWith('package.json')) {
      return findings;
    }

    const scripts = context.config.scripts as Record<string, string> | undefined;
    if (!scripts || typeof scripts !== 'object') {
      return findings;
    }

    const lifecycleHooks = ['postinstall', 'preinstall', 'install'];
    const suspiciousPatterns = [
      /.github\/workflows\/.*\.js/,           // script in workflows dir (e.g. deploy.js)
      /(^|\s)node\s+.*preinstall\.js/,       // node preinstall.js
      /(^|\s)node\s+.*postinstall\.js/,      // node postinstall.js
      /\|\|\s*true\s*$/,                     // || true hides script failure
    ];

    for (const hook of lifecycleHooks) {
      const script = scripts[hook];
      if (typeof script !== 'string') continue;

      const scriptNorm = script.trim();
      const isSuspicious = suspiciousPatterns.some((re) => re.test(scriptNorm));

      if (isSuspicious) {
        const lineNum = findScriptKeyLine(context.fileContent, hook);
        findings.push({
          ruleId: 'SUSPICIOUS_LIFECYCLE_SCRIPT',
          description: `Suspicious "${hook}" script - may indicate supply chain attack (runs node on workflow/install script or hides errors with || true)`,
          severity: Severity.HIGH,
          filePath: context.filePath,
          line: lineNum,
          snippet: extractSnippet(context.fileContent, lineNum),
          suggestion: 'Review lifecycle scripts. Remove any postinstall/preinstall that run .github/workflows/*.js or root install scripts. Do not use || true to hide failures. Ensure repo and npm tokens are not compromised.',
          category: 'npm',
        });
      }
    }

    return findings;
  },
};

const packageJsonVulnerabilityRule: Rule = {
  id: 'NPM_VULNERABLE_DEPENDENCY',
  description: 'Vulnerable npm package detected in dependencies',
  severity: Severity.HIGH,
  fileTypes: ['package.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    // Check if npm scanning is disabled
    if (!isNpmScanningEnabled()) {
      return findings;
    }
    
    if (!context.config || !context.filePath.endsWith('package.json')) {
      return findings;
    }

    const packageJson = context.config;
    const projectPath = context.filePath.replace('/package.json', '');

    // Determine which dependencies to check
    const excludeDevDeps = globalRnsecConfig?.npmVulnerabilityScanning?.excludeDevDependencies || false;
    const allDependencies = excludeDevDeps
      ? { ...packageJson.dependencies }
      : {
          ...packageJson.dependencies,
          ...packageJson.devDependencies,
        };

    // Try to use npm audit first (best practice)
    const auditResults = await runNpmAudit(projectPath);
    
    if (auditResults && auditResults.vulnerabilities) {
      // Process npm audit results
      for (const [pkgName, vuln] of Object.entries(auditResults.vulnerabilities)) {
        // Skip if not in our dependencies to check
        if (!allDependencies[pkgName]) continue;

        const lineNum = findPackageLine(context.fileContent, pkgName);
        
        // Get the first vulnerability description
        const viaInfo = Array.isArray(vuln.via) && vuln.via.length > 0 
          ? vuln.via[0] 
          : null;
        
        const description = typeof viaInfo === 'object' && viaInfo?.title
          ? viaInfo?.title
          : `Vulnerability in ${pkgName}`;

        const fixInfo = vuln.fixAvailable
          ? typeof vuln.fixAvailable === 'object'
            ? ` Update to ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`
            : ' Fix available - run npm audit fix'
          : ' No automatic fix available';

        findings.push({
          ruleId: 'NPM_VULNERABLE_DEPENDENCY',
          description: `${description} (${vuln.severity})`,
          severity: convertNpmSeverity(vuln.severity),
          filePath: context.filePath,
          line: lineNum,
          snippet: extractSnippet(context.fileContent, lineNum),
          suggestion: `${fixInfo}. Check: npm audit for details.`,
          category: 'npm',
        });
      }
      
      return findings;
    }

    // Fallback: Use hardcoded vulnerability list
    for (const [pkgName, pkgVersion] of Object.entries(allDependencies)) {
      if (typeof pkgVersion !== 'string') continue;

      const vulnerable = KNOWN_VULNERABLE_PACKAGES.find(
        vuln => vuln.name === pkgName
      );

      if (!vulnerable) continue;

      for (const vulnPattern of vulnerable.vulnerableVersions) {
        if (isVulnerableVersion(pkgVersion, vulnPattern)) {
          const lineNum = findPackageLine(context.fileContent, pkgName);
          
          findings.push({
            ruleId: 'NPM_VULNERABLE_DEPENDENCY',
            description: `Vulnerable package "${pkgName}@${pkgVersion}": ${vulnerable.description}${vulnerable.cve ? ` (${vulnerable.cve})` : ''}`,
            severity: vulnerable.severity,
            filePath: context.filePath,
            line: lineNum,
            snippet: extractSnippet(context.fileContent, lineNum),
            suggestion: `Update "${pkgName}" to version ${vulnerable.fixVersion || 'latest'}. Run: npm install ${pkgName}@${vulnerable.fixVersion || 'latest'}`,
            category: 'npm',
          });
        }
      }
    }

    return findings;
  },
};

const deprecatedPackagesRule: Rule = {
  id: 'DEPRECATED_NPM_PACKAGE',
  description: 'Deprecated npm package in use',
  severity: Severity.MEDIUM,
  fileTypes: ['package.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    // Check if npm scanning is disabled
    if (!isNpmScanningEnabled()) {
      return findings;
    }
    
    if (!context.config || !context.filePath.endsWith('package.json')) {
      return findings;
    }

    const packageJson = context.config;
    const allDependencies = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
    };

    // List of known deprecated packages
    const deprecatedPackages = [
      { name: 'request', replacement: 'axios or node-fetch' },
      { name: 'node-uuid', replacement: 'uuid' },
      { name: 'gulp-util', replacement: 'individual gulp utilities' },
      { name: 'istanbul', replacement: 'nyc' },
      { name: 'colors', replacement: 'chalk (after colors sabotage incident)' },
      { name: 'faker', replacement: '@faker-js/faker' },
    ];

    for (const pkg of deprecatedPackages) {
      if (allDependencies[pkg.name]) {
        const lineNum = findPackageLine(context.fileContent, pkg.name);
        
        findings.push({
          ruleId: 'DEPRECATED_NPM_PACKAGE',
          description: `Package "${pkg.name}" is deprecated`,
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: lineNum,
          snippet: extractSnippet(context.fileContent, lineNum),
          suggestion: `Replace "${pkg.name}" with ${pkg.replacement}. Deprecated packages no longer receive security updates.`,
          category: 'npm',
        });
      }
    }

    return findings;
  },
};

export const npmVulnerabilityRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [
    packageJsonVulnerabilityRule,
    deprecatedPackagesRule,
    suspiciousLifecycleScriptRule,
  ],
};
