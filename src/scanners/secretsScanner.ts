import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';
import { API_SECRET_PATTERNS } from '../utils/sensitiveDataPatterns.js';

const apiKeyDetectionRule: Rule = {
  id: 'API_KEY_EXPOSED',
  description: 'API keys or secrets exposed in source code',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.json', '.env'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    const fileContent = context.fileContent;
    const filePath = context.filePath.toLowerCase();

    if (filePath.includes('node_modules') || 
        filePath.includes('.test.') || 
        filePath.includes('.spec.') ||
        filePath.includes('mock')) {
      return findings;
    }

    for (const secretPattern of API_SECRET_PATTERNS) {
      const matches = fileContent.matchAll(secretPattern.pattern);
      
      for (const match of matches) {
        if (match.index === undefined) continue;

        const matchedText = match[0];
        const line = getLineNumber(fileContent, match.index);
        
        const contextStart = Math.max(0, match.index - 100);
        const contextEnd = Math.min(fileContent.length, match.index + 100);
        const surroundingContext = fileContent.substring(contextStart, contextEnd).toLowerCase();
        
        const isFalsePositive = 
          surroundingContext.includes('example') ||
          surroundingContext.includes('sample') ||
          surroundingContext.includes('dummy') ||
          surroundingContext.includes('placeholder') ||
          surroundingContext.includes('your_') ||
          surroundingContext.includes('xxx') ||
          surroundingContext.includes('...') ||
          matchedText.includes('example') ||
          matchedText.includes('your_') ||
          matchedText.includes('XXXXXXXX');

        if (isFalsePositive) continue;

        const maskedSecret = matchedText.length > 20 
          ? matchedText.substring(0, 20) + '...[REDACTED]'
          : matchedText.substring(0, 8) + '...[REDACTED]';

        findings.push({
          ruleId: 'API_KEY_EXPOSED',
          description: `${secretPattern.description}: ${maskedSecret}`,
          severity: secretPattern.severity,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(fileContent, line),
          suggestion: `Move ${secretPattern.name} to environment variables or secure config management. Never commit secrets to version control.`,
        });
      }
    }

    return findings;
  },
};

const envFileCommittedRule: Rule = {
  id: 'ENV_FILE_COMMITTED',
  description: 'Environment file with secrets potentially committed to repository',
  severity: Severity.HIGH,
  fileTypes: ['.env', '.env.local', '.env.production'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.filePath.includes('.env')) {
      return findings;
    }

    const sensitivePatterns = [
      /[A-Z_]+KEY/i,
      /[A-Z_]+SECRET/i,
      /[A-Z_]+TOKEN/i,
      /[A-Z_]+PASSWORD/i,
      /DATABASE_URL/i,
      /API_URL/i,
    ];

    const hasSensitiveData = sensitivePatterns.some(pattern => 
      pattern.test(context.fileContent)
    );

    if (hasSensitiveData) {
      findings.push({
        ruleId: 'ENV_FILE_COMMITTED',
        description: 'Environment file with sensitive data should not be committed to repository',
        severity: Severity.HIGH,
        filePath: context.filePath,
        line: 1,
        suggestion: 'Add .env files to .gitignore. Use .env.example with placeholder values instead. Load actual secrets from secure environment variable storage.',
      });
    }

    return findings;
  },
};

export const secretsRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [
    apiKeyDetectionRule,
    envFileCommittedRule,
  ],
};

