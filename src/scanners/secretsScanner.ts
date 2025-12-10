import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
}

const secretPatterns: SecretPattern[] = [
  {
    name: 'Firebase API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: Severity.HIGH,
    description: 'Firebase API key detected'
  },
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: Severity.HIGH,
    description: 'AWS Access Key ID detected'
  },
  {
    name: 'AWS Secret Key',
    pattern: /aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:][\s]*['"]?[A-Za-z0-9/+=]{40}['"]?/gi,
    severity: Severity.HIGH,
    description: 'AWS Secret Access Key detected'
  },
  {
    name: 'Google Cloud API Key',
    pattern: /AIza[0-9A-Za-z\\-_]{35}/g,
    severity: Severity.HIGH,
    description: 'Google Cloud API key detected'
  },
  {
    name: 'Google OAuth',
    pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    severity: Severity.MEDIUM,
    description: 'Google OAuth Client ID detected'
  },
  {
    name: 'Stripe Live API Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Stripe Live Secret Key detected'
  },
  {
    name: 'Stripe Restricted API Key',
    pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Stripe Restricted Key detected'
  },
  {
    name: 'Stripe Publishable Key',
    pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
    severity: Severity.LOW,
    description: 'Stripe Publishable Key detected (less sensitive but should be in env)'
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[0-9a-zA-Z]{36}/g,
    severity: Severity.HIGH,
    description: 'GitHub Personal Access Token detected'
  },
  {
    name: 'GitHub OAuth',
    pattern: /gho_[0-9a-zA-Z]{36}/g,
    severity: Severity.HIGH,
    description: 'GitHub OAuth Token detected'
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Slack Token detected'
  },
  {
    name: 'Slack Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
    severity: Severity.MEDIUM,
    description: 'Slack Webhook URL detected'
  },
  {
    name: 'Twilio API Key',
    pattern: /SK[0-9a-fA-F]{32}/g,
    severity: Severity.HIGH,
    description: 'Twilio API Key detected'
  },
  {
    name: 'SendGrid API Key',
    pattern: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g,
    severity: Severity.HIGH,
    description: 'SendGrid API Key detected'
  },
  {
    name: 'Mailgun API Key',
    pattern: /key-[0-9a-zA-Z]{32}/g,
    severity: Severity.HIGH,
    description: 'Mailgun API Key detected'
  },
  {
    name: 'Mailchimp API Key',
    pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    severity: Severity.HIGH,
    description: 'Mailchimp API Key detected'
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g,
    severity: Severity.HIGH,
    description: 'Private Key detected in source code'
  },
  {
    name: 'RSA Private Key',
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    severity: Severity.HIGH,
    description: 'RSA Private Key detected'
  },
  {
    name: 'SSH Key',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
    severity: Severity.HIGH,
    description: 'SSH Private Key detected'
  },
  {
    name: 'PGP Private Key',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    severity: Severity.HIGH,
    description: 'PGP Private Key detected'
  },
  {
    name: 'Heroku API Key',
    pattern: /[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    severity: Severity.HIGH,
    description: 'Heroku API Key detected'
  },
  {
    name: 'DigitalOcean Token',
    pattern: /dop_v1_[a-f0-9]{64}/g,
    severity: Severity.HIGH,
    description: 'DigitalOcean Personal Access Token detected'
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*/g,
    severity: Severity.MEDIUM,
    description: 'JWT Token detected (could be test/example or real)'
  },
  {
    name: 'Generic API Key',
    pattern: /[aA][pP][iI][_\-]?[kK][eE][yY][\s]*[=:][\s]*['"][0-9a-zA-Z\-_]{20,}['"]/g,
    severity: Severity.MEDIUM,
    description: 'Generic API key pattern detected'
  },
  {
    name: 'Generic Secret',
    pattern: /[sS][eE][cC][rR][eE][tT][\s]*[=:][\s]*['"][0-9a-zA-Z\-_!@#$%^&*()+=]{16,}['"]/g,
    severity: Severity.MEDIUM,
    description: 'Generic secret pattern detected'
  },
  {
    name: 'Bearer Token',
    pattern: /[bB]earer[\s]+[a-zA-Z0-9\-._~+/]+=*/g,
    severity: Severity.MEDIUM,
    description: 'Bearer token detected'
  },
  {
    name: 'Basic Auth',
    pattern: /[bB]asic[\s]+[A-Za-z0-9+/=]{20,}/g,
    severity: Severity.MEDIUM,
    description: 'Basic Authentication credentials detected'
  }
];

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

    for (const secretPattern of secretPatterns) {
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

