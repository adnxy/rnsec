import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';

const testCredentialsRule: Rule = {
  id: 'TEST_CREDENTIALS_IN_CODE',
  description: 'Test credentials or example passwords found in source code',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const filePath = context.filePath.toLowerCase();
    if (filePath.includes('.test.') ||
        filePath.includes('.spec.') ||
        filePath.includes('/__tests__/') ||
        filePath.includes('/test/') ||
        filePath.includes('node_modules') ||
        filePath.includes('/vendor/') ||
        filePath.includes('/lib/') ||
        filePath.includes('/libraries/') ||
        filePath.includes('/assets/') ||
        filePath.includes('/modules/') ||
        filePath.includes('highcharts') ||
        filePath.includes('.min.')) {
      return findings;
    }

    const testPatterns = [
      { pattern: /(password|pass|pwd)[\s]*[:=][\s]*['"](test|demo|admin|password|123456|qwerty)/gi, type: 'password' },
      { pattern: /(username|user|email)[\s]*[:=][\s]*['"](test|demo|admin|user@test\.com)/gi, type: 'username' },
      { pattern: /['"]test@(test|example)\.(com|org)['"]/gi, type: 'email' },
      { pattern: /Bearer\s+test[a-zA-Z0-9]+/gi, type: 'token' },
    ];

    for (const { pattern, type } of testPatterns) {
      const matches = context.fileContent.matchAll(pattern);
      
      for (const match of matches) {
        if (match.index === undefined) continue;
        
        const line = getLineNumber(context.fileContent, match.index);
        findings.push({
          ruleId: 'TEST_CREDENTIALS_IN_CODE',
          description: `Test ${type} found in production code: ${match[0]}`,
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Remove test credentials from production code. Use environment variables or mock data in tests only.',
        });
      }
    }

    return findings;
  },
};

const debugEndpointsRule: Rule = {
  id: 'DEBUG_ENDPOINTS_EXPOSED',
  description: 'Debug or development endpoints exposed in production code',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const debugEndpoints = [
      /\/debug\//gi,
      /\/api\/debug/gi,
      /\/admin\/debug/gi,
      /\/__debug/gi,
    ];

    const localPatterns = [
      /localhost/gi,
      /127\.0\.0\.1/gi,
      /192\.168\./gi,
      /10\.0\./gi,
      /172\.(1[6-9]|2[0-9]|3[0-1])\./gi,
    ];

    traverse(context.ast, {
      StringLiteral(path: any) {
        const { node } = path;
        const value = node.value;
        
        if (typeof value === 'string' && (value.includes('://') || value.startsWith('/'))) {
          const isLocal = localPatterns.some(pattern => pattern.test(value));
          if (isLocal) {
            return;
          }

          for (const pattern of debugEndpoints) {
            if (pattern.test(value)) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              const surroundingCode = context.fileContent.substring(
                Math.max(0, (node.start || 0) - 150),
                Math.min(context.fileContent.length, (node.end || 0) + 150)
              );
              
              const hasDevCheck = /__DEV__|process\.env\.NODE_ENV/.test(surroundingCode);
              
              if (!hasDevCheck) {
                findings.push({
                  ruleId: 'DEBUG_ENDPOINTS_EXPOSED',
                  description: `Debug endpoint exposed: ${value}`,
                  severity: Severity.HIGH,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Wrap debug endpoints in __DEV__ checks or remove them from production builds. Debug endpoints should never be accessible in production.',
                });
              }
              break;
            }
          }
        }
      },
    });

    return findings;
  },
};

const reduxDevToolsRule: Rule = {
  id: 'REDUX_DEVTOOLS_ENABLED',
  description: 'Redux DevTools enabled in production',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      MemberExpression(path: any) {
        const { node } = path;
        
        if (node.object.type === 'Identifier' &&
            node.object.name === 'window' &&
            node.property.type === 'Identifier' &&
            node.property.name === '__REDUX_DEVTOOLS_EXTENSION__') {
          
          const start = Math.max(0, (node.start || 0) - 200);
          const end = Math.min(context.fileContent.length, (node.end || 0) + 200);
          const surroundingCode = context.fileContent.substring(start, end);
          
          const hasDevCheck = /__DEV__|process\.env\.NODE_ENV.*!==.*production/.test(surroundingCode);
          
          if (!hasDevCheck) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            findings.push({
              ruleId: 'REDUX_DEVTOOLS_ENABLED',
              description: 'Redux DevTools extension enabled without production check',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Wrap Redux DevTools in __DEV__ or NODE_ENV check: window.__REDUX_DEVTOOLS_EXTENSION__ && __DEV__ ? ... : undefined',
            });
          }
        }
      },
    });

    return findings;
  },
};

export const debugRules: RuleGroup = {
  category: RuleCategory.LOGGING,
  rules: [
    testCredentialsRule,
    debugEndpointsRule,
    reduxDevToolsRule,
  ],
};

