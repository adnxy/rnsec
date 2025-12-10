import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

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
        filePath.includes('/test/')) {
      return findings;
    }

    const testPatterns = [
      { pattern: /(password|pass|pwd)[\s]*[:=][\s]*['"]?(test|demo|admin|password|123456|qwerty)/gi, type: 'password' },
      { pattern: /(username|user|email)[\s]*[:=][\s]*['"]?(test|demo|admin|user@test\.com)/gi, type: 'username' },
      { pattern: /test@(test|example)\.(com|org)/gi, type: 'email' },
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
      /\/test\//gi,
      /\/dev\//gi,
      /\/admin\/debug/gi,
      /\/api\/debug/gi,
      /localhost:\d{4}/gi,
      /127\.0\.0\.1:\d{4}/gi,
      /192\.168\.\d+\.\d+:\d{4}/gi,
      /10\.0\.\d+\.\d+:\d{4}/gi,
    ];

    traverse(context.ast, {
      StringLiteral(path: any) {
        const { node } = path;
        const value = node.value;

        if (typeof value === 'string' && (value.includes('://') || value.startsWith('/'))) {
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
                  severity: Severity.MEDIUM,
                  filePath: context.filePath,
                  line,
                  snippet: extractSnippet(context.fileContent, line),
                  suggestion: 'Wrap debug endpoints in __DEV__ checks or remove them from production builds.',
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
        
        if (
          node.object.type === 'Identifier' &&
          node.object.name === 'window' &&
          node.property.type === 'Identifier' &&
          node.property.name === '__REDUX_DEVTOOLS_EXTENSION__'
        ) {
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

const storybookInProductionRule: Rule = {
  id: 'STORYBOOK_IN_PRODUCTION',
  description: 'Storybook imports detected in production code',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const filePath = context.filePath.toLowerCase();
    if (filePath.includes('.stories.') || filePath.includes('storybook')) {
      return findings;
    }

    traverse(context.ast, {
      ImportDeclaration(path: any) {
        const { node } = path;
        
        if (node.source && node.source.value) {
          const importPath = node.source.value;
          
          if (importPath.includes('@storybook') || importPath.includes('storybook')) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'STORYBOOK_IN_PRODUCTION',
              description: `Storybook import in production code: ${importPath}`,
              severity: Severity.LOW,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Remove Storybook imports from production code. Keep Storybook isolated in .stories files.',
            });
          }
        }
      },
    });

    return findings;
  },
};

const sourceMapInProductionRule: Rule = {
  id: 'SOURCEMAP_REFERENCE',
  description: 'Source map reference in production bundle',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    const sourceMapPattern = /\/\/[@#]\s*sourceMappingURL=/gi;
    
    if (sourceMapPattern.test(context.fileContent)) {
      const matches = context.fileContent.matchAll(sourceMapPattern);
      
      for (const match of matches) {
        if (match.index === undefined) continue;
        
        const line = getLineNumber(context.fileContent, match.index);
        
        findings.push({
          ruleId: 'SOURCEMAP_REFERENCE',
          description: 'Source map reference found - exposes source code structure',
          severity: Severity.LOW,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Disable source maps in production builds or serve them separately with authentication.',
        });
      }
    }

    return findings;
  },
};

const alertInProductionRule: Rule = {
  id: 'ALERT_IN_PRODUCTION',
  description: 'Alert or prompt used in production code (development artifact)',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (node.callee.type === 'Identifier' && 
            (node.callee.name === 'alert' || node.callee.name === 'prompt' || node.callee.name === 'confirm')) {
          
          const surroundingCode = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 100),
            Math.min(context.fileContent.length, (node.end || 0) + 50)
          );

          const hasDevCheck = /__DEV__|NODE_ENV/.test(surroundingCode);
          
          if (!hasDevCheck) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'ALERT_IN_PRODUCTION',
              description: `${node.callee.name}() call without __DEV__ check - likely debug code`,
              severity: Severity.LOW,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: `Replace ${node.callee.name}() with proper UI components or wrap in __DEV__ check for debugging only.`,
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
    storybookInProductionRule,
    sourceMapInProductionRule,
    alertInProductionRule,
  ],
};

