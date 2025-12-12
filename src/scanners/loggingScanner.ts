import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { containsSensitiveKeyword, getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';
import { SENSITIVE_DATA_CATEGORIES } from '../utils/sensitiveDataPatterns.js';

function categorizeSensitiveData(text: string): string {
  const lowerText = text.toLowerCase();
  
  if (lowerText.includes('password') || lowerText.includes('passwd') || lowerText.includes('pwd')) {
    return SENSITIVE_DATA_CATEGORIES.PASSWORD;
  }
  if (lowerText.includes('token') || lowerText.includes('jwt') || lowerText.includes('bearer')) {
    return SENSITIVE_DATA_CATEGORIES.TOKEN;
  }
  if (lowerText.includes('apikey') || lowerText.includes('api_key') || lowerText.includes('secret')) {
    return SENSITIVE_DATA_CATEGORIES.API_KEY;
  }
  if (lowerText.includes('session') || lowerText.includes('sessionid')) {
    return SENSITIVE_DATA_CATEGORIES.SESSION;
  }
  if (lowerText.includes('email') || lowerText.includes('phone') || lowerText.includes('ssn')) {
    return SENSITIVE_DATA_CATEGORIES.PII;
  }
  if (lowerText.includes('credit') || lowerText.includes('card') || lowerText.includes('cvv') || lowerText.includes('pin')) {
    return SENSITIVE_DATA_CATEGORIES.PAYMENT;
  }
  if (lowerText.includes('user') && (lowerText.includes('profile') || lowerText.includes('data'))) {
    return SENSITIVE_DATA_CATEGORIES.USER_PROFILE;
  }
  if (lowerText.includes('private') || lowerText.includes('encryption')) {
    return SENSITIVE_DATA_CATEGORIES.CRYPTO_KEY;
  }
  
  return SENSITIVE_DATA_CATEGORIES.SENSITIVE;
}

const sensitiveLoggingRule: Rule = {
  id: 'SENSITIVE_LOGGING',
  description: 'Sensitive data potentially logged to console',
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
        filePath.includes('/tests/')) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'console' &&
          node.callee.property.type === 'Identifier' &&
          ['log', 'error', 'warn', 'info', 'debug'].includes(node.callee.property.name)
        ) {
          const codeContext = context.fileContent.substring(
            Math.max(0, (node.start || 0) - 200),
            Math.min(context.fileContent.length, (node.end || 0) + 50)
          );
          const hasDevCheck = /__DEV__|process\.env\.NODE_ENV/.test(codeContext);
          
          for (const arg of node.arguments) {
            let hasSensitiveData = false;
            let sensitiveContext = '';
            let dataCategory = '';
            
            if (arg.type === 'StringLiteral' && arg.value) {
              if (containsSensitiveKeyword(arg.value)) {
                hasSensitiveData = true;
                sensitiveContext = arg.value.length > 50 ? arg.value.substring(0, 50) + '...' : arg.value;
                dataCategory = categorizeSensitiveData(arg.value);
              }
            }
            
            if (arg.type === 'Identifier' && arg.name) {
              if (containsSensitiveKeyword(arg.name)) {
                hasSensitiveData = true;
                sensitiveContext = arg.name;
                dataCategory = categorizeSensitiveData(arg.name);
              }
            }
            
            if (arg.type === 'MemberExpression') {
              const memberStr = context.fileContent.substring(arg.start || 0, arg.end || 0);
              if (containsSensitiveKeyword(memberStr)) {
                hasSensitiveData = true;
                sensitiveContext = memberStr;
                dataCategory = categorizeSensitiveData(memberStr);
              }
            }
            
            if (arg.type === 'TemplateLiteral') {
              const templateStr = context.fileContent.substring(arg.start || 0, arg.end || 0);
              if (containsSensitiveKeyword(templateStr)) {
                hasSensitiveData = true;
                sensitiveContext = templateStr.length > 60 ? templateStr.substring(0, 60) + '...' : templateStr;
                dataCategory = categorizeSensitiveData(templateStr);
              }
            }
            
            if (arg.type === 'ObjectExpression') {
              const objectStr = context.fileContent.substring(arg.start || 0, arg.end || 0);
              if (containsSensitiveKeyword(objectStr)) {
                hasSensitiveData = true;
                sensitiveContext = 'object containing sensitive fields';
                dataCategory = categorizeSensitiveData(objectStr);
              }
            }
            
            if (hasSensitiveData) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              const consoleMethod = node.callee.property.name;
              
              findings.push({
                ruleId: 'SENSITIVE_LOGGING',
                description: `console.${consoleMethod}() logging ${dataCategory}: ${sensitiveContext}`,
                severity: hasDevCheck ? Severity.LOW : Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: hasDevCheck 
                  ? 'Consider using a secure logging service instead of console logs, even in development.'
                  : 'Remove console logs with sensitive data or wrap in __DEV__ check. Use a logging library with data filtering for production.',
              });
              
              break;
            }
          }
        }
      },
    });

    return findings;
  },
};

export const loggingRules: RuleGroup = {
  category: RuleCategory.LOGGING,
  rules: [sensitiveLoggingRule],
};
