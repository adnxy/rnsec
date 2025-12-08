/**
 * Logging security scanner
 * Detects sensitive data in logs
 */

import _traverse from '@babel/traverse';
// Handle ESM/CommonJS interop
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { containsSensitiveKeyword, getLineNumber, extractSnippet } from '../utils/stringUtils.js';
import { RuleCategory } from '../types/ruleTypes.js';

/**
 * Rule: SENSITIVE_LOGGING
 * Detects console.log of sensitive data
 */
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

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for console.log, console.error, console.warn
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'console' &&
          node.callee.property.type === 'Identifier' &&
          ['log', 'error', 'warn', 'info', 'debug'].includes(node.callee.property.name)
        ) {
          // Check arguments for sensitive keywords
          for (const arg of node.arguments) {
            let hasSensitiveData = false;
            let sensitiveContext = '';
            
            // Check string literals
            if (arg.type === 'StringLiteral') {
              if (containsSensitiveKeyword(arg.value)) {
                hasSensitiveData = true;
                sensitiveContext = arg.value;
              }
            }
            
            // Check identifiers (variable names)
            if (arg.type === 'Identifier') {
              if (containsSensitiveKeyword(arg.name)) {
                hasSensitiveData = true;
                sensitiveContext = arg.name;
              }
            }
            
            // Check member expressions like user.password
            if (arg.type === 'MemberExpression') {
              const memberStr = context.fileContent.substring(arg.start || 0, arg.end || 0);
              if (containsSensitiveKeyword(memberStr)) {
                hasSensitiveData = true;
                sensitiveContext = memberStr;
              }
            }
            
            // Check template literals
            if (arg.type === 'TemplateLiteral') {
              const templateStr = context.fileContent.substring(arg.start || 0, arg.end || 0);
              if (containsSensitiveKeyword(templateStr)) {
                hasSensitiveData = true;
                sensitiveContext = 'template string with sensitive data';
              }
            }
            
            if (hasSensitiveData) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'SENSITIVE_LOGGING',
                description: `Console logging potentially sensitive data: ${sensitiveContext}`,
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Remove console logs containing sensitive data before production or use a logging library with filtering',
              });
              
              break; // Only report once per console call
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

