# Contributing to rnsec - Developer Guide

Thank you for your interest in contributing to rnsec! This guide will help you get started with development.

## 📋 Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Code Standards](#code-standards)
- [Testing Your Changes](#testing-your-changes)
- [Submitting Changes](#submitting-changes)

## 🚀 Development Setup

### Prerequisites

- Node.js 18+
- npm or yarn
- TypeScript knowledge
- Familiarity with AST parsing (Babel)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/adnxy/rnsec.git
cd rnsec

# Install dependencies
npm install

# Build the project
npm run build

# Link globally for testing
npm link
```

### Development Workflow

```bash
# Watch mode for development (rebuild on changes)
npm run build -- --watch

# Type checking without building
npm run lint

# Clean build artifacts
npm run clean

# Test your changes
rnsec scan examples/vulnerable-app
```

## 📁 Project Structure

```
rnsec/
├── src/
│   ├── cli/              # CLI entry point and command handling
│   │   └── index.ts      # Main CLI implementation
│   ├── core/             # Core scanning engine
│   │   ├── astParser.ts  # JavaScript/TypeScript AST parsing
│   │   ├── fileWalker.ts # Project file discovery
│   │   ├── htmlReporter.ts # HTML report generation
│   │   ├── reporter.ts   # Terminal output formatting
│   │   ├── ruleEngine.ts # Rule execution engine
│   │   └── template.html # HTML report template
│   ├── scanners/         # Security rule implementations
│   │   ├── androidScanner.ts
│   │   ├── authenticationScanner.ts
│   │   ├── configScanner.ts
│   │   ├── cryptoScanner.ts
│   │   ├── debugScanner.ts
│   │   ├── iosScanner.ts
│   │   ├── loggingScanner.ts
│   │   ├── manifestScanner.ts
│   │   ├── networkScanner.ts
│   │   ├── reactNativeScanner.ts
│   │   ├── secretsScanner.ts
│   │   ├── storageScanner.ts
│   │   └── webviewScanner.ts
│   ├── types/            # TypeScript type definitions
│   │   ├── findings.ts   # Finding and result types
│   │   └── ruleTypes.ts  # Rule interface definitions
│   ├── utils/            # Utility functions
│   │   ├── fileUtils.ts
│   │   ├── sensitiveDataPatterns.ts
│   │   └── stringUtils.ts
│   ├── constants.ts      # Application constants
│   └── index.ts          # Public API exports
├── examples/             # Test applications
│   ├── vulnerable-app/   # App with intentional security issues
│   └── secure-app/       # App following best practices
└── dist/                 # Compiled JavaScript (generated)
```

## 🎯 Code Standards

### TypeScript Guidelines

1. **Strong Typing**: No `any` types unless absolutely necessary
   ```typescript
   // ✅ Good
   function processRule(rule: Rule): Finding[]
   
   // ❌ Bad
   function processRule(rule: any): any
   ```

2. **Use Constants**: Extract magic numbers and strings
   ```typescript
   // ✅ Good
   import { SEVERITY_THRESHOLDS } from '../constants.js';
   if (findings.length > SEVERITY_THRESHOLDS.RISK_HIGH) { }
   
   // ❌ Bad
   if (findings.length > 5) { }
   ```

3. **JSDoc Comments**: Document public APIs
   ```typescript
   /**
    * Scan a project for security vulnerabilities
    * @param rootDir - Root directory of the project
    * @returns Scan results with findings
    */
   async scanProject(rootDir: string): Promise<ScanResult>
   ```

### Naming Conventions

- **Files**: camelCase (e.g., `storageScanner.ts`)
- **Classes**: PascalCase (e.g., `RuleEngine`)
- **Functions**: camelCase (e.g., `registerRuleGroup`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `EXIT_CODES`)
- **Interfaces**: PascalCase (e.g., `RuleContext`)

### Code Organization

- Keep functions small and focused (< 50 lines)
- Extract complex logic into separate functions
- Group related functionality together
- Use early returns to reduce nesting

### Error Handling

```typescript
// Always handle errors gracefully
try {
  const result = await riskyOperation();
  return result;
} catch (error) {
  // Log in development, silent in production
  if (process.env.NODE_ENV !== 'production') {
    console.error('Operation failed:', error);
  }
  return fallbackValue;
}
```

## 🧪 Testing Your Changes

### Manual Testing

1. **Test with vulnerable app**:
   ```bash
   rnsec scan examples/vulnerable-app
   ```
   Should detect 35+ security issues

2. **Test with secure app**:
   ```bash
   rnsec scan examples/secure-app
   ```
   Should detect minimal or no issues

3. **Test report generation**:
   ```bash
   rnsec scan examples/vulnerable-app --html test-report.html
   open test-report.html
   ```

4. **Test JSON output**:
   ```bash
   rnsec scan examples/vulnerable-app --json > output.json
   cat output.json
   ```

5. **Test rules listing**:
   ```bash
   rnsec rules
   ```

### Testing New Rules

When adding a new security rule:

1. Create test cases in `examples/vulnerable-app/`
2. Verify detection with `rnsec scan examples/vulnerable-app`
3. Check for false positives
4. Test debug context filtering
5. Verify report displays correctly

## 📝 Adding a New Security Rule

### Rule Template

```typescript
// src/scanners/yourScanner.ts
import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { RuleCategory } from '../types/ruleTypes.js';

const yourNewRule: Rule = {
  id: 'YOUR_RULE_ID',
  description: 'Clear, actionable description of the security issue',
  severity: Severity.HIGH, // or MEDIUM, LOW
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      // Your AST visitor pattern
      CallExpression(path: any) {
        const { node } = path;
        
        // Detection logic here
        if (isVulnerable(node)) {
          findings.push({
            ruleId: 'YOUR_RULE_ID',
            description: 'Specific issue found',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line: getLineNumber(context.fileContent, node.start || 0),
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'How to fix this issue',
          });
        }
      },
    });

    return findings;
  },
};

export const yourRuleGroup: RuleGroup = {
  category: RuleCategory.YOUR_CATEGORY,
  rules: [yourNewRule],
};
```

### Rule Guidelines

1. **Be Specific**: Clearly identify what makes code vulnerable
2. **Avoid False Positives**: Check for test files, debug contexts
3. **Provide Context**: Include line numbers and code snippets
4. **Offer Solutions**: Give actionable suggestions for fixes
5. **Performance**: Optimize for speed (avoid regex in loops)

## 🔄 Submitting Changes

### Before Submitting

1. **Build succeeds**: `npm run build`
2. **Linting passes**: `npm run lint`
3. **Manual testing**: Test with example apps
4. **Update docs**: Update README if adding features
5. **Update CHANGELOG**: Add entry for your changes

### Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes following code standards
4. Commit with conventional commits:
   ```
   feat: add new SQL injection scanner
   fix: reduce false positives in storage scanner
   docs: update contributing guide
   refactor: extract constants from reporter
   ```
5. Push to your fork: `git push origin feature/your-feature`
6. Open a pull request with:
   - Clear description of changes
   - Screenshots/examples if UI changes
   - Test results
   - Related issue numbers

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] No `any` types introduced
- [ ] JSDoc comments added for public APIs
- [ ] Constants used instead of magic numbers
- [ ] Error handling implemented
- [ ] Tested with example apps
- [ ] Build passes (`npm run build`)
- [ ] Linting passes (`npm run lint`)
- [ ] CHANGELOG updated
- [ ] Documentation updated (if needed)

## 🎓 Learning Resources

- **Babel AST**: [AST Explorer](https://astexplorer.net/)
- **Security Patterns**: [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/)
- **TypeScript**: [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/intro.html)

## 💬 Questions?

- Open an issue with the "question" label
- Email: adnanpoviolabs@gmail.com
- Check existing [discussions](https://github.com/adnxy/rnsec/discussions)

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to rnsec! Your efforts help make React Native apps more secure. 🔒**

