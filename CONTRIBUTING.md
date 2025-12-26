# Contributing to rnsec

Thank you for your interest in contributing to rnsec!

## Quick Start

```bash
# Clone the repository
git clone https://github.com/adnxy/rnsec.git
cd rnsec

# Install dependencies
npm install

# Build the project
npm run build

# Test it locally
npm link
rnsec scan examples/vulnerable-app
```

## How to Contribute

### Reporting Bugs

[Open an issue](https://github.com/adnxy/rnsec/issues/new?template=bug_report.md) with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Node version)

### Suggesting Features

[Open an issue](https://github.com/adnxy/rnsec/issues/new?template=feature_request.md) with:
- Use case description
- Proposed solution
- Why it would be useful

### Submitting Pull Requests

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/your-feature`
3. **Make your changes** following the code structure
4. **Build**: `npm run build`
5. **Test**: Test with the example apps
6. **Commit**: Use clear commit messages
7. **Push**: `git push origin feature/your-feature`
8. **Open a PR** with a clear description

### Adding Security Rules

New security rules are welcome! Place them in the appropriate scanner file in `src/scanners/`.

Example:
```typescript
const yourRule: Rule = {
  id: 'YOUR_RULE_ID',
  description: 'Clear description of the security issue',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    // Your detection logic
    return findings;
  },
};
```

## Code Style

- TypeScript with strict mode
- Clear, descriptive variable names
- JSDoc comments for public functions
- Keep functions focused and small

## Project Structure

```
src/
├── cli/           # Command-line interface
├── core/          # Core engine (parser, walker, reporter)
├── scanners/      # Security rule implementations
├── types/         # TypeScript type definitions
└── utils/         # Utility functions
```

## Questions?

- Open an [issue](https://github.com/adnxy/rnsec/issues)
- Email: adnanpoviolabs@gmail.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
