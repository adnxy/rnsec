# Roadmap

This document outlines the planned features and improvements for rnsec.

## Version 1.x - Current Release

### Completed
- ✅ 63 security rules across 13 categories
- ✅ HTML and JSON report generation
- ✅ CLI with scan and rules commands
- ✅ Support for React Native and Expo projects
- ✅ Android and iOS platform-specific checks
- ✅ 27+ API key pattern detection
- ✅ Zero-configuration operation

## Version 2.0 - Enhanced Configuration

### Planned Features

#### Custom Rule Configuration
- **Rule Selection**: Enable/disable specific rules via configuration file
- **Severity Customization**: Adjust severity levels per project needs
- **Custom Thresholds**: Configure what constitutes high/medium/low risk
- **Ignore Patterns**: Specify files/directories to exclude from scanning

**Configuration File Example:**
```json
{
  "rnsec": {
    "rules": {
      "STORAGE_ASYNCSTORAGE": "error",
      "HTTP_REQUEST": "warning",
      "EVAL_USAGE": "off"
    },
    "exclude": ["**/*.test.ts", "node_modules/**"],
    "severity": {
      "failOn": "high"
    }
  }
}
```

#### Enhanced Reporting
- PDF report generation
- SARIF format for GitHub Security
- Excel/CSV export for audits
- Custom report templates
- Trend analysis across scans

#### Developer Experience
- VS Code extension for real-time scanning
- Pre-commit hooks integration
- Watch mode for continuous scanning
- Fix suggestions with auto-apply
- Interactive CLI mode

## Version 2.1 - Performance & Scale

### Optimization
- Parallel file processing
- Incremental scanning (scan only changed files)
- Cache results for faster re-scans
- Memory optimization for large projects
- Worker threads for CPU-intensive operations

### Monorepo Support
- Multi-project scanning
- Aggregated reports across projects
- Workspace-aware configuration

## Version 2.2 - Advanced Detection

### New Security Rules
- SQL injection patterns
- XSS vulnerabilities in WebViews
- Insecure data validation
- Business logic flaws
- Race condition detection
- Memory leak patterns

### Enhanced Analysis
- Data flow analysis
- Control flow analysis
- Taint tracking for sensitive data
- Cross-file analysis
- Dependency vulnerability scanning

### Platform Support
- React Native Windows rules
- React Native macOS rules
- Electron security checks

## Version 3.0 - Enterprise Features

### Team Collaboration
- Centralized reporting dashboard
- Team analytics and metrics
- Issue assignment and tracking
- Historical trend visualization
- Compliance reporting (OWASP, PCI-DSS)

### Integration Ecosystem
- Jira integration
- Slack/Teams notifications
- SonarQube plugin
- Azure DevOps extension
- GitLab Security Dashboard

### Advanced Configuration
- Organization-wide policies
- Rule templates and sharing
- Custom rule development API
- Plugin architecture
- Baseline management

## Future Considerations

### Research & Development
- Machine learning for vulnerability detection
- Natural language processing for code comments
- Automated fix generation
- Security training recommendations
- Threat modeling integration

### Community
- Public rule repository
- Community-contributed scanners
- Security challenge platform
- Best practices library

## Contributing to the Roadmap

Have ideas for rnsec? We'd love to hear them!

- **Vote on features**: Star/react to issues labeled `enhancement`
- **Suggest features**: Open an issue with the `feature request` template
- **Contribute**: See [CONTRIBUTING.md](CONTRIBUTING.md) for how to implement features

## Release Schedule

- **Minor releases**: Every 2-3 months
- **Patch releases**: As needed for bugs
- **Major releases**: Annually

## Priority Levels

- **🔴 High**: Next release
- **🟡 Medium**: Within 6 months
- **🟢 Low**: Under consideration

## Current Priorities

| Feature | Priority | Target Version | Status |
|---------|----------|----------------|--------|
| Rule Configuration | 🔴 High | 2.0 | Planning |
| VS Code Extension | 🔴 High | 2.0 | Planning |
| Performance Optimization | 🟡 Medium | 2.1 | Research |
| Advanced Detection | 🟡 Medium | 2.2 | Research |
| Automated Testing | 🔴 High | 1.1 | In Progress |

## Questions?

For roadmap questions or suggestions:
- Open a [GitHub Discussion](https://github.com/adnxy/rnsec/discussions)
- Email: adnanpoviolabs@gmail.com

---

**Note**: This roadmap is subject to change based on community feedback and project priorities.

Last updated: December 2024

