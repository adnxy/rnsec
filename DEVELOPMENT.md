# Testing & Release Workflow

This guide explains how to test changes, fix issues, and release new versions of rnsec to GitHub and npm.

## Local Development & Testing

### 1. Make Changes to Code

Edit scanner files in `src/scanners/` or core files in `src/core/`.

### 2. Build the Project

```bash
npm run build
```

This compiles TypeScript to JavaScript in the `dist/` folder.

### 3. Test Locally

#### Test on Vulnerable App
```bash
node dist/index.js scan --path examples/vulnerable-app
```

#### Test on Secure App
```bash
node dist/index.js scan --path examples/secure-app
```

#### Test supply-chain rules (SUSPICIOUS_LIFECYCLE_SCRIPT, OBFUSCATED_EVAL_EXECUTION)
```bash
node dist/index.js scan --path examples/supply-chain-test
```
Or with JSON output to inspect findings:
```bash
node dist/index.js scan --path examples/supply-chain-test --json
```
The fixture in `examples/supply-chain-test/` contains a `package.json` with suspicious lifecycle scripts and a `preinstall.js` with the `eval(Buffer.from(...).toString())` pattern. Do not run `npm install` in that directory.

#### Test All Commands
```bash
# Check version
node dist/index.js --version

# List all rules
node dist/index.js rules

# Scan with JSON output
node dist/index.js scan --json

# Scan specific path
node dist/index.js scan --path /path/to/your/rn-app
```

### 4. Test as Global Package (Optional)

Link the package globally to test as if installed:

```bash
npm link
rnsec scan --path examples/vulnerable-app
rnsec --version
```

To unlink:
```bash
npm unlink -g rnsec
```

### 5. Lint and Type Check

```bash
npm run lint
```

---

## Release Workflow

### Step 1: Update Version Number

Choose the version bump type based on changes:

- **Patch** (1.1.0 → 1.1.1): Bug fixes, small improvements
- **Minor** (1.1.0 → 1.2.0): New features, backward compatible
- **Major** (1.1.0 → 2.0.0): Breaking changes

#### Manual Version Update

Edit these files:

1. `package.json`: Update `version` field
2. `src/constants.ts`: Update `VERSION` constant
3. `CHANGELOG.md`: Add new version section with changes

#### OR Use npm version command

```bash
# For patch release (1.1.0 → 1.1.1)
npm version patch -m "Release v%s"

# For minor release (1.1.0 → 1.2.0)
npm version minor -m "Release v%s"

# For major release (1.1.0 → 2.0.0)
npm version major -m "Release v%s"
```

This automatically:
- Updates `package.json`
- Creates a git commit
- Creates a git tag

### Step 2: Update CHANGELOG.md

Add a new section at the top:

```markdown
## [1.1.1] - 2026-01-XX

### Fixed
- Fixed import paths for reorganized scanner files
- Improved build process

### Changed
- ...

### Added
- ...
```

### Step 3: Build and Test

```bash
# Clean build
npm run clean
npm run build

# Test the build
node dist/index.js --version
node dist/index.js scan --path examples/vulnerable-app
```

### Step 4: Commit and Push to GitHub

```bash
# Add all changes
git add -A

# Commit with descriptive message
git commit -m "Release v1.1.1

- Fixed import paths after scanner reorganization
- Improved build stability
- Updated documentation
"

# Push to main branch
git push origin main

# Create and push version tag
git tag -a v1.1.1 -m "Release v1.1.1 - Bug fixes and improvements"
git push origin v1.1.1
```

### Step 5: Create GitHub Release

#### Option A: Using GitHub CLI (Recommended)

```bash
gh release create v1.1.1 \
  --title "rnsec v1.1.1" \
  --notes-file RELEASE_NOTES.md
```

#### Option B: Using GitHub Web Interface

1. Go to: https://github.com/adnxy/rnsec/releases/new
2. Select tag: `v1.1.1`
3. Release title: `rnsec v1.1.1`
4. Copy content from `RELEASE_NOTES.md` or write release notes
5. Click "Publish release"

### Step 6: Publish to npm

#### Check Build Quality

```bash
# See what will be published
npm pack --dry-run

# This shows:
# - Which files will be included
# - Package size
# - Any warnings
```

#### Publish to npm

```bash
# Login to npm (if not already)
npm login

# Publish (for public package)
npm publish --access public

# For pre-release versions
npm publish --tag beta
npm publish --tag next
```

#### Verify Publication

```bash
# Check on npm
npm view rnsec version

# Install from npm to test
npm install -g rnsec@latest

# Test installed version
rnsec --version
rnsec scan --path /path/to/test/app
```

---

## Quick Release Checklist

- [ ] All tests pass locally
- [ ] Version number updated in `package.json`, `src/constants.ts`, `CHANGELOG.md`
- [ ] CHANGELOG.md updated with changes
- [ ] Built successfully (`npm run build`)
- [ ] Tested CLI commands work
- [ ] Committed changes to git
- [ ] Pushed to GitHub main branch
- [ ] Created and pushed git tag
- [ ] Created GitHub release
- [ ] Published to npm
- [ ] Verified npm package works
- [ ] Announced on social media/Discord (optional)

---

## Hotfix Workflow (Emergency Fixes)

For critical bugs that need immediate release:

```bash
# 1. Fix the bug
# Edit files...

# 2. Quick test
npm run build
node dist/index.js scan --path examples/vulnerable-app

# 3. Patch version
npm version patch -m "Hotfix v%s: Fix critical import bug"

# 4. Push
git push origin main --tags

# 5. Publish to npm immediately
npm publish --access public

# 6. Create GitHub release
gh release create v1.1.1 --title "Hotfix v1.1.1" --notes "Critical bug fix: Fixed import paths"
```

---

## Troubleshooting

### Build Fails

```bash
# Clean everything and rebuild
npm run clean
rm -rf node_modules package-lock.json
npm install
npm run build
```

### Import Errors

If you see "Cannot find module" errors:
- Check relative import paths (`../../types/` vs `../types/`)
- Ensure all files have `.js` extension in imports (TypeScript requirement for ESM)
- Verify file exists at the import path

### npm Publish Fails

```bash
# Check if you're logged in
npm whoami

# Check if version already exists
npm view rnsec versions

# Check package contents
npm pack --dry-run
```

### Git Tag Already Exists

```bash
# Delete local tag
git tag -d v1.1.1

# Delete remote tag
git push origin :refs/tags/v1.1.1

# Recreate tag
git tag -a v1.1.1 -m "Release v1.1.1"
git push origin v1.1.1
```

---

## Best Practices

1. **Always test before publishing** - Run on real projects
2. **Use semantic versioning** - Follow semver.org rules
3. **Write clear CHANGELOG** - Help users understand changes
4. **Tag every release** - Makes it easy to track history
5. **Test installation** - Install from npm after publishing
6. **Keep commits clean** - Squash WIP commits before release
7. **Document breaking changes** - Mark clearly in CHANGELOG
8. **Update examples** - Keep example apps in sync with changes

---

## Release Frequency

- **Patch releases** (bug fixes): As needed, same day if critical
- **Minor releases** (features): Every 2-4 weeks
- **Major releases** (breaking changes): Every 6-12 months

---

## Version History

- v1.1.0 - Major feature release (13 new rules, improved detection)
- v1.0.1 - CI/CD fixes, documentation improvements  
- v1.0.0 - Initial public release
