#!/bin/sh
# Plain git pre-commit hook. Install with:
#   cp examples/pre-commit/git-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Husky: put the same command in .husky/pre-commit (a hook file in any directory runs after
#   git config core.hooksPath <directory>).
#
# Recommended: install rnsec as a project dependency (npm install --save-dev rnsec); `npx --no` uses that first,
# falls back to any rnsec on PATH and never downloads. A finding at or above --fail-on makes
# rnsec exit 1 and git aborts the commit; an rnsec error exits 2, which aborts it too.
# Console mode writes rnsec-report.html and rnsec-report.json into the working directory: add both to .gitignore.
# Bypass once with: git commit --no-verify
npx --no rnsec scan --fail-on high
