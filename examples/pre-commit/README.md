# Pre-commit hooks

Run rnsec before each commit so that findings at or above a severity stop the commit. All variants run
`npx --no rnsec scan --fail-on high`. `npx --no` never downloads anything: it uses the local install first, then any `rnsec` on `PATH`. Installing rnsec as a project dependency keeps everyone on the same version:

```bash
npm install --save-dev rnsec
```

| File | Use |
|------|-----|
| [`.pre-commit-config.yaml`](.pre-commit-config.yaml) | Local hook for the [pre-commit](https://pre-commit.com) framework (`language: system`) |
| [`git-hook.sh`](git-hook.sh) | Plain git hook; for husky put the same command in `.husky/pre-commit` |

Notes:

- Exit codes: `0` commit proceeds, `1` findings at or above `--fail-on`, `2` rnsec error. Anything but `0` blocks the commit.
- In console mode rnsec writes `rnsec-report.html` and `rnsec-report.json` into the working directory. Add them to `.gitignore`.
- Do not use `--silent` here: it suppresses the console report, so a failed hook shows no reason.
- `--changed-files HEAD` makes the hook faster by scanning only tracked files that differ from `HEAD`, staged ones included. Files git does not track yet (never `git add`ed) are not scanned. The scan then covers only part of the project, so keep a full scan in CI.
- Skip the hook once with `git commit --no-verify`.
