# Benchmark

`bench/` is a dev-only harness that scans a fixed set of open-source React Native apps and reports how many findings rnsec produces. It exists to see the effect of a rule change on real code. It is not shipped in the npm package and is not part of `npm test`.

**Results are directional.** They measure finding volume and whether known true positives are still reported. They do not give precision as a percentage: there is no labelled hold-out set. For 1.5.0, the volume went from 1460 to 524 default-output findings (533 with the four new rules), based on hand sampling of about 200 removed findings, all but one of which were correct removals (the one regression was fixed). Retained findings are mostly "plausible, needs review", not confirmed exploitable.

## Corpus

`bench/corpus.json` lists 8 apps with a URL, a full commit SHA and the sub-path to scan: bluesky social-app, mattermost-mobile, Rocket.Chat.ReactNative, BlueWallet, metamask-mobile, eigen, joplin (`packages/app-mobile`) and the ignite boilerplate (`boilerplate`). The ignite SHA is the default-branch HEAD at the time it was first scanned (2026-10-30). If a pinned SHA cannot be fetched, the run records `shaExact: false` in the metadata.

## Running it

```bash
npm run build
node bench/run.mjs --dir <clones dir> --out <results dir>
node bench/report.mjs --out <results dir> --save <aggregate.json>
```

- `--dir` and `--out` must be outside the rnsec repository (the script refuses otherwise).
- `run.mjs` also accepts `--only name,name`, `--no-clone` (reuse the clones as they are) and `--verbose` (sets `RNSEC_VERBOSE=1`, so rule exceptions appear in the stderr files).
- For each app it writes `<name>.json` (the scan output, `--format json`), `<name>.stderr.txt` and `<name>.meta.json` (exit code, duration, finding count, rnsec version and commit, pinned and actual SHA).
- To compare with an earlier run, save its aggregate with `--save` and pass it to a later report:

```bash
node bench/report.mjs --out <new results dir> --compare <aggregate.json>
```

The report prints findings per rule and per app, and with `--compare` the per-rule and per-app delta and the total change.

## Known-true-positive gate

```bash
node bench/check-tps.mjs bench/known-tps.json <results dir>
```

The input is `{ "tps": [ { "repo", "rule", "file", "line" } ] }`. A true positive is still reported when a finding has the same rule, a file path ending in `/<repo>/<file>`, and (if `line` is given) a line within 3 of it. The script prints `OK` or `LOST` per entry and exits 1 if any is lost.

The 12 entries used for 1.5.0 are a **reconstructed** gate: a list of known real findings rebuilt for this check. It is small, it is not a sample of the corpus, and one entry (a fourth `IOS_ATS_DISABLED` true positive from the 1.4.0 labels) could not be located, because the original labels were lost. The list is committed as `bench/known-tps.json`. Passing the gate means those 12 are still found. It says nothing about other true positives that were never identified.

## Safety: clones are untrusted

- The clones are never built, installed or executed. They are shallow, `--no-checkout` clones fetched with git hooks and fsmonitor disabled and `GIT_LFS_SKIP_SMUDGE=1`; rnsec only reads the files.
- npm vulnerability scanning is disabled so that no `npm audit` runs in a clone. Two mechanisms: `run.mjs` writes `npmVulnerabilityScanning: { enabled: false }` into a `.rnsec.json` in each scan root (merged with an existing one, with a note in the metadata), and it puts a stub `npm` first on `PATH` that logs the call and exits 1. The calls are recorded in `npm-calls.log` and counted per app as `npmCalls` in the metadata. It should be 0.
- Do not run `npm install`, build scripts or the apps' own tooling inside the clone directory.

## Limits

- Eight apps are not representative of all React Native code.
- The scan root is rnsec's project root, so project-level findings are counted once per root.
- A drop in findings is not by itself an improvement. Check what was removed.
