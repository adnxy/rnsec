# Adding a rule

A new rule touches the scanner, the OWASP mapping, the fixtures and a few generated or counted places. `npm test` fails when one is missed.

## 1. Write the rule

Rules live in `src/scanners/`, grouped by area (`security/`, `android/`, `ios/`, `react-native/`, `modules/`). A rule is an object that implements `Rule` from `src/types/ruleTypes.ts`:

```typescript
const yourRule: Rule = {
  id: 'YOUR_RULE_ID',                    // SCREAMING_SNAKE_CASE, unique, never renamed later (users put it in ignoredRules)
  description: 'Clear description of the security issue',
  severity: Severity.HIGH,               // default severity; a finding may report another one
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    // detection logic
    return findings;
  },
};
```

Rule definitions know nothing about OWASP: do not add standards data to the rule or its findings.

## 2. Register it in a group

Add the rule to the `rules` array of the group at the bottom of its scanner file (for example `storageRules`). A rule in a group that is already registered is picked up everywhere.

If you create a **new group**, register it in three places, or tests fail:

1. `registerAllRules()` in `src/cli/index.ts`
2. the `groups` list in `tests/owasp-mappings.test.mjs`
3. the `GROUPS` list in `scripts/generate-owasp-docs.mjs`

## 3. Map it to OWASP, or say why not

Every registered rule must be in exactly one of two tables in `src/standards/owasp/mappings.ts`.

**Mapped:** add an entry to `RULE_STANDARDS`:

```typescript
ANDROID_BACKUP_ALLOWED: {
  title: "Android backup allowed",       // short human title
  maswe: ["MASWE-0006"],                 // MASVS controls are derived from these
  mastg: ["MASTG-TEST-0216", "MASTG-TEST-0262"],  // optional: static tests whose title matches the check
  cwe: [212],                            // optional: only numbers you are sure about
  platform: ["android"],                 // android | ios | cross-platform | expo
  confidence: "high",                    // how well the check matches the weakness
  // mappingNote: "Optional: why the mapping is as narrow as it is.",
},
```

(An existing entry of `RULE_STANDARDS`; use your rule's ID as the key.)

- Pick the MASWE entry that describes the weakness. `masvs` is derived from the MASWE entries; write an explicit `masvs` only when it must be narrower than that union (say why in a comment) or when no MASWE fits.
- List only static MASTG tests (titles such as "References to...", "Hardcoded...", "Configurations Allowing..."). A MASTG test may only be listed when it links to one of the rule's MASWE entries and runs on a platform the rule targets.
- Presence/absence heuristics ("X not found") must be `confidence: "low"`. A control is reported as `checked-heuristic` when all of its applicable mapped rules are low confidence; one higher-confidence rule makes it `checked`.
- `platform` decides whether a control is `not-applicable` for a project without that platform.

**Unmapped:** if no MASVS control honestly fits, add the rule to `UNMAPPED_RULES` with a one-sentence reason. An empty reason fails the tests, and a rule in both tables fails too.

### The pinned snapshot policy

Only IDs that exist in `src/standards/owasp/snapshot.json` are allowed: MASVS 2.1.0, MASWE 1.0.0 and the pinned MASTG (`v2.0.0 + master@2eb0f70`, see the `sources` block of the file). `tests/owasp-mappings.test.mjs` fails on an unknown MASVS, MASWE or MASTG ID, and on one without an official page URL. Do not edit `snapshot.json` by hand and do not invent IDs.

To move to newer official data:

1. Change the pins (`PINS`: version, commit, URL) in `scripts/update-owasp-snapshot.mjs`.
2. Run `node scripts/update-owasp-snapshot.mjs`. It needs network access, `curl`, `tar` and `git`, verifies every pinned commit and cross reference, and rewrites `snapshot.json` deterministically.
3. If MASWE or MASTG IDs were added, add them to `MASWE_FOLDER` / `MASTG_FOLDER` in `src/standards/owasp/index.ts` (the category folder on mas.owasp.org), otherwise their URLs resolve to `undefined` and the URL test fails.
4. Fix mappings that now point at renamed or removed IDs, then run the checks in step 6.

## 4. Add fixtures

Add a positive fixture and a near-miss under `tests/cases/`:

- `tests/cases/cov-<rule>/` triggers the rule (a small project: `package.json` plus the file that triggers it)
- `tests/cases/cov-<rule>-neg/` looks similar but must not trigger it

Assert both from a test, for example by adding a row to the `cases` list in `tests/rule-coverage.test.mjs` (rule, fixture directory, file name, expected `[line, severity]` of each finding). `scan()` and `byRule()` in `tests/helpers.mjs` run the built CLI on a fixture and pick out one rule's findings. Fixtures with provider-shaped secrets must use the `{{fake:kind}}` markers from `tests/helpers.mjs`, never real-looking literals.

## 5. Keep the counted and generated places in step

- Rule counts: `README.md` (every "N security rules" / "N different security issues", and the category table, whose rows must sum to the total) and the `description` in `package.json`. `tests/docs-consistency.test.mjs` compares them with `rnsec rules`.
- `CHANGELOG.md`: name the rule ID (in backticks) in the `## [Unreleased]` section. The same test checks that the rule IDs named there exist.
- `docs/owasp-coverage.md` is generated from the mapping: run `npm run docs:owasp` and commit the result. `tests/owasp-docs.test.mjs` fails when it is stale.
- `tests/snapshots/examples.json` (scans of `examples/`) changes when the rule fires there: after checking the diff is intended, run `UPDATE_SNAPSHOTS=1 npm test`.

## 6. Run the checks

```bash
npm run lint                  # type check
npm test                      # builds, then runs every test, including the mapping, docs and fixture tests
npm run docs:owasp            # regenerate docs/owasp-coverage.md after any mapping change
```

`tests/owasp-mappings.test.mjs` is the one to read when the mapping fails: it checks that every registered rule is mapped xor unmapped (and neither table has stale IDs), that every referenced ID exists in the snapshot, that `masvs` stays within the MASWE union, that MASTG tests fit the rule's platform and MASWE links, and that every ID has an official URL.
