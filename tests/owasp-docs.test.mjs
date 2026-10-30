import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { repoRoot } from './helpers.mjs';
import { renderOwaspDocs, OUT_FILE } from '../scripts/generate-owasp-docs.mjs';

// docs/owasp-coverage.md is generated from the mapping table (dist/), so it cannot drift:
// after changing mappings.ts, snapshot.json or the rules, run `npm run docs:owasp` and commit the result.

test('docs/owasp-coverage.md is up to date with the OWASP mapping', async () => {
  assert.equal(OUT_FILE, resolve(repoRoot, 'docs/owasp-coverage.md'));
  const expected = await renderOwaspDocs();
  const committed = readFileSync(OUT_FILE, 'utf8');
  assert.equal(committed, expected, 'docs/owasp-coverage.md is stale: run `npm run docs:owasp` and commit the result');
});

test('the generated matrix has one row per MASVS control and per rule', async () => {
  const text = await renderOwaspDocs();
  assert.equal([...text.matchAll(/^\| MASVS-[A-Z]+-\d+ \|/gm)].length, 24);
  const ruleRows = [...text.matchAll(/^\| `([A-Z0-9_]+)` \| /gm)].map(m => m[1]);
  // mapped rules (reference table) and unmapped rules; the control table lists IDs inside a cell, not as a row start
  assert.equal(new Set(ruleRows).size, ruleRows.length, 'a rule appears in more than one table');
});
