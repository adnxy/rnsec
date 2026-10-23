import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { repoRoot } from './helpers.mjs';

// Keeps the docs in step with the code: rule counts, README category table, versions and
// the rule IDs named in the newest CHANGELOG section must match what the CLI reports.
// Like the other tests this runs the built CLI (override with RNSEC_BIN=.build-x/index.js).
const cli = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');
const read = file => readFileSync(join(repoRoot, file), 'utf8');

const run = spawnSync('node', [cli, 'rules'], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
assert.equal(run.status, 0, `rnsec rules failed:\n${run.stderr}`);
// Strip ANSI codes in case the output is colored despite NO_COLOR
const output = run.stdout.replace(/\u001b\[[0-9;]*m/g, '');

const total = Number(output.match(/Total:\s*(\d+) security rules loaded/)?.[1]);
const ruleIds = new Set([...output.matchAll(/▸ ([A-Z][A-Z0-9_]+)/g)].map(m => m[1]));

const readme = read('README.md');
const pkg = JSON.parse(read('package.json'));
const changelog = read('CHANGELOG.md');

/** Body of the newest CHANGELOG section (from its `## [x.y.z]` heading to the next one) */
function topChangelogSection() {
  const heading = changelog.match(/^## \[(\d+\.\d+\.\d+)\][^\n]*$/m);
  const start = heading.index;
  const next = changelog.indexOf('\n## [', start + 1);
  return { version: heading[1], body: changelog.slice(start, next === -1 ? undefined : next) };
}

test('rules command reports a plausible total', () => {
  assert.ok(Number.isInteger(total) && total > 0, `could not read the total from:\n${output.slice(-300)}`);
  assert.equal(ruleIds.size, total, 'the number of listed rule IDs differs from "Total: N security rules loaded"');
});

test('every "N security rules" / "N different security issues" count in README.md matches the CLI', () => {
  const counts = [...readme.matchAll(/\b(\d+) (?:different )?security (?:rules|issues)\b/g)].map(m => Number(m[1]));
  assert.ok(counts.length >= 3, `expected at least 3 rule counts in README.md, found ${counts.length}`);
  for (const n of counts) assert.equal(n, total, `README.md says ${n}, the CLI lists ${total}`);
});

test('package.json description states the rule count', () => {
  const counts = [...pkg.description.matchAll(/\b(\d+) (?:different )?security (?:rules|issues)\b/g)].map(m => Number(m[1]));
  assert.ok(counts.length >= 1, `no rule count in the package.json description: ${pkg.description}`);
  for (const n of counts) assert.equal(n, total, `package.json says ${n}, the CLI lists ${total}`);
});

test('README category table sums to the rule total', () => {
  const rows = [...readme.matchAll(/^\| \*\*(.+?)\*\* \| (\d+) \|/gm)].map(m => [m[1], Number(m[2])]);
  assert.ok(rows.length > 0, 'no category rows found in README.md');
  const sum = rows.reduce((acc, [, n]) => acc + n, 0);
  assert.equal(sum, total, `category table sums to ${sum}, the CLI lists ${total}: ${rows.map(r => r.join('=')).join(', ')}`);
  const categories = readme.match(/across (\d+) categories/);
  if (categories) assert.equal(Number(categories[1]), rows.length, 'README category count differs from the table');
});

test('package.json, package-lock.json, src/constants.ts and the CHANGELOG agree on the version', () => {
  const constant = read('src/constants.ts').match(/VERSION = '([^']+)'/)?.[1];
  const lock = JSON.parse(read('package-lock.json'));
  const { version } = topChangelogSection();
  assert.equal(constant, pkg.version, 'src/constants.ts VERSION differs from package.json');
  assert.equal(version, pkg.version, 'top CHANGELOG.md heading differs from package.json');
  assert.equal(lock.version, pkg.version, 'package-lock.json version differs from package.json');
  assert.equal(lock.packages[''].version, pkg.version, 'package-lock.json root package version differs from package.json');
});

test('every rule ID named in the newest CHANGELOG section exists', () => {
  const { version, body } = topChangelogSection();
  // Backticked SCREAMING_SNAKE tokens that are not rule IDs
  const notRules = new Set(['RNSEC_VERBOSE', 'RULE_ID', 'NODE_ENV', 'PRIVATE_KEY', 'AFTER_FIRST_UNLOCK']);
  const mentioned = new Set(
    [...body.matchAll(/`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`/g)].map(m => m[1]).filter(id => !notRules.has(id))
  );
  assert.ok(mentioned.size > 0, `no rule IDs found in the CHANGELOG [${version}] section`);
  const unknown = [...mentioned].filter(id => !ruleIds.has(id));
  assert.deepEqual(unknown, [], `CHANGELOG [${version}] names rule IDs that do not exist: ${unknown.join(', ')}`);
});
