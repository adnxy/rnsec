import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, readFileSync, realpathSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, relative, sep } from 'node:path';
import { scan, repoRoot } from './helpers.mjs';

// Snapshot of what rnsec reports for the bundled examples. Review the diff before updating:
//   UPDATE_SNAPSHOTS=1 node --test tests/examples-snapshot.test.mjs
const snapshotFile = join(repoRoot, 'tests', 'snapshots', 'examples.json');
const EXAMPLES = ['secure-app', 'vulnerable-app', 'supply-chain-test'];

/** Copy only git-tracked files of examples/<name> (so local reports or node_modules cannot influence the scan) */
function copyTracked(name) {
  const out = execFileSync('git', ['ls-files', '-z', '--', `examples/${name}`], { cwd: repoRoot, encoding: 'utf8' });
  const dest = realpathSync(mkdtempSync(join(tmpdir(), `rnsec-snap-${name}-`)));
  for (const rel of out.split('\0').filter(Boolean)) {
    const target = join(dest, relative(`examples/${name}`, rel));
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(repoRoot, rel), target);
  }
  // no network: keep `npm audit` from running
  writeFileSync(join(dest, '.rnsec.jsonc'), JSON.stringify({ npmVulnerabilityScanning: { dataSource: 'hardcoded' } }));
  return dest;
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function snapshotOf(name) {
  const dir = copyTracked(name);
  try {
    const result = scan(dir);
    const findings = result.findings
      .map(f => ({
        ruleId: f.ruleId,
        file: relative(dir, f.filePath).split(sep).join('/'),
        line: f.line ?? null,
        severity: f.severity,
        confidence: f.confidence ?? null,
      }))
      .sort((a, b) =>
        cmp(a.file, b.file) || cmp(a.line ?? 0, b.line ?? 0) || cmp(a.ruleId, b.ruleId) ||
        cmp(a.severity, b.severity) || cmp(a.confidence ?? '', b.confidence ?? ''));
    return { findings, exitCode: result.exitCode };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const key = f => `${f.ruleId}  ${f.file}:${f.line ?? '-'}  ${f.severity}  confidence=${f.confidence ?? '-'}`;

/** Multiset difference a - b */
function minus(a, b) {
  const remaining = new Map();
  for (const f of b) remaining.set(key(f), (remaining.get(key(f)) ?? 0) + 1);
  return a.filter(f => {
    const n = remaining.get(key(f)) ?? 0;
    if (n > 0) { remaining.set(key(f), n - 1); return false; }
    return true;
  });
}

const actual = Object.fromEntries(EXAMPLES.map(name => [name, snapshotOf(name)]));

if (process.env.UPDATE_SNAPSHOTS) {
  mkdirSync(dirname(snapshotFile), { recursive: true });
  writeFileSync(snapshotFile, JSON.stringify(actual, null, 2) + '\n');
}

const expected = existsSync(snapshotFile) ? JSON.parse(readFileSync(snapshotFile, 'utf8')) : {};

for (const name of EXAMPLES) {
  test(`examples/${name} matches the snapshot`, () => {
    const want = expected[name];
    assert.ok(want, `no snapshot for ${name}; run with UPDATE_SNAPSHOTS=1 to create tests/snapshots/examples.json`);
    const got = actual[name];
    const added = minus(got.findings, want.findings);
    const removed = minus(want.findings, got.findings);
    const lines = [];
    if (added.length) lines.push(`Added findings (${added.length}):`, ...added.map(f => `  + ${key(f)}`));
    if (removed.length) lines.push(`Removed findings (${removed.length}):`, ...removed.map(f => `  - ${key(f)}`));
    if (got.exitCode !== want.exitCode) lines.push(`Exit code changed: ${want.exitCode} -> ${got.exitCode}`);
    assert.ok(lines.length === 0, `examples/${name} differs from tests/snapshots/examples.json (UPDATE_SNAPSHOTS=1 to accept):\n${lines.join('\n')}`);
    assert.deepEqual(got, want);
  });
}
