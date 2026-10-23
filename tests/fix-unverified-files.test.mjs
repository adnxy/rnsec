import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { repoRoot, untrackedProject } from './helpers.mjs';

const cli = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');
const NOTICE = /Note: 1 file\(s\) \(\.env, credential or registry config\) were not checked: .* is not a git repository/;

function run(dir, args = []) {
  return spawnSync('node', [cli, 'scan', '--path', dir, '--json', ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
}

/** A directory outside any git repository that holds an .env file. */
function nonGitProject() {
  const dir = mkdtempSync(join(tmpdir(), 'rnsec-nogit-'));
  writeFileSync(join(dir, '.env'), 'API_SECRET=abc123def456\n');
  writeFileSync(join(dir, 'a.ts'), 'export const a = 1;\n');
  return dir;
}

test('outside git: .env candidates produce a stderr notice, stdout stays JSON, exit code is unchanged', () => {
  const dir = nonGitProject();
  const r = run(dir);
  assert.match(r.stderr, NOTICE);
  assert.doesNotMatch(r.stdout, /not checked/);
  JSON.parse(r.stdout);
  assert.equal(r.status, 0);
});

test('outside git: --silent prints no notice', () => {
  const r = run(nonGitProject(), ['--silent']);
  assert.doesNotMatch(r.stderr, /not checked/);
});

test('outside git: no candidate files, no notice', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rnsec-nogit-'));
  writeFileSync(join(dir, 'a.ts'), 'export const a = 1;\n');
  assert.doesNotMatch(run(dir).stderr, /not checked/);
});

test('inside git: an untracked .env prints no notice (tracking could be checked)', () => {
  const dir = untrackedProject({ '.env': 'API_SECRET=abc123def456\n' });
  assert.doesNotMatch(run(dir).stderr, /not checked/);
});
