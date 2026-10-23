import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, existsSync, writeFileSync, symlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { repoRoot, scan, byRule, gitProject } from './helpers.mjs';

const cli = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');

function run(dir, args) {
  return spawnSync('node', [cli, 'scan', '--path', dir, '--json', ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
}

test('--changed-files with --path in a monorepo subfolder resolves paths against the scan root', () => {
  const repo = gitProject({
    'apps/mobile/package.json': '{"name":"mobile","version":"1.0.0"}',
    'apps/mobile/src/a.ts': 'export const a = 1;\n',
    'apps/other/b.ts': "export const password = 'other_secret_password_456';\n",
  }, { commit: true });
  writeFileSync(join(repo, 'apps/mobile/src/a.ts'), "export const config = { password: 'super_secret_password_123' };\n");
  writeFileSync(join(repo, 'apps/other/b.ts'), "export const password = 'changed_secret_password_789';\n");

  const changed = scan(join(repo, 'apps/mobile'), ['--changed-files', 'HEAD']);
  const full = scan(join(repo, 'apps/mobile'));
  assert.equal(byRule(full, 'HARDCODED_SECRETS').length, 1);
  assert.deepEqual(
    byRule(changed, 'HARDCODED_SECRETS').map(f => f.filePath),
    byRule(full, 'HARDCODED_SECRETS').map(f => f.filePath),
    'the changed file under the scan root is found, the change outside it is ignored'
  );
});

test('--changed-files rejects a ref that git would parse as an option (no file is written)', () => {
  const repo = gitProject({ 'a.ts': 'export const a = 1;\n' });
  const out = join(mkdtempSync(join(tmpdir(), 'rnsec-ref-')), 'pwned');
  const r = run(repo, ['--changed-files', `--output=${out}`]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /must not start with "-"/);
  assert.equal(existsSync(out), false);
});

test('--changed-files does not run shell commands embedded in the ref', () => {
  const repo = gitProject({ 'a.ts': 'export const a = 1;\n' });
  const marker = join(mkdtempSync(join(tmpdir(), 'rnsec-ref-')), 'PWNED2');
  const r = run(repo, ['--changed-files', `HEAD;touch ${marker}`]);
  assert.notEqual(r.status, 0);
  assert.equal(existsSync(marker), false);
});

test('--changed-files reports unreadable changed files on stderr, in --json and normal mode', () => {
  const repo = gitProject({ 'a.ts': 'export const a = 1;\n' });
  symlinkSync(join(repo, 'does-not-exist'), join(repo, 'broken.ts'));
  execFileSync('git', ['add', '-A'], { cwd: repo });

  const json = run(repo, ['--changed-files', 'HEAD']);
  assert.match(json.stderr, /1 file\(s\) skipped due to read errors/);
  JSON.parse(json.stdout);

  const normal = spawnSync('node', [cli, 'scan', '--path', repo, '--changed-files', 'HEAD'], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  assert.match(normal.stderr + normal.stdout, /1 file\(s\) skipped due to read errors/);
});
