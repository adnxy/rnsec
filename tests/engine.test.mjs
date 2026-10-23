import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, ids, byRule, gitProject, fakeSecret } from './helpers.mjs';

test('__DEV__ guard elsewhere in a file does not hide real secrets', () => {
  const r = scan('debug-filter-local');
  const secrets = r.findings.filter(f => f.ruleId === 'API_KEY_EXPOSED');
  assert.ok(secrets.length >= 1, `expected a secret finding, got ${ids(r)}`);
  assert.ok(secrets.some(f => f.line === 2), 'live key on line 2 must be reported');
});

test('code inside a __DEV__ block IS suppressed, else-branch is not', () => {
  const r = scan('debug-filter-local');
  const lines = byRule(r, 'INSECURE_HTTP_URL').map(f => f.line);
  assert.ok(!lines.includes(7), 'http inside if (__DEV__) must be suppressed');
  assert.ok(lines.includes(9), 'http in the else branch must be reported');
});

test('rnsec-ignore suppresses only the named rule on that line', () => {
  const r = scan('inline-suppression');
  const http = byRule(r, 'INSECURE_HTTP_URL').map(f => f.line);
  assert.deepEqual(http, [4, 5], 'only line 3 (named rule, next line) is suppressed');
  const timeouts = byRule(r, 'NO_REQUEST_TIMEOUT').map(f => f.line);
  assert.ok(!timeouts.includes(5), 'trailing comment suppresses NO_REQUEST_TIMEOUT on its own line');
  assert.ok(timeouts.includes(4), 'other lines keep their findings');
});

test('projects living under dev/assets folders are not suppressed by absolute path', () => {
  const r = scan('dev-assets-path/dev/assets/app');
  assert.ok(byRule(r, 'API_KEY_EXPOSED').length >= 1);
});

test('.rnsec.jsonc with comments and globs loads', () => {
  const r = scan('jsonc-config');
  assert.ok(!ids(r).includes('INSECURE_HTTP_URL'), 'ignoredRules from the JSONC file must apply');
});

import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

test('--changed-files honours default and configured excludes', () => {
  const http = "fetch('http://api.example-corp.com/x');\n";
  const dir = gitProject({
    'src/App.tsx': http,
    'dist/bundle.js': http,
    'legacy/old.ts': http,
    'src/__mocks__/api.ts': http,
    '.rnsec.json': JSON.stringify({ exclude: ['legacy/**'] }),
  });
  const r = scan(dir, ['--changed-files', 'HEAD']);
  const files = [...new Set(byRule(r, 'INSECURE_HTTP_URL').map(f => f.filePath.split('/').slice(-2).join('/')))];
  assert.deepEqual(files, ['src/App.tsx']);
});

test('tracked .env files are scanned, untracked ones are not', () => {
  const secret = `STRIPE_SECRET_KEY=${fakeSecret('stripe_live')}\n`;
  const dir = gitProject({ '.env': secret });
  assert.ok(ids(scan(dir)).includes('ENV_FILE_COMMITTED') || ids(scan(dir)).includes('API_KEY_EXPOSED'));

  const dir2 = gitProject({});
  writeFileSync(join(dir2, '.env'), secret); // never added to git
  const r2 = scan(dir2);
  assert.ok(!ids(r2).includes('ENV_FILE_COMMITTED') && !ids(r2).includes('API_KEY_EXPOSED'));
});

test('large --json output is not truncated when piped and exit code is preserved', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rnsec-big-'));
  const lines = [];
  for (let i = 0; i < 400; i++) lines.push(`fetch('http://api${i}.example-corp.com/x');`);
  lines.push(`export const key = '${fakeSecret('stripe_live')}';`);
  writeFileSync(join(dir, 'App.tsx'), lines.join('\n'));
  const r = scan(dir); // scan() parses stdout from a pipe; throws if truncated
  assert.ok(r.findings.length >= 400);
  assert.equal(r.exitCode, 1, 'HIGH finding must still produce exit code 1');
});

test('dev-only filter: one-line ternary and compound guards never hide production code', () => {
  const r = scan('debug-filter-shapes');
  const keyLines = byRule(r, 'API_KEY_EXPOSED').map(f => f.line);
  assert.ok(keyLines.includes(3), 'live key in the alternate of a one-line __DEV__ ternary must be reported');
  const http = byRule(r, 'INSECURE_HTTP_URL').map(f => f.line);
  // line 7 (!__DEV__ && flag) is production code: reported. line 9 (else of that if) is reachable in production: reported.
  assert.ok(http.includes(7) && http.includes(9), `prod branches must be reported, got ${http}`);
  // lines 14, 15, 16, 17 only run in development builds
  for (const l of [14, 15, 16, 17]) assert.ok(!http.includes(l), `dev-only line ${l} must be suppressed, got ${http}`);
});

test('related rules report the same issue once per line (most specific rule wins)', () => {
  const r = scan('dedup-families');
  const byLine = {};
  for (const f of r.findings) (byLine[f.line] ??= []).push(f.ruleId);
  for (const l of [4, 6, 9]) {
    assert.ok(byLine[l]?.length === 1, `line ${l} must carry exactly one finding, got ${JSON.stringify(byLine[l])}`);
  }
  assert.equal(byLine[4][0], 'MMKV_UNENCRYPTED_SENSITIVE_DATA');
  assert.equal(byLine[6][0], 'JWT_INSECURE_SIGNING');
  assert.equal(byLine[9][0], 'JWT_INSECURE_SIGNING');
  assert.deepEqual(byLine[13], ['SENSITIVE_LOGGING'], 'logging an error + token is one finding');
});
