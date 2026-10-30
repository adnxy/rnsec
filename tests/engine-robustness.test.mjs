import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan, byRule, ids, repoRoot, casesDir } from './helpers.mjs';

/** Write `files` (path -> content) into a fresh directory, optionally nested under `prefix`, and return the project root. */
function project(files, prefix = '') {
  const base = mkdtempSync(join(tmpdir(), 'rnsec-rb-'));
  const root = prefix ? join(base, prefix) : base;
  for (const [rel, content] of Object.entries(files)) {
    const full = join(root, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

const cli = join(repoRoot, 'dist/index.js');
const runCli = (dir, args = []) =>
  spawnSync('node', [cli, 'scan', '--path', dir, '--json', ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });

// ---- robustness ----------------------------------------------------------------------------------------------

test('no rule throws on awkward syntax (numeric/computed/spread keys, enums, decorators, templates, optional chaining)', () => {
  const dir = join(casesDir, 'awkward-syntax');
  const run = runCli(dir);
  const r = JSON.parse(run.stdout);
  assert.deepEqual(r.ruleErrors ?? [], [], `rules threw: ${JSON.stringify(r.ruleErrors)}`);
  assert.equal(r.parseFailures, undefined, 'fixture must parse');
  assert.ok(!/Scan incomplete/.test(run.stderr), run.stderr);
  // the fixture is not inert: rules did run over it
  assert.ok(r.findings.length > 5, `expected findings on the fixture, got ${ids(r)}`);
});

test('INSECURE_WEBSOCKET survives numeric/computed keys and still reports a ws:// url key', () => {
  const dir = project({
    'src/socket.ts': [
      "const cfg = {",
      "  1: 'ws://api.example-corp.com/numeric',",
      "  [`k${Date.now()}`]: 'ws://api.example-corp.com/computed',",
      "  url: 'ws://api.example-corp.com/socket',",
      '};',
      'export default cfg;',
    ].join('\n'),
  });
  const run = runCli(dir);
  const r = JSON.parse(run.stdout);
  assert.deepEqual(r.ruleErrors ?? [], []);
  const lines = byRule(r, 'INSECURE_WEBSOCKET').map(f => f.line);
  assert.ok(lines.includes(4), `the url key must still fire, got ${lines}`);
});

test('a parse failure is counted, warned about on stderr, and stdout stays pure JSON', () => {
  const dir = project({ 'src/broken.ts': 'const = ;\nfunction (){', 'src/ok.ts': "fetch('http://api.example-corp.com/x');\n" });
  const run = runCli(dir);
  const r = JSON.parse(run.stdout);
  assert.equal(r.parseFailures, 1);
  assert.match(run.stderr, /Scan incomplete: 1 file\(s\) failed to parse/);
  assert.ok(ids(r).includes('INSECURE_HTTP_URL'), 'other files are still scanned');
});

test('a clean scan has neither field in the JSON nor a warning', () => {
  const dir = project({ 'src/ok.ts': 'export const x = 1;\n' });
  const run = runCli(dir);
  const r = JSON.parse(run.stdout);
  assert.ok(!('ruleErrors' in r) && !('parseFailures' in r));
  assert.ok(!/Scan incomplete/.test(run.stderr));
});

test('the engine collects a throwing rule instead of hiding it, and keeps scanning', async () => {
  const { RuleEngine } = await import(join(repoRoot, 'dist/core/ruleEngine.js'));
  const dir = project({ 'src/a.ts': 'export const a = 1;\n' });
  const engine = new RuleEngine();
  engine.setRespectGitignore(false);
  engine.registerRuleGroup({
    category: 'CONFIG',
    rules: [
      { id: 'BOOM', description: 'x', severity: 'LOW', fileTypes: ['.ts'], apply: async () => { throw new TypeError('x.toLowerCase is not a function'); } },
      { id: 'FINE', description: 'x', severity: 'LOW', fileTypes: ['.ts'], apply: async c => [{ ruleId: 'FINE', description: 'ok', severity: 'LOW', filePath: c.filePath, line: 1 }] },
    ],
  });
  const res = await engine.runRulesOnProject(dir);
  assert.equal(res.ruleErrors.length, 1);
  assert.equal(res.ruleErrors[0].ruleId, 'BOOM');
  assert.match(res.ruleErrors[0].filePath, /a\.ts$/);
  assert.match(res.ruleErrors[0].message, /toLowerCase/);
  assert.equal(res.findings.length, 1);
});

// ---- file roles: code-pattern rules skip non-app source and bundles, secret rules do not -----------------------

const LINKING = "import { Linking } from 'react-native';\nexport const open = (url: string) => Linking.openURL(url);\n";
const SECRET = "export const stripeKey = '" + 'sk_' + 'live_' + "51Nq7XaB3cD9eF2gH5iJ8kL1mN4oP7qR0sT';\n";

test('INSECURE_LINKING_OPEN fires in app code and not in scripts/ or generated bundles', () => {
  const dir = project({ 'src/open.ts': LINKING, 'scripts/open.ts': LINKING, 'src/vendor-lib.bundle.js': LINKING.replace('export ', '') });
  const files = byRule(JSON.parse(runCli(dir).stdout), 'INSECURE_LINKING_OPEN').map(f => f.filePath.slice(dir.length + 1));
  assert.deepEqual(files, ['src/open.ts']);
});

test('a bundle banner marks a file generated even when its name is ordinary', () => {
  const dir = project({ 'src/open.ts': LINKING, 'src/chunk.js': '/*! For license information */\n' + LINKING.replace('export ', '') });
  const files = byRule(JSON.parse(runCli(dir).stdout), 'INSECURE_LINKING_OPEN').map(f => f.filePath.slice(dir.length + 1));
  assert.deepEqual(files, ['src/open.ts']);
});

test('secret rules still fire in scripts/ and in generated bundles', () => {
  const dir = project({ 'scripts/deploy.ts': SECRET, 'src/app.bundle.js': SECRET.replace('export ', '') });
  const files = byRule(JSON.parse(runCli(dir).stdout), 'API_KEY_EXPOSED').map(f => f.filePath.slice(dir.length + 1)).sort();
  assert.deepEqual(files, ['scripts/deploy.ts', 'src/app.bundle.js']);
});

// ---- root-relative path gating -------------------------------------------------------------------------------

const LOGIN_NO_TIMEOUT = "export async function login(user: string) { return fetch('https://api.example-corp.com/login', { method: 'POST', body: user }); }\n";

test('MISSING_SESSION_TIMEOUT keys on the root-relative path, not on where the repo is checked out', () => {
  const inAuthDir = project({ 'src/util.ts': LOGIN_NO_TIMEOUT }, 'auth-session-app');
  assert.equal(byRule(JSON.parse(runCli(inAuthDir).stdout), 'MISSING_SESSION_TIMEOUT').length, 0, 'checkout dir name must not matter');
  const inside = project({ 'src/auth/login.ts': LOGIN_NO_TIMEOUT });
  const found = byRule(JSON.parse(runCli(inside).stdout), 'MISSING_SESSION_TIMEOUT');
  assert.equal(found.length, 1);
  assert.equal(found[0].confidence, 'low');
});

const WALLET_INDEX = "export const label = 'wallet';\n";

test('IOS_MISSING_APP_SNAPSHOT_PROTECTION ignores `index.` in the checkout path and still fires for App.tsx', () => {
  const dir = project({ 'src/wallet.ts': WALLET_INDEX }, 'index.checkout');
  assert.equal(byRule(JSON.parse(runCli(dir).stdout), 'IOS_MISSING_APP_SNAPSHOT_PROTECTION').length, 0);
  const app = project({ 'App.tsx': WALLET_INDEX });
  assert.equal(byRule(JSON.parse(runCli(app).stdout), 'IOS_MISSING_APP_SNAPSHOT_PROTECTION').length, 1);
});

const screen = secure => `import React from 'react';
import { TextInput, View } from 'react-native';
export default function Login() {
  return (<View><TextInput ${secure} placeholder="user" /></View>);
}
`;

test('SCREENSHOT_PROTECTION_MISSING ignores a /screens/ checkout dir, and secureTextEntry={false} is not sensitive', () => {
  const nested = project({ 'src/Login.tsx': screen('secureTextEntry') }, 'screens/app');
  assert.equal(byRule(JSON.parse(runCli(nested).stdout), 'SCREENSHOT_PROTECTION_MISSING').length, 0, 'abs path must not count as a screen');
  for (const [attr, expected] of [['secureTextEntry', 1], ['secureTextEntry={true}', 1], ['secureTextEntry={false}', 0], ['secureTextEntry={null}', 0]]) {
    const dir = project({ 'src/screens/Login.tsx': screen(attr) });
    const found = byRule(JSON.parse(runCli(dir).stdout), 'SCREENSHOT_PROTECTION_MISSING');
    assert.equal(found.length, expected, attr);
    if (expected) assert.equal(found[0].confidence, 'low');
  }
});

// ---- confidence ----------------------------------------------------------------------------------------------

test('heuristic rules carry an explicit confidence so --min-confidence can hide them', () => {
  const dir = project({
    'src/auth/login.ts': LOGIN_NO_TIMEOUT,
    'src/screens/Login.tsx': screen('secureTextEntry'),
    // a named untrusted source (route params) is medium; a bare parameter is low
    'src/open.ts': "import { Linking } from 'react-native';\nexport const open = (route: any) => Linking.openURL(route.params.url);\n",
    'src/nav.ts': "export const go = (navigation: any, token: string) => navigation.navigate('Home', { authToken: token });\n",
  });
  const all = JSON.parse(runCli(dir).stdout);
  const expected = { MISSING_SESSION_TIMEOUT: 'low', SCREENSHOT_PROTECTION_MISSING: 'low', INSECURE_LINKING_OPEN: 'medium', SENSITIVE_NAVIGATION_PARAMS: 'low' };
  for (const [rule, confidence] of Object.entries(expected)) {
    const found = byRule(all, rule);
    assert.ok(found.length >= 1, `${rule} did not fire`);
    for (const f of found) assert.equal(f.confidence, confidence, rule);
  }
  const high = JSON.parse(runCli(dir, ['--min-confidence', 'high']).stdout);
  for (const rule of Object.keys(expected)) assert.equal(byRule(high, rule).length, 0, `${rule} must be hidden at --min-confidence high`);
});
