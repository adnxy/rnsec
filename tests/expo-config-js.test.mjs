import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, byRule, gitProject } from './helpers.mjs';

// EXPO_UPDATES_INSECURE_URL, EXPO_UPDATES_NO_CODE_SIGNING and EXPO_INSECURE_PERMISSIONS read static
// object-literal app.config.js/ts as well as app.json. Dynamic values are never reported.
const summary = (r, id) => byRule(r, id).map(f => [f.filePath.split('/').pop(), f.line, f.severity]).sort((a, b) => a[1] - b[1]);
const RULES = ['EXPO_UPDATES_INSECURE_URL', 'EXPO_UPDATES_NO_CODE_SIGNING', 'EXPO_INSECURE_PERMISSIONS'];

test('app.config.ts `export default { expo: {...} }`: insecure url, no code signing and permission with lines', () => {
  const r = scan('ex-js-updates-pos');
  assert.deepEqual(summary(r, 'EXPO_UPDATES_INSECURE_URL'), [['app.config.ts', 6, 'HIGH']]);
  assert.deepEqual(summary(r, 'EXPO_UPDATES_NO_CODE_SIGNING'), [['app.config.ts', 5, 'HIGH']]);
  assert.deepEqual(summary(r, 'EXPO_INSECURE_PERMISSIONS'), [['app.config.ts', 9, 'LOW']]);
});

test('app.config.js `({ config }) => ({ ...config, ... })` is read when the returned object is a literal', () => {
  const r = scan('ex-js-updates-fn');
  assert.deepEqual(summary(r, 'EXPO_UPDATES_INSECURE_URL'), [['app.config.js', 5, 'HIGH']]);
  assert.deepEqual(summary(r, 'EXPO_UPDATES_NO_CODE_SIGNING'), [['app.config.js', 4, 'HIGH']]);
  assert.deepEqual(summary(r, 'EXPO_INSECURE_PERMISSIONS'), [['app.config.js', 9, 'LOW']]);
});

test('module.exports literal with https url, code signing and harmless permissions is clean', () => {
  const r = scan('ex-js-updates-neg');
  for (const id of RULES) assert.deepEqual(byRule(r, id), [], id);
});

test('values behind variables, spreads or other keys are never reported', () => {
  for (const dir of ['ex-js-updates-dynamic-neg', 'ex-js-updates-spread-neg']) {
    const r = scan(dir);
    for (const id of RULES) assert.deepEqual(byRule(r, id), [], `${id} in ${dir}`);
  }
});

test('app.json behaviour is unchanged next to the new app.config.js support', () => {
  const r = scan('rnc-config');
  assert.deepEqual(summary(r, 'EXPO_INSECURE_PERMISSIONS'), [['app.json', 5, 'LOW']]);
});

// ---- EXPO_PUBLIC_ENV_SECRET (.env files are only read when git tracks them, so the project is built here)
const envRun = content => scan(gitProject({ 'package.json': '{"name":"app","dependencies":{"expo":"^51.0.0"}}', '.env': content }));

test('EXPO_PUBLIC_ENV_SECRET: secret-named EXPO_PUBLIC_ literals in .env, value redacted', () => {
  const r = envRun(
    [
      '# build config',
      'EXPO_PUBLIC_API_URL=https://api.myshop.dev',
      'EXPO_PUBLIC_CLIENT_SECRET=q8Zr41LmV0xTnB7aWc2Yd9Ke',
      'export EXPO_PUBLIC_AUTH_TOKEN="a1b2c3d4e5f6a7b8c9d0"',
      'EXPO_PUBLIC_DB_PASSWORD=correct-horse-battery # prod db',
      '',
    ].join('\n')
  );
  const found = byRule(r, 'EXPO_PUBLIC_ENV_SECRET').sort((a, b) => a.line - b.line);
  assert.deepEqual(found.map(f => [f.line, f.severity, f.confidence]), [
    [3, 'HIGH', 'medium'],
    [4, 'HIGH', 'medium'],
    [5, 'HIGH', 'medium'],
  ]);
  assert.ok(found.every(f => !JSON.stringify(f).includes('q8Zr41LmV0xTnB7aWc2Yd9Ke') && f.snippet.endsWith('=<redacted>')));
});

test('EXPO_PUBLIC_ENV_SECRET: publishable, anon, public, url, placeholder, empty, non-EXPO_PUBLIC and comment lines are clean', () => {
  const r = envRun(
    [
      'EXPO_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_51Nq7XaB3cD9eF2gH5iJ8kL',
      'EXPO_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.anon.payload',
      'EXPO_PUBLIC_GOOGLE_PUBLIC_KEY=abcdefghijklmnop1234',
      'EXPO_PUBLIC_SENTRY_DSN=https://abc@o1.ingest.sentry.io/2',
      'EXPO_PUBLIC_API_KEY=abcdefghijklmnop1234',
      'EXPO_PUBLIC_PASSWORD_MIN_LENGTH=12',
      'EXPO_PUBLIC_SECRETARY_EMAIL=desk@myshop.dev',
      'EXPO_PUBLIC_CLIENT_SECRET=changeme',
      'EXPO_PUBLIC_CLIENT_SECRET_2=your-secret-here',
      'EXPO_PUBLIC_AUTH_TOKEN=',
      'EXPO_PUBLIC_REFRESH_TOKEN=${REFRESH_TOKEN}',
      '#EXPO_PUBLIC_CLIENT_SECRET=q8Zr41LmV0xTnB7aWc2Yd9Ke',
      'SERVER_ONLY_SECRET=q8Zr41LmV0xTnB7aWc2Yd9Ke',
      '',
    ].join('\n')
  );
  assert.deepEqual(byRule(r, 'EXPO_PUBLIC_ENV_SECRET'), []);
});
