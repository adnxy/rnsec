import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, byRule } from './helpers.mjs';

const summary = (r, id, file) =>
  byRule(r, id)
    .filter(f => !file || f.filePath.endsWith(file))
    .map(f => [f.line, f.severity])
    .sort((a, b) => a[0] - b[0]);

test('TLS_VALIDATION_DISABLED_ENV flags env switch and property assignment only', () => {
  const r = scan('rnsec-tls-pos');
  assert.deepEqual(summary(r, 'TLS_VALIDATION_DISABLED_ENV'), [[3, 'HIGH'], [5, 'HIGH']]);
  assert.ok(byRule(r, 'TLS_VALIDATION_DISABLED_ENV').every(f => f.confidence === 'high'));
});

test('TLS_VALIDATION_DISABLED_ENV: safe near-misses are clean', () => {
  assert.deepEqual(byRule(scan('rnsec-tls-neg'), 'TLS_VALIDATION_DISABLED_ENV'), []);
});

test('BUNDLED_ENV_SECRET flags secret-named client env vars once per name', () => {
  const r = scan('rnsec-env-pos');
  assert.deepEqual(summary(r, 'BUNDLED_ENV_SECRET'), [
    [2, 'HIGH'], [4, 'HIGH'], [6, 'MEDIUM'], [7, 'HIGH'], [8, 'HIGH'],
  ]);
  assert.ok(byRule(r, 'BUNDLED_ENV_SECRET').every(f => f.confidence === 'medium'));
});

test('BUNDLED_ENV_SECRET: public/publishable/anon/url/word-substring names are clean', () => {
  assert.deepEqual(byRule(scan('rnsec-env-neg'), 'BUNDLED_ENV_SECRET'), []);
});

test('MMKV_UNENCRYPTED_SENSITIVE_DATA flags plain instance with sensitive key and hardcoded key', () => {
  const r = scan('rnsec-mmkv-pos');
  assert.deepEqual(summary(r, 'MMKV_UNENCRYPTED_SENSITIVE_DATA', 'storage.ts'), [[3, 'MEDIUM'], [9, 'MEDIUM']]);
  assert.deepEqual(summary(r, 'MMKV_UNENCRYPTED_SENSITIVE_DATA', 'v4.ts'), [[2, 'MEDIUM']]);
  assert.ok(byRule(r, 'MMKV_UNENCRYPTED_SENSITIVE_DATA').every(f => f.confidence === 'medium'));
});

test('MMKV_UNENCRYPTED_SENSITIVE_DATA: benign keys and encrypted instances are clean', () => {
  assert.deepEqual(byRule(scan('rnsec-mmkv-neg'), 'MMKV_UNENCRYPTED_SENSITIVE_DATA'), []);
});

test('SQLITE_QUERY_INJECTION flags interpolated SQL with severity/confidence tiers', () => {
  const r = scan('rnsec-sqlite-pos');
  assert.deepEqual(summary(r, 'SQLITE_QUERY_INJECTION'), [[6, 'HIGH'], [10, 'MEDIUM'], [15, 'MEDIUM']]);
  const conf = Object.fromEntries(byRule(r, 'SQLITE_QUERY_INJECTION').map(f => [f.line, f.confidence]));
  assert.deepEqual(conf, { 6: 'medium', 10: 'medium', 15: 'low' });
});

test('SQLITE_QUERY_INJECTION: bound params, placeholders, DDL consts, numeric casts and non-sqlite files are clean', () => {
  assert.deepEqual(byRule(scan('rnsec-sqlite-neg'), 'SQLITE_QUERY_INJECTION'), []);
});

test('OAUTH_INSECURE_FLOW flags PKCE off, implicit flow and nonce off', () => {
  const r = scan('rnsec-oauth-pos');
  // line 6 (usePKCE: false in expo-auth-session code) belongs to EXPO_AUTH_SESSION_NO_PKCE
  assert.deepEqual(summary(r, 'OAUTH_INSECURE_FLOW'), [[7, 'MEDIUM'], [10, 'MEDIUM'], [11, 'MEDIUM']]);
  assert.ok(byRule(r, 'OAUTH_INSECURE_FLOW').every(f => f.confidence === 'high'));
  assert.deepEqual(summary(r, 'EXPO_AUTH_SESSION_NO_PKCE'), [[6, 'HIGH']]);
});

const pkce = r =>
  r.findings.filter(f => ['EXPO_AUTH_SESSION_NO_PKCE', 'OAUTH_INSECURE_FLOW'].includes(f.ruleId)).map(f => [f.ruleId, f.line]);

test('usePKCE: false in expo-auth-session code yields exactly one finding, EXPO_AUTH_SESSION_NO_PKCE, on the property line', () => {
  const r = scan('rx-pkce-expo');
  assert.deepEqual(pkce(r), [['EXPO_AUTH_SESSION_NO_PKCE', 7]]);
});

test('usePKCE: false in a non-expo OAuth library stays with OAUTH_INSECURE_FLOW', () => {
  const r = scan('rx-pkce-other');
  assert.deepEqual(pkce(r), [['OAUTH_INSECURE_FLOW', 8]]);
});

test('OAUTH_INSECURE_FLOW: code+PKCE and ungated files are clean', () => {
  assert.deepEqual(byRule(scan('rnsec-oauth-neg'), 'OAUTH_INSECURE_FLOW'), []);
});
