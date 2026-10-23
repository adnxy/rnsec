import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, byRule } from './helpers.mjs';

const summary = (r, id) => byRule(r, id).map(f => [f.filePath.split('/').pop(), f.line, f.severity, f.confidence]);

test('EXPO_CONFIG_INSECURE_SETTINGS: app.json settings with exact lines', () => {
  const r = scan('ex-insecure-pos');
  assert.deepEqual(summary(r, 'EXPO_CONFIG_INSECURE_SETTINGS').sort((a, b) => a[1] - b[1]), [
    ['app.json', 5, 'MEDIUM', 'medium'],
    ['app.json', 9, 'LOW', 'medium'],
    ['app.json', 11, 'HIGH', 'high'],
    ['app.json', 21, 'HIGH', 'high'],
  ]);
});

test('EXPO_CONFIG_INSECURE_SETTINGS: ATS flag ignored by narrower keys is LOW/medium', () => {
  const found = byRule(scan('ex-insecure-ats-narrow'), 'EXPO_CONFIG_INSECURE_SETTINGS');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'LOW');
  assert.equal(found[0].confidence, 'medium');
  assert.equal(found[0].line, 6);
  assert.match(found[0].description, /NSAllowsLocalNetworking/);
});

test('EXPO_CONFIG_INSECURE_SETTINGS: app.config.ts literals', () => {
  assert.deepEqual(summary(scan('ex-insecure-js'), 'EXPO_CONFIG_INSECURE_SETTINGS').sort((a, b) => a[1] - b[1]), [
    ['app.config.ts', 7, 'MEDIUM', 'medium'],
    ['app.config.ts', 11, 'HIGH', 'high'],
    ['app.config.ts', 14, 'HIGH', 'high'],
  ]);
});

test('EXPO_CONFIG_INSECURE_SETTINGS: safe or absent settings are not reported', () => {
  assert.equal(byRule(scan('ex-insecure-neg'), 'EXPO_CONFIG_INSECURE_SETTINGS').length, 0);
});

test('EXPO_CONFIG_INSECURE_SETTINGS: skipped when native dirs exist (native rules own it)', () => {
  assert.equal(byRule(scan('ex-insecure-bare'), 'EXPO_CONFIG_INSECURE_SETTINGS').length, 0);
});

test('EXPO_SENSITIVE_CONFIG_EXPOSED: secret-named literals in app.json, nested included', () => {
  const found = byRule(scan('ex-extra-pos'), 'EXPO_SENSITIVE_CONFIG_EXPOSED').sort((a, b) => a.line - b.line);
  assert.deepEqual(found.map(f => [f.line, f.severity, f.confidence]), [
    [7, 'HIGH', 'medium'],
    [9, 'HIGH', 'medium'],
    [10, 'MEDIUM', 'medium'],
  ]);
  assert.match(found[0].reason, /ships|embedded|shipped/);
});

test('EXPO_SENSITIVE_CONFIG_EXPOSED: public names, placeholders and benign names are ignored', () => {
  assert.equal(byRule(scan('ex-extra-neg'), 'EXPO_SENSITIVE_CONFIG_EXPOSED').length, 0);
});

test('EXPO_SENSITIVE_CONFIG_EXPOSED: app.config.js literal only, process.env and placeholders skipped', () => {
  assert.deepEqual(summary(scan('ex-extra-js'), 'EXPO_SENSITIVE_CONFIG_EXPOSED'), [['app.config.js', 6, 'HIGH', 'medium']]);
});

test('EXPO_SENSITIVE_CONFIG_EXPOSED: ios/android config and plugin options; public SDK identifiers are allowlisted', () => {
  const found = byRule(scan('ex-sensitive-native'), 'EXPO_SENSITIVE_CONFIG_EXPOSED').sort((a, b) => a.line - b.line);
  assert.deepEqual(found.map(f => [f.line, f.severity, f.confidence]), [
    [16, 'HIGH', 'medium'], // android.config.branch.secret (the key_test_ apiKey on the same line is allowlisted, the Branch secret is not)
    [17, 'MEDIUM', 'low'], // android.config.someSdk.apiKey: unknown SDK, api-key name
    [22, 'HIGH', 'medium'], // @sentry/react-native/expo authToken
  ]);
  const text = found.map(f => f.description).join('\n');
  assert.match(text, /plugins\[@sentry\/react-native\/expo\]\.authToken/);
  assert.doesNotMatch(text, /googleMaps|googleSignIn|googleMobileAds|key_live|key_test/);
});

test('EAS_JSON_SECRET_IN_ENV: literal secrets in build env, EXPO_PUBLIC_ names included', () => {
  const found = byRule(scan('ex-eas-pos'), 'EAS_JSON_SECRET_IN_ENV').sort((a, b) => a.line - b.line);
  assert.deepEqual(found.map(f => [f.line, f.severity, f.confidence]), [
    [7, 'HIGH', 'medium'],
    [8, 'MEDIUM', 'medium'],
  ]);
  assert.match(found[1].description, /EXPO_PUBLIC/);
});

test('EAS_JSON_SECRET_IN_ENV: references, empty values, public names and file paths are ignored', () => {
  assert.equal(byRule(scan('ex-eas-neg'), 'EAS_JSON_SECRET_IN_ENV').length, 0);
});
