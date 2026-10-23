import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, byRule } from './helpers.mjs';

const summarize = fs => fs.map(f => [f.line, f.severity]).sort((a, b) => a[0] - b[0]);

test('NSC cleartext: base-config HIGH, public domain-config MEDIUM, local domains and comments ignored', () => {
  const r = scan('cfg-nsc-bad');
  assert.deepEqual(summarize(byRule(r, 'ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT')), [[4, 'HIGH'], [10, 'MEDIUM']]);
});

test('NSC cleartext: localhost/private domains, cleartext=false and debug-overrides are clean', () => {
  const r = scan('cfg-nsc-good');
  assert.equal(byRule(r, 'ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT').length, 0);
});

test('ANDROID_USER_CA_TRUSTED flags user CAs and overridePins outside debug-overrides', () => {
  const r = scan('cfg-nsc-bad');
  const fs = byRule(r, 'ANDROID_USER_CA_TRUSTED');
  assert.deepEqual(summarize(fs), [[7, 'MEDIUM'], [13, 'MEDIUM']]);
  assert.match(fs.find(f => f.line === 7).description, /user-installed CA/);
  assert.match(fs.find(f => f.line === 13).description, /overridePins/);
});

test('ANDROID_USER_CA_TRUSTED ignores user CAs and overridePins inside debug-overrides', () => {
  const r = scan('cfg-nsc-good');
  assert.equal(byRule(r, 'ANDROID_USER_CA_TRUSTED').length, 0);
});

test('DEPENDENCY_NONREGISTRY_SOURCE flags git, tarball, shorthand, latest and *', () => {
  const r = scan('cfg-deps-bad');
  assert.deepEqual(summarize(byRule(r, 'DEPENDENCY_NONREGISTRY_SOURCE')), [
    [6, 'MEDIUM'], [7, 'MEDIUM'], [8, 'MEDIUM'], [9, 'LOW'], [10, 'MEDIUM'], [11, 'LOW'], [12, 'LOW'], [15, 'MEDIUM'],
  ]);
});

test('DEPENDENCY_NONREGISTRY_SOURCE allows semver, workspace/file/link/portal/patch/npm/catalog', () => {
  const r = scan('cfg-deps-good');
  assert.equal(byRule(r, 'DEPENDENCY_NONREGISTRY_SOURCE').length, 0);
});

test('IOS_FILE_SHARING_ENABLED is LOW/medium confidence on its own', () => {
  const [f, ...rest] = byRule(scan('cfg-ios-bad'), 'IOS_FILE_SHARING_ENABLED');
  assert.equal(rest.length, 0);
  assert.equal(f.line, 7);
  assert.equal(f.severity, 'LOW');
  assert.equal(f.confidence, 'medium');
});

test('IOS_FILE_SHARING_ENABLED is MEDIUM with in-place document opening', () => {
  const [f] = byRule(scan('cfg-ios-inplace'), 'IOS_FILE_SHARING_ENABLED');
  assert.equal(f.line, 7);
  assert.equal(f.severity, 'MEDIUM');
});

test('IOS_FILE_SHARING_ENABLED: false value and commented-out key are clean', () => {
  assert.equal(byRule(scan('cfg-ios-good'), 'IOS_FILE_SHARING_ENABLED').length, 0);
});
