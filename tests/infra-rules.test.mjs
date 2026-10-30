import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { scan, byRule, casesDir, repoRoot } from './helpers.mjs';

const cli = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');

// TLS_VALIDATION_DISABLED_NATIVE, GRADLE_INSECURE_REPOSITORY, ANDROID_FILEPROVIDER_BROAD_PATHS and
// FIREBASE_RULES_OPEN_ACCESS: each has a positive and a near-miss fixture under tests/cases/.
const where = (result, ruleId) =>
  byRule(result, ruleId)
    .map(f => `${f.filePath.split(/tests\/cases\/[^/]+\/|rnsec-case-[^/]+\/[^/]+\//).pop()}:${f.line}:${f.severity}:${f.confidence}`)
    .sort();

test('TLS_VALIDATION_DISABLED_NATIVE flags trust-all, hostname, WebView and auth-challenge bypasses', () => {
  assert.deepEqual(where(scan('tls-native-pos'), 'TLS_VALIDATION_DISABLED_NATIVE'), [
    // empty checkServerTrusted behind `if (!validateCertificates)`: opt-in, MEDIUM
    'android/app/src/main/java/com/example/OptIn.kt:14:MEDIUM:medium',
    'android/app/src/main/java/com/example/OptIn.kt:22:HIGH:high',
    // proceed() only when a setting is on: MEDIUM
    'android/app/src/main/java/com/example/OptIn.kt:27:MEDIUM:medium',
    'android/app/src/main/java/com/example/TrustAll.java:17:HIGH:high',
    'android/app/src/main/java/com/example/TrustAll.java:29:HIGH:high',
    'android/app/src/main/java/com/example/TrustAll.java:35:HIGH:high',
    'android/app/src/main/java/com/example/TrustAll.java:40:HIGH:high',
    'android/app/src/main/java/com/example/TrustAll.java:46:HIGH:high',
    'ios/App/Challenge.m:9:HIGH:high',
    'ios/App/Delegates.swift:10:HIGH:high',
    // trustSelfSigned switch: MEDIUM
    'ios/App/Delegates.swift:24:MEDIUM:medium',
  ]);
});

test('TLS_VALIDATION_DISABLED_NATIVE stays quiet on delegating managers, real checks, dialogs, DEBUG code and client certificates', () => {
  assert.deepEqual(where(scan('tls-native-neg'), 'TLS_VALIDATION_DISABLED_NATIVE'), []);
});

test('GRADLE_INSECURE_REPOSITORY flags http repositories and allowInsecureProtocol, not https, local hosts or comments', () => {
  assert.deepEqual(where(scan('gradle-http-pos'), 'GRADLE_INSECURE_REPOSITORY'), [
    'android/build.gradle:12:HIGH:high',
    'android/build.gradle:17:HIGH:medium',
    'android/build.gradle:4:HIGH:high',
    'android/settings.gradle.kts:3:HIGH:high',
  ]);
  assert.deepEqual(where(scan('gradle-http-neg'), 'GRADLE_INSECURE_REPOSITORY'), []);
});

test('ANDROID_FILEPROVIDER_BROAD_PATHS flags root-path and whole-directory paths in FileProvider xml only', () => {
  assert.deepEqual(where(scan('fileprovider-pos'), 'ANDROID_FILEPROVIDER_BROAD_PATHS'), [
    'android/app/src/main/res/xml/file_paths.xml:3:HIGH:high',
    'android/app/src/main/res/xml/file_paths.xml:4:MEDIUM:medium',
    'android/app/src/main/res/xml/file_paths.xml:5:LOW:medium',
  ]);
  assert.deepEqual(where(scan('fileprovider-neg'), 'ANDROID_FILEPROVIDER_BROAD_PATHS'), []);
});

test('FIREBASE_RULES_OPEN_ACCESS grades open, wildcard-read and time-limited rules; ignores guarded rules and other .rules files', () => {
  assert.deepEqual(where(scan('firebase-rules-pos'), 'FIREBASE_RULES_OPEN_ACCESS'), [
    'database.rules.json:4:HIGH:high',
    'database.rules.json:5:HIGH:high',
    'firestore.rules:11:MEDIUM:medium',
    'firestore.rules:5:HIGH:high',
    'firestore.rules:8:HIGH:high',
    'storage.rules:5:LOW:medium',
    'storage.rules:6:MEDIUM:medium',
  ]);
  assert.deepEqual(where(scan('firebase-rules-neg'), 'FIREBASE_RULES_OPEN_ACCESS'), []);
});

const NEW_RULES = ['TLS_VALIDATION_DISABLED_NATIVE', 'GRADLE_INSECURE_REPOSITORY', 'ANDROID_FILEPROVIDER_BROAD_PATHS', 'FIREBASE_RULES_OPEN_ACCESS'];

test('the new rules are listed by `rnsec rules`', () => {
  const run = spawnSync('node', [cli, 'rules'], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  for (const id of NEW_RULES) assert.ok(run.stdout.includes(id), `${id} missing from \`rnsec rules\``);
});

test('findings of the new rules are written to SARIF with their rule definitions', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rnsec-sarif-'));
  const fixtures = { TLS_VALIDATION_DISABLED_NATIVE: 'tls-native-pos', GRADLE_INSECURE_REPOSITORY: 'gradle-http-pos', ANDROID_FILEPROVIDER_BROAD_PATHS: 'fileprovider-pos', FIREBASE_RULES_OPEN_ACCESS: 'firebase-rules-pos' };
  for (const [id, fixture] of Object.entries(fixtures)) {
    const out = join(dir, `${fixture}.sarif`);
    spawnSync('node', [cli, 'scan', '--path', join(casesDir, fixture), '--json', '--sarif', out], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
    const run = JSON.parse(readFileSync(out, 'utf8')).runs[0];
    assert.ok(run.tool.driver.rules.some(r => r.id === id), `${id} missing from the SARIF rule definitions`);
    assert.ok(run.results.some(r => r.ruleId === id), `${id} has no SARIF result for ${fixture}`);
  }
});
