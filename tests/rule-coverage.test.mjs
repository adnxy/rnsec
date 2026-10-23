import { test } from 'node:test';
import assert from 'node:assert/strict';
import { basename } from 'node:path';
import { scan, byRule } from './helpers.mjs';

// One positive fixture (tests/cases/cov-<rule>) and one near-miss (cov-<rule>-neg) per rule.
// `expected` lists [line, severity] of every finding of the rule; `line: undefined` means the rule reports no line.
const cases = [
  { rule: 'ANDROID_CONTENT_PROVIDER_NO_PERMISSION', dir: 'cov-android-content-provider-no-permission', file: 'AndroidManifest.xml', expected: [[3, 'HIGH']] },
  { rule: 'ANDROID_DEBUGGABLE_ENABLED', dir: 'cov-android-debuggable-enabled', file: 'AndroidManifest.xml', expected: [[5, 'HIGH']] },
  { rule: 'ANDROID_INTENT_FILTER_PERMISSIVE', dir: 'cov-android-intent-filter-permissive', file: 'AndroidManifest.xml', expected: [[4, 'MEDIUM']] },
  { rule: 'HARDCODED_ENCRYPTION_KEY', dir: 'cov-hardcoded-encryption-key', file: 'crypto.ts', expected: [[3, 'HIGH']] },
  // ECB block mode on its own line, plus two whole-file findings anchored on line 1 (no user auth: HIGH, no StrongBox: MEDIUM)
  { rule: 'INSECURE_KEYSTORE_USAGE', dir: 'cov-insecure-keystore-usage', file: 'KeyHelper.kt', expected: [[1, 'HIGH'], [1, 'MEDIUM'], [9, 'HIGH']] },
  // One finding per risky mode (location, fetch); both anchor on the UIBackgroundModes key.
  { rule: 'IOS_BACKGROUND_MODES_UNNECESSARY', dir: 'cov-ios-background-modes-unnecessary', file: 'Info.plist', expected: [[7, 'LOW'], [7, 'LOW']] },
  { rule: 'IOS_KEYCHAIN_ACCESS_GROUP_INSECURE', dir: 'cov-ios-keychain-access-group-insecure', file: 'App.entitlements', expected: [[undefined, 'MEDIUM']] },
  { rule: 'IOS_UNIVERSAL_LINKS_MISCONFIGURED', dir: 'cov-ios-universal-links-misconfigured', file: 'Info.plist', expected: [[7, 'MEDIUM']] },
  { rule: 'JAVASCRIPT_ENABLED_BRIDGE', dir: 'cov-javascript-enabled-bridge', file: 'Share.ts', expected: [[4, 'HIGH']] },
  { rule: 'MMKV_NO_ENCRYPTION', dir: 'cov-mmkv-no-encryption', file: 'session.ts', expected: [[6, 'HIGH']] },
  { rule: 'REDUX_DEVTOOLS_ENABLED', dir: 'cov-redux-devtools-enabled', file: 'store.js', expected: [[6, 'MEDIUM']] },
  { rule: 'SCREENSHOT_PROTECTION_MISSING', dir: 'cov-screenshot-protection-missing', file: 'PaymentScreen.tsx', expected: [[1, 'MEDIUM']] },
  { rule: 'WEBVIEW_CACHING_ENABLED', dir: 'cov-webview-caching-enabled', file: 'Account.tsx', expected: [[6, 'LOW']] },
  { rule: 'WEBVIEW_GEOLOCATION_ENABLED', dir: 'cov-webview-geolocation-enabled', file: 'StoreLocator.tsx', expected: [[5, 'MEDIUM']] },
];

const summarize = fs => fs.map(f => [f.line, f.severity]).sort((a, b) => (a[0] ?? 0) - (b[0] ?? 0) || a[1].localeCompare(b[1]));
const sorted = expected => summarize(expected.map(([line, severity]) => ({ line, severity })));

for (const { rule, dir, file, expected } of cases) {
  test(`${rule} fires on its documented trigger with the expected severity and line`, () => {
    const found = byRule(scan(dir), rule);
    assert.ok(found.length >= 1, `${rule} did not fire for ${dir}`);
    assert.deepEqual(summarize(found), sorted(expected));
    for (const f of found) assert.equal(basename(f.filePath), file);
  });

  test(`${rule} stays quiet on the near-miss fixture`, () => {
    assert.equal(byRule(scan(`${dir}-neg`), rule).length, 0);
  });
}
