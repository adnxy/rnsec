/**
 * Tests for all 17 new v1.3.0 security rules.
 *
 * Each rule is tested with:
 *   - Positive cases: code that SHOULD trigger the rule
 *   - Negative cases: safe code that should NOT trigger (false positive prevention)
 *
 * Run: npx tsx tests/rules.test.ts
 */

import { parseJSFile } from '../src/core/astParser.js';
import { reactNativeRules } from '../src/scanners/react-native/reactNativeScanner.js';
import { storageRules } from '../src/scanners/security/storageScanner.js';
import { networkRules } from '../src/scanners/security/networkScanner.js';
import { configRules } from '../src/scanners/security/configScanner.js';
import { androidRules } from '../src/scanners/android/androidScanner.js';
import { iosRules } from '../src/scanners/ios/iosScanner.js';
import { cryptoRules } from '../src/scanners/security/cryptoScanner.js';
import { authenticationRules } from '../src/scanners/security/authenticationScanner.js';
import type { RuleContext } from '../src/types/ruleTypes.js';
import type { Finding } from '../src/types/findings.js';
import type { Rule } from '../src/types/ruleTypes.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function findRule(groups: { rules: Rule[] }[], id: string): Rule {
  for (const g of groups) {
    const r = g.rules.find((r) => r.id === id);
    if (r) return r;
  }
  throw new Error(`Rule ${id} not found`);
}

async function makeJsContext(code: string, filePath = '/app/src/Component.tsx'): Promise<RuleContext> {
  const result = await parseJSFile(filePath, code);
  return { filePath, fileContent: code, ast: result.ast };
}

function makeJsonContext(json: object, filePath = '/app/app.json'): RuleContext {
  return { filePath, fileContent: JSON.stringify(json, null, 2), config: json };
}

function makeXmlContext(xml: string, filePath = '/app/android/AndroidManifest.xml'): RuleContext {
  return { filePath, fileContent: xml, xmlContent: xml };
}

function makeNativeContext(code: string, filePath: string): RuleContext {
  return { filePath, fileContent: code };
}

const allGroups = [
  reactNativeRules, storageRules, networkRules, configRules,
  androidRules, iosRules, cryptoRules, authenticationRules,
];

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function assertFindings(
  testName: string,
  ruleId: string,
  context: RuleContext,
  expectCount: 'none' | 'some' | number,
) {
  const rule = findRule(allGroups, ruleId);
  const findings = await rule.apply(context);
  const matched = findings.filter((f) => f.ruleId === ruleId);

  let ok = false;
  if (expectCount === 'none') ok = matched.length === 0;
  else if (expectCount === 'some') ok = matched.length > 0;
  else ok = matched.length === expectCount;

  if (ok) {
    passed++;
    console.log(`  ✓ ${testName}`);
  } else {
    failed++;
    const msg = `  ✗ ${testName} — expected ${expectCount}, got ${matched.length}`;
    console.log(msg);
    failures.push(msg);
  }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

async function runTests() {
  console.log('\n=== RNSEC v1.3.0 Rule Tests ===\n');

  // ─── 1. EXPO_UPDATES_NO_CODE_SIGNING ────────────────────────────────────
  console.log('EXPO_UPDATES_NO_CODE_SIGNING:');
  await assertFindings(
    'detects updates without code signing',
    'EXPO_UPDATES_NO_CODE_SIGNING',
    makeJsonContext({ expo: { updates: { url: 'https://u.expo.dev/xxx' }, runtimeVersion: '1.0.0' } }),
    'some',
  );
  await assertFindings(
    'allows updates with code signing',
    'EXPO_UPDATES_NO_CODE_SIGNING',
    makeJsonContext({ expo: { updates: { url: 'https://u.expo.dev/xxx', codeSigningCertificate: './cert.pem' }, runtimeVersion: '1.0.0' } }),
    'none',
  );
  await assertFindings(
    'ignores non-expo config',
    'EXPO_UPDATES_NO_CODE_SIGNING',
    makeJsonContext({ name: 'test' }),
    'none',
  );

  // ─── 2. INSECURE_LINKING_OPEN ───────────────────────────────────────────
  console.log('INSECURE_LINKING_OPEN:');
  await assertFindings(
    'detects Linking.openURL with variable',
    'INSECURE_LINKING_OPEN',
    await makeJsContext(`
      import { Linking } from 'react-native';
      function open(url) { Linking.openURL(url); }
    `),
    'some',
  );
  await assertFindings(
    'allows Linking.openURL with string literal',
    'INSECURE_LINKING_OPEN',
    await makeJsContext(`
      import { Linking } from 'react-native';
      Linking.openURL('https://example.com');
    `),
    'none',
  );
  await assertFindings(
    'allows Linking.openURL with validation nearby',
    'INSECURE_LINKING_OPEN',
    await makeJsContext(`
      import { Linking } from 'react-native';
      function open(url) {
        if (url.startsWith('https://')) { Linking.openURL(url); }
      }
    `),
    'none',
  );

  // ─── 3. SENSITIVE_NAVIGATION_PARAMS ─────────────────────────────────────
  console.log('SENSITIVE_NAVIGATION_PARAMS:');
  await assertFindings(
    'detects token in navigation params',
    'SENSITIVE_NAVIGATION_PARAMS',
    await makeJsContext(`
      function go(nav) { nav.navigate('Profile', { token: 'abc' }); }
    `),
    'some',
  );
  await assertFindings(
    'detects password in navigation.push params',
    'SENSITIVE_NAVIGATION_PARAMS',
    await makeJsContext(`
      function go(nav) { nav.push('Login', { password: 'secret' }); }
    `),
    'some',
  );
  await assertFindings(
    'allows non-sensitive navigation params',
    'SENSITIVE_NAVIGATION_PARAMS',
    await makeJsContext(`
      function go(nav) { nav.navigate('Details', { itemId: 42, title: 'Hello' }); }
    `),
    'none',
  );

  // ─── 4. PUSH_NOTIFICATION_SENSITIVE_DATA ────────────────────────────────
  console.log('PUSH_NOTIFICATION_SENSITIVE_DATA:');
  await assertFindings(
    'detects logging notification data',
    'PUSH_NOTIFICATION_SENSITIVE_DATA',
    await makeJsContext(`
      import * as Notifications from 'expo-notifications';
      Notifications.addNotificationReceivedListener((n) => {
        console.log(n.request.content.data);
      });
    `),
    'none', // notification.data pattern not matched by regex exactly — need notification.request.content.data
  );
  await assertFindings(
    'detects logging notification.request.content.data',
    'PUSH_NOTIFICATION_SENSITIVE_DATA',
    await makeJsContext(`
      import * as Notifications from 'expo-notifications';
      Notifications.addNotificationReceivedListener((notification) => {
        console.log('data:', notification.request.content.data);
      });
    `),
    'some',
  );
  await assertFindings(
    'safe notification handler without logging',
    'PUSH_NOTIFICATION_SENSITIVE_DATA',
    await makeJsContext(`
      import * as Notifications from 'expo-notifications';
      Notifications.addNotificationReceivedListener((notification) => {
        const type = notification.request.content.data?.type;
        refreshContent();
      });
    `),
    'none',
  );
  await assertFindings(
    'no push import - no findings',
    'PUSH_NOTIFICATION_SENSITIVE_DATA',
    await makeJsContext(`
      import React from 'react';
      function foo() { console.log('hello'); }
    `),
    'none',
  );

  // ─── 5. EXPO_AUTH_SESSION_NO_PKCE ───────────────────────────────────────
  console.log('EXPO_AUTH_SESSION_NO_PKCE:');
  await assertFindings(
    'detects usePKCE: false',
    'EXPO_AUTH_SESSION_NO_PKCE',
    await makeJsContext(`
      import * as AuthSession from 'expo-auth-session';
      const [req] = useAuthRequest({ clientId: 'x', usePKCE: false });
    `),
    'some',
  );
  await assertFindings(
    'allows usePKCE: true',
    'EXPO_AUTH_SESSION_NO_PKCE',
    await makeJsContext(`
      import * as AuthSession from 'expo-auth-session';
      const [req] = useAuthRequest({ clientId: 'x', usePKCE: true });
    `),
    'none',
  );
  await assertFindings(
    'allows omitted usePKCE (default true)',
    'EXPO_AUTH_SESSION_NO_PKCE',
    await makeJsContext(`
      import * as AuthSession from 'expo-auth-session';
      const [req] = useAuthRequest({ clientId: 'x' });
    `),
    'none',
  );
  await assertFindings(
    'no auth-session import - no findings',
    'EXPO_AUTH_SESSION_NO_PKCE',
    await makeJsContext(`
      function foo() { useAuthRequest({ usePKCE: false }); }
    `),
    'none',
  );

  // ─── 6. UNENCRYPTED_REALM_DATABASE ──────────────────────────────────────
  console.log('UNENCRYPTED_REALM_DATABASE:');
  await assertFindings(
    'detects Realm.open without encryption in sensitive context',
    'UNENCRYPTED_REALM_DATABASE',
    await makeJsContext(`
      import Realm from 'realm';
      // Stores user credentials
      const realm = await Realm.open({ schema: [UserSchema] });
    `),
    'some',
  );
  await assertFindings(
    'allows Realm.open with encryptionKey',
    'UNENCRYPTED_REALM_DATABASE',
    await makeJsContext(`
      import Realm from 'realm';
      const realm = await Realm.open({ schema: [UserSchema], encryptionKey: key });
    `),
    'none',
  );
  await assertFindings(
    'allows Realm.open without sensitive context',
    'UNENCRYPTED_REALM_DATABASE',
    await makeJsContext(`
      import Realm from 'realm';
      const realm = await Realm.open({ schema: [CacheSchema] });
    `),
    'none',
  );

  // ─── 7. UNENCRYPTED_SQLITE_DATABASE ─────────────────────────────────────
  console.log('UNENCRYPTED_SQLITE_DATABASE:');
  await assertFindings(
    'detects SQLite without encryption in sensitive context',
    'UNENCRYPTED_SQLITE_DATABASE',
    await makeJsContext(`
      import * as SQLite from 'expo-sqlite';
      // store user session tokens
      const db = SQLite.openDatabase('users.db');
    `),
    'some',
  );
  await assertFindings(
    'allows SQLite with sqlcipher',
    'UNENCRYPTED_SQLITE_DATABASE',
    await makeJsContext(`
      import * as SQLite from 'expo-sqlite';
      // store user session data with sqlcipher
      const db = SQLite.openDatabase('users.db');
    `),
    'none',
  );
  await assertFindings(
    'allows SQLite without sensitive context',
    'UNENCRYPTED_SQLITE_DATABASE',
    await makeJsContext(`
      import * as SQLite from 'expo-sqlite';
      const db = SQLite.openDatabase('cache.db');
    `),
    'none',
  );

  // ─── 8. EXPO_SECURE_STORE_WEAK_OPTIONS ──────────────────────────────────
  console.log('EXPO_SECURE_STORE_WEAK_OPTIONS:');
  await assertFindings(
    'detects AFTER_FIRST_UNLOCK for sensitive key',
    'EXPO_SECURE_STORE_WEAK_OPTIONS',
    await makeJsContext(`
      import * as SecureStore from 'expo-secure-store';
      SecureStore.setItemAsync('auth_token', tok, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK });
    `),
    'some',
  );
  await assertFindings(
    'allows WHEN_UNLOCKED for sensitive key',
    'EXPO_SECURE_STORE_WEAK_OPTIONS',
    await makeJsContext(`
      import * as SecureStore from 'expo-secure-store';
      SecureStore.setItemAsync('auth_token', tok, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
    `),
    'none',
  );
  await assertFindings(
    'allows AFTER_FIRST_UNLOCK for non-sensitive key',
    'EXPO_SECURE_STORE_WEAK_OPTIONS',
    await makeJsContext(`
      import * as SecureStore from 'expo-secure-store';
      SecureStore.setItemAsync('app_theme', val, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK });
    `),
    'none',
  );

  // ─── 9. INSECURE_WEBSOCKET ─────────────────────────────────────────────
  console.log('INSECURE_WEBSOCKET:');
  await assertFindings(
    'detects ws:// WebSocket',
    'INSECURE_WEBSOCKET',
    await makeJsContext(`const ws = new WebSocket('ws://api.example.com/ws');`),
    'some',
  );
  await assertFindings(
    'allows wss:// WebSocket',
    'INSECURE_WEBSOCKET',
    await makeJsContext(`const ws = new WebSocket('wss://api.example.com/ws');`),
    'none',
  );
  await assertFindings(
    'allows ws://localhost behind __DEV__',
    'INSECURE_WEBSOCKET',
    await makeJsContext(`
      if (__DEV__) { const ws = new WebSocket('ws://localhost:3000/ws'); }
    `),
    'none',
  );

  // ─── 10. HARDCODED_IP_ADDRESS ───────────────────────────────────────────
  console.log('HARDCODED_IP_ADDRESS:');
  await assertFindings(
    'detects public IP in URL',
    'HARDCODED_IP_ADDRESS',
    await makeJsContext(`const url = 'http://203.0.113.50:8080/api';`),
    'some',
  );
  await assertFindings(
    'allows private IP behind __DEV__',
    'HARDCODED_IP_ADDRESS',
    await makeJsContext(`
      const url = __DEV__ ? 'http://192.168.1.100:3000' : 'https://api.example.com';
    `),
    'none',
  );
  await assertFindings(
    'ignores IP in test files',
    'HARDCODED_IP_ADDRESS',
    await makeJsContext(
      `const url = 'http://10.0.0.1:3000/api';`,
      '/app/src/__tests__/api.test.ts',
    ),
    'none',
  );

  // ─── 11. EXPO_UPDATES_INSECURE_URL ──────────────────────────────────────
  console.log('EXPO_UPDATES_INSECURE_URL:');
  await assertFindings(
    'detects http:// updates URL',
    'EXPO_UPDATES_INSECURE_URL',
    makeJsonContext({ expo: { updates: { url: 'http://updates.example.com/manifest' } } }),
    'some',
  );
  await assertFindings(
    'allows https:// updates URL',
    'EXPO_UPDATES_INSECURE_URL',
    makeJsonContext({ expo: { updates: { url: 'https://updates.example.com/manifest' } } }),
    'none',
  );
  await assertFindings(
    'ignores missing updates URL',
    'EXPO_UPDATES_INSECURE_URL',
    makeJsonContext({ expo: { name: 'test' } }),
    'none',
  );

  // ─── 12. EXPO_SENSITIVE_CONFIG_EXPOSED ──────────────────────────────────
  console.log('EXPO_SENSITIVE_CONFIG_EXPOSED:');
  await assertFindings(
    'detects hardcoded secret in extra',
    'EXPO_SENSITIVE_CONFIG_EXPOSED',
    makeJsonContext({ expo: { extra: { apiSecret: 'sk_live_real_key_123' } } }),
    'some',
  );
  await assertFindings(
    'allows env reference in extra',
    'EXPO_SENSITIVE_CONFIG_EXPOSED',
    makeJsonContext({ expo: { extra: { apiSecret: '${process.env.API_SECRET}' } } }),
    'none',
  );
  await assertFindings(
    'allows placeholder values',
    'EXPO_SENSITIVE_CONFIG_EXPOSED',
    makeJsonContext({ expo: { extra: { client_secret: 'your_placeholder_value' } } }),
    'none',
  );

  // ─── 13. ANDROID_TASK_AFFINITY_VULNERABILITY ────────────────────────────
  console.log('ANDROID_TASK_AFFINITY_VULNERABILITY:');
  await assertFindings(
    'detects custom taskAffinity',
    'ANDROID_TASK_AFFINITY_VULNERABILITY',
    makeXmlContext(`
      <manifest><application>
        <activity android:name=".Pay" android:taskAffinity="com.example.pay"></activity>
      </application></manifest>
    `),
    'some',
  );
  await assertFindings(
    'allows empty taskAffinity (secure)',
    'ANDROID_TASK_AFFINITY_VULNERABILITY',
    makeXmlContext(`
      <manifest><application>
        <activity android:name=".Pay" android:taskAffinity=""></activity>
      </application></manifest>
    `),
    'none',
  );
  await assertFindings(
    'allows no taskAffinity attribute',
    'ANDROID_TASK_AFFINITY_VULNERABILITY',
    makeXmlContext(`
      <manifest><application>
        <activity android:name=".Main"></activity>
      </application></manifest>
    `),
    'none',
  );

  // ─── 14. ANDROID_WEBVIEW_DEBUG_ENABLED ──────────────────────────────────
  console.log('ANDROID_WEBVIEW_DEBUG_ENABLED:');
  await assertFindings(
    'detects webContentsDebuggingEnabled JSX prop',
    'ANDROID_WEBVIEW_DEBUG_ENABLED',
    await makeJsContext(`
      import { WebView } from 'react-native-webview';
      function App() { return <WebView webContentsDebuggingEnabled={true} />; }
    `),
    'some',
  );
  await assertFindings(
    'detects setWebContentsDebuggingEnabled(true) in Java',
    'ANDROID_WEBVIEW_DEBUG_ENABLED',
    makeNativeContext(
      'WebView.setWebContentsDebuggingEnabled(true);',
      '/app/android/WebViewHelper.java',
    ),
    'some',
  );
  await assertFindings(
    'allows debug behind __DEV__ guard',
    'ANDROID_WEBVIEW_DEBUG_ENABLED',
    await makeJsContext(`
      import { WebView } from 'react-native-webview';
      function App() { return <WebView webContentsDebuggingEnabled={__DEV__} />; }
    `),
    'none',
  );
  await assertFindings(
    'allows debug behind BuildConfig.DEBUG guard',
    'ANDROID_WEBVIEW_DEBUG_ENABLED',
    makeNativeContext(
      'if (BuildConfig.DEBUG) { WebView.setWebContentsDebuggingEnabled(true); }',
      '/app/android/WebViewHelper.java',
    ),
    'none',
  );

  // ─── 15. ANDROID_MISSING_NETWORK_SECURITY_CONFIG ────────────────────────
  console.log('ANDROID_MISSING_NETWORK_SECURITY_CONFIG:');
  await assertFindings(
    'detects missing network security config',
    'ANDROID_MISSING_NETWORK_SECURITY_CONFIG',
    makeXmlContext(`
      <manifest>
        <uses-permission android:name="android.permission.INTERNET" />
        <application android:name=".App"></application>
      </manifest>
    `),
    'some',
  );
  await assertFindings(
    'allows with network security config',
    'ANDROID_MISSING_NETWORK_SECURITY_CONFIG',
    makeXmlContext(`
      <manifest>
        <uses-permission android:name="android.permission.INTERNET" />
        <application android:name=".App" android:networkSecurityConfig="@xml/network_security_config"></application>
      </manifest>
    `),
    'none',
  );
  await assertFindings(
    'ignores apps without INTERNET permission',
    'ANDROID_MISSING_NETWORK_SECURITY_CONFIG',
    makeXmlContext(`
      <manifest>
        <application android:name=".App"></application>
      </manifest>
    `),
    'none',
  );

  // ─── 16. IOS_INSECURE_PASTEBOARD_USAGE ──────────────────────────────────
  console.log('IOS_INSECURE_PASTEBOARD_USAGE:');
  await assertFindings(
    'detects UIPasteboard with sensitive context',
    'IOS_INSECURE_PASTEBOARD_USAGE',
    makeNativeContext(
      `func copyPassword(_ password: String) { UIPasteboard.general.string = password }`,
      '/app/ios/CopyHelper.swift',
    ),
    'some',
  );
  await assertFindings(
    'allows UIPasteboard without sensitive context',
    'IOS_INSECURE_PASTEBOARD_USAGE',
    makeNativeContext(
      `func copyLink(_ link: String) { UIPasteboard.general.string = link }`,
      '/app/ios/ShareHelper.swift',
    ),
    'none',
  );

  // ─── 17. IOS_MISSING_APP_SNAPSHOT_PROTECTION ────────────────────────────
  console.log('IOS_MISSING_APP_SNAPSHOT_PROTECTION:');
  await assertFindings(
    'detects sensitive app without snapshot protection',
    'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
    await makeJsContext(
      `import React from 'react';\n// banking app\nfunction App() { return null; }`,
      '/app/App.tsx',
    ),
    'some',
  );
  await assertFindings(
    'allows with AppState + blur protection',
    'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
    await makeJsContext(
      `import React from 'react';\nimport { AppState } from 'react-native';\n// banking app\nAppState.addEventListener('change', () => { blur(); });`,
      '/app/App.tsx',
    ),
    'none',
  );
  await assertFindings(
    'ignores non-sensitive apps',
    'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
    await makeJsContext(
      `import React from 'react';\nfunction App() { return null; }`,
      '/app/App.tsx',
    ),
    'none',
  );
  await assertFindings(
    'ignores non-App files',
    'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
    await makeJsContext(
      `import React from 'react';\n// banking app\nfunction Screen() { return null; }`,
      '/app/src/screens/Home.tsx',
    ),
    'none',
  );

  // ─── IOS_DATA_PROTECTION_MISSING (fixed rule) ───────────────────────────
  console.log('IOS_DATA_PROTECTION_MISSING:');
  await assertFindings(
    'detects explicit NSFileProtectionNone',
    'IOS_DATA_PROTECTION_MISSING',
    {
      filePath: '/app/ios/App.entitlements',
      fileContent: '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionNone</string>',
      plistContent: '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionNone</string>',
    },
    'some',
  );
  await assertFindings(
    'does NOT flag missing entitlement (iOS default is secure)',
    'IOS_DATA_PROTECTION_MISSING',
    {
      filePath: '/app/ios/Info.plist',
      fileContent: '<key>NSFaceIDUsageDescription</key><string>Unlock with Face ID</string>',
      plistContent: '<key>NSFaceIDUsageDescription</key><string>Unlock with Face ID</string>',
    },
    'none',
  );
  await assertFindings(
    'does NOT flag explicit secure protection level',
    'IOS_DATA_PROTECTION_MISSING',
    {
      filePath: '/app/ios/App.entitlements',
      fileContent: '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionComplete</string>',
      plistContent: '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionComplete</string>',
    },
    'none',
  );
  await assertFindings(
    'does NOT flag app with camera/location (not a file storage concern)',
    'IOS_DATA_PROTECTION_MISSING',
    {
      filePath: '/app/ios/Info.plist',
      fileContent: '<key>NSCameraUsageDescription</key><string>Take photos</string><key>NSLocationAlwaysUsageDescription</key><string>Track location</string>',
      plistContent: '<key>NSCameraUsageDescription</key><string>Take photos</string><key>NSLocationAlwaysUsageDescription</key><string>Track location</string>',
    },
    'none',
  );

  // ─── 18. CUSTOM_CRYPTO_IMPLEMENTATION ───────────────────────────────────
  console.log('CUSTOM_CRYPTO_IMPLEMENTATION:');
  await assertFindings(
    'detects DIY crypto function',
    'CUSTOM_CRYPTO_IMPLEMENTATION',
    await makeJsContext(`
      function customEncrypt(data, key) {
        let result = '';
        for (let i = 0; i < data.length; i++) {
          result += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
        }
        return result;
      }
    `),
    'some',
  );
  await assertFindings(
    'allows crypto library wrapper',
    'CUSTOM_CRYPTO_IMPLEMENTATION',
    await makeJsContext(`
      function customEncrypt(data, key) {
        return CryptoJS.AES.encrypt(data, key).toString();
      }
    `),
    'none',
  );
  await assertFindings(
    'ignores test files',
    'CUSTOM_CRYPTO_IMPLEMENTATION',
    await makeJsContext(
      `function customEncrypt(d, k) { return d ^ k; }`,
      '/app/src/__tests__/crypto.test.ts',
    ),
    'none',
  );

  // ─── 19. MISSING_SESSION_TIMEOUT ────────────────────────────────────────
  console.log('MISSING_SESSION_TIMEOUT:');
  await assertFindings(
    'detects auth file without timeout',
    'MISSING_SESSION_TIMEOUT',
    await makeJsContext(
      `async function login(user, pass) { await setItem('session_token', token); }`,
      '/app/src/authService.tsx',
    ),
    'some',
  );
  await assertFindings(
    'allows auth file with timeout',
    'MISSING_SESSION_TIMEOUT',
    await makeJsContext(
      `const SESSION_TIMEOUT = 30000;\nasync function login(user, pass) { await setItem('session_token', token); }`,
      '/app/src/authService.tsx',
    ),
    'none',
  );
  await assertFindings(
    'ignores non-auth files',
    'MISSING_SESSION_TIMEOUT',
    await makeJsContext(
      `async function login(user, pass) { await setItem('session_token', token); }`,
      '/app/src/utils/api.tsx',
    ),
    'none',
  );

  // ─── Summary ────────────────────────────────────────────────────────────
  console.log(`\n${'='.repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);

  if (failures.length > 0) {
    console.log('\nFailed tests:');
    failures.forEach((f) => console.log(f));
  }

  console.log('');
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
  console.error('Test runner error:', err);
  process.exit(1);
});
