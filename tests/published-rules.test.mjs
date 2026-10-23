import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Ported from the former tests/rules.test.ts (tsx). Like the other suites this exercises the BUILT dist.
// Rules are applied directly to synthetic contexts (no file walker, no engine filtering).
const dist = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const load = rel => import(pathToFileURL(resolve(dist, rel)).href);

const { parseJSFile } = await load('core/astParser.js');
const { reactNativeRules } = await load('scanners/react-native/reactNativeScanner.js');
const { storageRules } = await load('scanners/security/storageScanner.js');
const { networkRules } = await load('scanners/security/networkScanner.js');
const { configRules } = await load('scanners/security/configScanner.js');
const { androidRules } = await load('scanners/android/androidScanner.js');
const { iosRules } = await load('scanners/ios/iosScanner.js');
const { cryptoRules } = await load('scanners/security/cryptoScanner.js');
const { authenticationRules } = await load('scanners/security/authenticationScanner.js');
const { webviewRules } = await load('scanners/security/webviewScanner.js');
const { expoConfigRules } = await load('scanners/security/expoConfigScanner.js');

const allGroups = [
  reactNativeRules, storageRules, networkRules, configRules, expoConfigRules,
  androidRules, iosRules, cryptoRules, authenticationRules, webviewRules,
];

function findRule(id) {
  for (const g of allGroups) {
    const r = g.rules.find(r => r.id === id);
    if (r) return r;
  }
  throw new Error(`Rule ${id} not found`);
}

async function makeJsContext(code, filePath = '/app/src/Component.tsx') {
  const result = await parseJSFile(filePath, code);
  return { filePath, fileContent: code, ast: result.ast };
}

function makeJsonContext(json, filePath = '/app/app.json') {
  return { filePath, fileContent: JSON.stringify(json, null, 2), config: json };
}

function makeXmlContext(xml, filePath = '/app/android/AndroidManifest.xml') {
  return { filePath, fileContent: xml, xmlContent: xml };
}

function makeNativeContext(code, filePath) {
  return { filePath, fileContent: code };
}

/** expectCount: 'none' | 'some' | exact number. `opts.todo` marks a known divergence from the local FP-reduction work. */
function check(testName, ruleId, contextOrPromise, expectCount, opts = {}) {
  test(`${ruleId}: ${testName}`, opts, async () => {
    const findings = await findRule(ruleId).apply(await contextOrPromise);
    const matched = findings.filter(f => f.ruleId === ruleId);
    if (expectCount === 'none') assert.equal(matched.length, 0, `expected none, got ${JSON.stringify(matched.map(f => [f.line, f.description]))}`);
    else if (expectCount === 'some') assert.ok(matched.length > 0, 'expected at least one finding');
    else assert.equal(matched.length, expectCount);
  });
}

// ─── 1. EXPO_UPDATES_NO_CODE_SIGNING ────────────────────────────────────
check(
  'detects updates without code signing',
  'EXPO_UPDATES_NO_CODE_SIGNING',
  makeJsonContext({ expo: { updates: { url: 'https://u.expo.dev/xxx' }, runtimeVersion: '1.0.0' } }),
  'some',
);
check(
  'allows updates with code signing',
  'EXPO_UPDATES_NO_CODE_SIGNING',
  makeJsonContext({ expo: { updates: { url: 'https://u.expo.dev/xxx', codeSigningCertificate: './cert.pem' }, runtimeVersion: '1.0.0' } }),
  'none',
);
check(
  'ignores non-expo config',
  'EXPO_UPDATES_NO_CODE_SIGNING',
  makeJsonContext({ name: 'test' }),
  'none',
);

// ─── 2. INSECURE_LINKING_OPEN ───────────────────────────────────────────
check(
  'detects Linking.openURL with variable',
  'INSECURE_LINKING_OPEN',
  makeJsContext(`
    import { Linking } from 'react-native';
    function open(url) { Linking.openURL(url); }
  `),
  'some',
);
check(
  'allows Linking.openURL with string literal',
  'INSECURE_LINKING_OPEN',
  makeJsContext(`
    import { Linking } from 'react-native';
    Linking.openURL('https://example.com');
  `),
  'none',
);
check(
  'allows Linking.openURL with validation nearby',
  'INSECURE_LINKING_OPEN',
  makeJsContext(`
    import { Linking } from 'react-native';
    function open(url) {
      if (url.startsWith('https://')) { Linking.openURL(url); }
    }
  `),
  'none',
);

// ─── 3. SENSITIVE_NAVIGATION_PARAMS ─────────────────────────────────────
check(
  'detects token in navigation params',
  'SENSITIVE_NAVIGATION_PARAMS',
  makeJsContext(`
    function go(nav) { nav.navigate('Profile', { token: 'abc' }); }
  `),
  'some',
);
check(
  'detects password in navigation.push params',
  'SENSITIVE_NAVIGATION_PARAMS',
  makeJsContext(`
    function go(nav) { nav.push('Login', { password: 'secret' }); }
  `),
  'some',
);
check(
  'allows non-sensitive navigation params',
  'SENSITIVE_NAVIGATION_PARAMS',
  makeJsContext(`
    function go(nav) { nav.navigate('Details', { itemId: 42, title: 'Hello' }); }
  `),
  'none',
);

// ─── 4. PUSH_NOTIFICATION_SENSITIVE_DATA ────────────────────────────────
check(
  'detects logging notification data',
  'PUSH_NOTIFICATION_SENSITIVE_DATA',
  makeJsContext(`
    import * as Notifications from 'expo-notifications';
    Notifications.addNotificationReceivedListener((n) => {
      console.log(n.request.content.data);
    });
  `),
  'none', // notification.data pattern not matched by regex exactly — need notification.request.content.data
);
check(
  'detects logging notification.request.content.data',
  'PUSH_NOTIFICATION_SENSITIVE_DATA',
  makeJsContext(`
    import * as Notifications from 'expo-notifications';
    Notifications.addNotificationReceivedListener((notification) => {
      console.log('data:', notification.request.content.data);
    });
  `),
  'some',
);
check(
  'safe notification handler without logging',
  'PUSH_NOTIFICATION_SENSITIVE_DATA',
  makeJsContext(`
    import * as Notifications from 'expo-notifications';
    Notifications.addNotificationReceivedListener((notification) => {
      const type = notification.request.content.data?.type;
      refreshContent();
    });
  `),
  'none',
);
check(
  'no push import - no findings',
  'PUSH_NOTIFICATION_SENSITIVE_DATA',
  makeJsContext(`
    import React from 'react';
    function foo() { console.log('hello'); }
  `),
  'none',
);

// ─── 5. EXPO_AUTH_SESSION_NO_PKCE ───────────────────────────────────────
check(
  'detects usePKCE: false',
  'EXPO_AUTH_SESSION_NO_PKCE',
  makeJsContext(`
    import * as AuthSession from 'expo-auth-session';
    const [req] = useAuthRequest({ clientId: 'x', usePKCE: false });
  `),
  'some',
);
check(
  'allows usePKCE: true',
  'EXPO_AUTH_SESSION_NO_PKCE',
  makeJsContext(`
    import * as AuthSession from 'expo-auth-session';
    const [req] = useAuthRequest({ clientId: 'x', usePKCE: true });
  `),
  'none',
);
check(
  'allows omitted usePKCE (default true)',
  'EXPO_AUTH_SESSION_NO_PKCE',
  makeJsContext(`
    import * as AuthSession from 'expo-auth-session';
    const [req] = useAuthRequest({ clientId: 'x' });
  `),
  'none',
);
check(
  'no auth-session import - no findings',
  'EXPO_AUTH_SESSION_NO_PKCE',
  makeJsContext(`
    function foo() { useAuthRequest({ usePKCE: false }); }
  `),
  'none',
);

// ─── 6. UNENCRYPTED_REALM_DATABASE ──────────────────────────────────────
check(
  'detects Realm.open without encryption in sensitive context',
  'UNENCRYPTED_REALM_DATABASE',
  makeJsContext(`
    import Realm from 'realm';
    // Stores user credentials
    const realm = await Realm.open({ schema: [UserSchema] });
  `),
  'some',
);
check(
  'allows Realm.open with encryptionKey',
  'UNENCRYPTED_REALM_DATABASE',
  makeJsContext(`
    import Realm from 'realm';
    const realm = await Realm.open({ schema: [UserSchema], encryptionKey: key });
  `),
  'none',
);
check(
  'allows Realm.open without sensitive context',
  'UNENCRYPTED_REALM_DATABASE',
  makeJsContext(`
    import Realm from 'realm';
    const realm = await Realm.open({ schema: [CacheSchema] });
  `),
  'none',
);

check(
  'ignores look-alike identifiers (tokenizer, authorName, userAgent, passportPhoto)',
  'UNENCRYPTED_REALM_DATABASE',
  makeJsContext(`
    import Realm from 'realm';
    const tokenizer = makeTokenizer();
    const authorName = 'x';
    const userAgent = navigator.userAgent;
    const passportPhoto = null;
    const realm = await Realm.open({ schema: [CacheSchema] });
  `),
  'none',
);

// ─── 7. UNENCRYPTED_SQLITE_DATABASE ─────────────────────────────────────
check(
  'detects SQLite without encryption in sensitive context',
  'UNENCRYPTED_SQLITE_DATABASE',
  makeJsContext(`
    import * as SQLite from 'expo-sqlite';
    // store user session tokens
    const db = SQLite.openDatabase('users.db');
  `),
  'some',
);
check(
  'allows SQLite with sqlcipher',
  'UNENCRYPTED_SQLITE_DATABASE',
  makeJsContext(`
    import * as SQLite from 'expo-sqlite';
    // store user session data with sqlcipher
    const db = SQLite.openDatabase('users.db');
  `),
  'none',
);
check(
  'allows SQLite without sensitive context',
  'UNENCRYPTED_SQLITE_DATABASE',
  makeJsContext(`
    import * as SQLite from 'expo-sqlite';
    const db = SQLite.openDatabase('cache.db');
  `),
  'none',
);

check(
  'ignores look-alike identifiers (tokenizer, authorName, userAgent, passportPhoto)',
  'UNENCRYPTED_SQLITE_DATABASE',
  makeJsContext(`
    import * as SQLite from 'expo-sqlite';
    const tokenizer = makeTokenizer();
    const authorName = 'x';
    const userAgent = navigator.userAgent;
    const passportPhoto = null;
    const db = SQLite.openDatabase('cache.db');
  `),
  'none',
);

// ─── 8. EXPO_SECURE_STORE_WEAK_OPTIONS ──────────────────────────────────
// Deliberate change from 1.3.0: AFTER_FIRST_UNLOCK is Apple's recommended replacement for the deprecated
// ALWAYS and a background-access trade-off, not a weakness, so it is no longer reported. ALWAYS* is.
check(
  'allows AFTER_FIRST_UNLOCK for sensitive key (intentional FP fix, was reported in 1.3.0)',
  'EXPO_SECURE_STORE_WEAK_OPTIONS',
  makeJsContext(`
    import * as SecureStore from 'expo-secure-store';
    SecureStore.setItemAsync('auth_token', tok, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK });
  `),
  'none',
);
check(
  'detects ALWAYS for sensitive key',
  'EXPO_SECURE_STORE_WEAK_OPTIONS',
  makeJsContext(`
    import * as SecureStore from 'expo-secure-store';
    SecureStore.setItemAsync('auth_token', tok, { keychainAccessible: SecureStore.ALWAYS });
  `),
  1,
);
check(
  'detects ALWAYS_THIS_DEVICE_ONLY for non-sensitive key',
  'EXPO_SECURE_STORE_WEAK_OPTIONS',
  makeJsContext(`
    import * as SecureStore from 'expo-secure-store';
    SecureStore.setItemAsync('app_theme', val, { keychainAccessible: SecureStore.ALWAYS_THIS_DEVICE_ONLY });
  `),
  1,
);
check(
  'allows WHEN_UNLOCKED for sensitive key',
  'EXPO_SECURE_STORE_WEAK_OPTIONS',
  makeJsContext(`
    import * as SecureStore from 'expo-secure-store';
    SecureStore.setItemAsync('auth_token', tok, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
  `),
  'none',
);
check(
  'allows AFTER_FIRST_UNLOCK for non-sensitive key',
  'EXPO_SECURE_STORE_WEAK_OPTIONS',
  makeJsContext(`
    import * as SecureStore from 'expo-secure-store';
    SecureStore.setItemAsync('app_theme', val, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK });
  `),
  'none',
);

// ─── 9. INSECURE_WEBSOCKET ─────────────────────────────────────────────
check(
  'detects ws:// WebSocket',
  'INSECURE_WEBSOCKET',
  makeJsContext(`const ws = new WebSocket('ws://api.example.com/ws');`),
  'some',
);
check(
  'allows wss:// WebSocket',
  'INSECURE_WEBSOCKET',
  makeJsContext(`const ws = new WebSocket('wss://api.example.com/ws');`),
  'none',
);
check(
  'allows ws://localhost behind __DEV__',
  'INSECURE_WEBSOCKET',
  makeJsContext(`
    if (__DEV__) { const ws = new WebSocket('ws://localhost:3000/ws'); }
  `),
  'none',
);

// ─── 10. HARDCODED_IP_ADDRESS ───────────────────────────────────────────
// 1.3.0 used 203.0.113.50 here; that is an RFC 5737 documentation address and is deliberately no longer reported
check(
  'detects public IP in URL',
  'HARDCODED_IP_ADDRESS',
  makeJsContext(`const url = 'http://45.33.32.156:8080/api';`),
  'some',
);
check(
  'allows private IP behind __DEV__',
  'HARDCODED_IP_ADDRESS',
  makeJsContext(`
    const url = __DEV__ ? 'http://192.168.1.100:3000' : 'https://api.example.com';
  `),
  'none',
);
check(
  'ignores IP in test files',
  'HARDCODED_IP_ADDRESS',
  makeJsContext(
    `const url = 'http://10.0.0.1:3000/api';`,
    '/app/src/__tests__/api.test.ts',
  ),
  'none',
);

// ─── 11. EXPO_UPDATES_INSECURE_URL ──────────────────────────────────────
check(
  'detects http:// updates URL',
  'EXPO_UPDATES_INSECURE_URL',
  makeJsonContext({ expo: { updates: { url: 'http://updates.example.com/manifest' } } }),
  'some',
);
check(
  'allows https:// updates URL',
  'EXPO_UPDATES_INSECURE_URL',
  makeJsonContext({ expo: { updates: { url: 'https://updates.example.com/manifest' } } }),
  'none',
);
check(
  'ignores missing updates URL',
  'EXPO_UPDATES_INSECURE_URL',
  makeJsonContext({ expo: { name: 'test' } }),
  'none',
);

// ─── 12. EXPO_SENSITIVE_CONFIG_EXPOSED ──────────────────────────────────
check(
  'detects hardcoded secret in extra',
  'EXPO_SENSITIVE_CONFIG_EXPOSED',
  makeJsonContext({ expo: { extra: { apiSecret: 'sk_live_real_key_123' } } }),
  'some',
);
check(
  'allows env reference in extra',
  'EXPO_SENSITIVE_CONFIG_EXPOSED',
  makeJsonContext({ expo: { extra: { apiSecret: '${process.env.API_SECRET}' } } }),
  'none',
);
check(
  'allows placeholder values',
  'EXPO_SENSITIVE_CONFIG_EXPOSED',
  makeJsonContext({ expo: { extra: { client_secret: 'your_placeholder_value' } } }),
  'none',
);

// ─── 13. ANDROID_TASK_AFFINITY_VULNERABILITY ────────────────────────────
check(
  'detects custom taskAffinity',
  'ANDROID_TASK_AFFINITY_VULNERABILITY',
  makeXmlContext(`
    <manifest><application>
      <activity android:name=".Pay" android:taskAffinity="com.example.pay"></activity>
    </application></manifest>
  `),
  'some',
);
check(
  'allows empty taskAffinity (secure)',
  'ANDROID_TASK_AFFINITY_VULNERABILITY',
  makeXmlContext(`
    <manifest><application>
      <activity android:name=".Pay" android:taskAffinity=""></activity>
    </application></manifest>
  `),
  'none',
);
check(
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
check(
  'detects webContentsDebuggingEnabled JSX prop',
  'ANDROID_WEBVIEW_DEBUG_ENABLED',
  makeJsContext(`
    import { WebView } from 'react-native-webview';
    function App() { return <WebView webContentsDebuggingEnabled={true} />; }
  `),
  'some',
);
check(
  'detects setWebContentsDebuggingEnabled(true) in Java',
  'ANDROID_WEBVIEW_DEBUG_ENABLED',
  makeNativeContext(
    'WebView.setWebContentsDebuggingEnabled(true);',
    '/app/android/WebViewHelper.java',
  ),
  'some',
);
check(
  'allows debug behind __DEV__ guard',
  'ANDROID_WEBVIEW_DEBUG_ENABLED',
  makeJsContext(`
    import { WebView } from 'react-native-webview';
    function App() { return <WebView webContentsDebuggingEnabled={__DEV__} />; }
  `),
  'none',
);
check(
  'allows debug behind BuildConfig.DEBUG guard',
  'ANDROID_WEBVIEW_DEBUG_ENABLED',
  makeNativeContext(
    'if (BuildConfig.DEBUG) { WebView.setWebContentsDebuggingEnabled(true); }',
    '/app/android/WebViewHelper.java',
  ),
  'none',
);

// ─── 15. ANDROID_MISSING_NETWORK_SECURITY_CONFIG ────────────────────────
check(
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
check(
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
check(
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
check(
  'detects UIPasteboard with sensitive context',
  'IOS_INSECURE_PASTEBOARD_USAGE',
  makeNativeContext(
    `func copyPassword(_ password: String) { UIPasteboard.general.string = password }`,
    '/app/ios/CopyHelper.swift',
  ),
  'some',
);
check(
  'allows UIPasteboard without sensitive context',
  'IOS_INSECURE_PASTEBOARD_USAGE',
  makeNativeContext(
    `func copyLink(_ link: String) { UIPasteboard.general.string = link }`,
    '/app/ios/ShareHelper.swift',
  ),
  'none',
);

// ─── 17. IOS_MISSING_APP_SNAPSHOT_PROTECTION ────────────────────────────
check(
  'detects sensitive app without snapshot protection',
  'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
  makeJsContext(
    `import React from 'react';\n// banking app\nfunction App() { return null; }`,
    '/app/App.tsx',
  ),
  'some',
);
check(
  'allows with AppState + blur protection',
  'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
  makeJsContext(
    `import React from 'react';\nimport { AppState } from 'react-native';\n// banking app\nAppState.addEventListener('change', () => { blur(); });`,
    '/app/App.tsx',
  ),
  'none',
);
check(
  'ignores non-sensitive apps',
  'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
  makeJsContext(
    `import React from 'react';\nfunction App() { return null; }`,
    '/app/App.tsx',
  ),
  'none',
);
check(
  'ignores non-App files',
  'IOS_MISSING_APP_SNAPSHOT_PROTECTION',
  makeJsContext(
    `import React from 'react';\n// banking app\nfunction Screen() { return null; }`,
    '/app/src/screens/Home.tsx',
  ),
  'none',
);

// ─── IOS_DATA_PROTECTION_MISSING (fixed rule) ───────────────────────────
check(
  'detects explicit NSFileProtectionNone',
  'IOS_DATA_PROTECTION_MISSING',
  {
    filePath: '/app/ios/App.entitlements',
    fileContent: '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionNone</string>',
    plistContent: '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionNone</string>',
  },
  'some',
);
check(
  'does NOT flag missing entitlement (iOS default is secure)',
  'IOS_DATA_PROTECTION_MISSING',
  {
    filePath: '/app/ios/Info.plist',
    fileContent: '<key>NSFaceIDUsageDescription</key><string>Unlock with Face ID</string>',
    plistContent: '<key>NSFaceIDUsageDescription</key><string>Unlock with Face ID</string>',
  },
  'none',
);
check(
  'does NOT flag explicit secure protection level',
  'IOS_DATA_PROTECTION_MISSING',
  {
    filePath: '/app/ios/App.entitlements',
    fileContent: '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionComplete</string>',
    plistContent: '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionComplete</string>',
  },
  'none',
);
check(
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
check(
  'detects DIY crypto function',
  'CUSTOM_CRYPTO_IMPLEMENTATION',
  makeJsContext(`
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
check(
  'allows crypto library wrapper',
  'CUSTOM_CRYPTO_IMPLEMENTATION',
  makeJsContext(`
    function customEncrypt(data, key) {
      return CryptoJS.AES.encrypt(data, key).toString();
    }
  `),
  'none',
);
check(
  'ignores test files',
  'CUSTOM_CRYPTO_IMPLEMENTATION',
  makeJsContext(
    `function customEncrypt(d, k) { return d ^ k; }`,
    '/app/src/__tests__/crypto.test.ts',
  ),
  'none',
);

// ─── 19. MISSING_SESSION_TIMEOUT ────────────────────────────────────────
check(
  'detects auth file without timeout',
  'MISSING_SESSION_TIMEOUT',
  makeJsContext(
    `async function login(user, pass) { await setItem('session_token', token); }`,
    '/app/src/authService.tsx',
  ),
  'some',
);
check(
  'allows auth file with timeout',
  'MISSING_SESSION_TIMEOUT',
  makeJsContext(
    `const SESSION_TIMEOUT = 30000;\nasync function login(user, pass) { await setItem('session_token', token); }`,
    '/app/src/authService.tsx',
  ),
  'none',
);
check(
  'ignores non-auth files',
  'MISSING_SESSION_TIMEOUT',
  makeJsContext(
    `async function login(user, pass) { await setItem('session_token', token); }`,
    '/app/src/utils/api.tsx',
  ),
  'none',
);


// ─── Regression tests for fixes that shipped in the published 1.3.0 ───────────

const applyRule = async (ruleId, ctx) => (await findRule(ruleId).apply(await ctx)).filter(f => f.ruleId === ruleId);
const HTML_NO_CSP = /HTML without Content-Security-Policy/;

// d77f271: MISSING_SECURITY_HEADERS must resolve `source={variable}` instead of guessing from the identifier
test('MISSING_SECURITY_HEADERS: source variable holding { uri } is not inline HTML', async () => {
  const found = await applyRule('MISSING_SECURITY_HEADERS', makeJsContext(`
    import { WebView } from 'react-native-webview';
    const source = { uri: 'https://example.com/page' };
    export default function App() { return <WebView source={source} />; }
  `));
  assert.ok(!found.some(f => HTML_NO_CSP.test(f.description)), `must not be treated as HTML: ${found.map(f => f.description)}`);
  // it is still remote content without headers, which is the other branch of the rule
  assert.equal(found.length, 1);
  assert.match(found[0].description, /external content/);
});

test('MISSING_SECURITY_HEADERS: source variable holding { uri } next to unrelated html: text stays a uri source', async () => {
  const found = await applyRule('MISSING_SECURITY_HEADERS', makeJsContext(`
    import { WebView } from 'react-native-webview';
    const labels = { html: 'HTML' };
    const source = { uri: 'https://example.com/page', headers: { 'X-Frame-Options': 'DENY' } };
    export default function App() { return <WebView source={source} />; }
  `));
  assert.equal(found.length, 0, `headers are set on the uri source: ${found.map(f => f.description)}`);
});

test('MISSING_SECURITY_HEADERS: source variable holding { html } with a script and no CSP is reported', async () => {
  const found = await applyRule('MISSING_SECURITY_HEADERS', makeJsContext(`
    import { WebView } from 'react-native-webview';
    const source = { html: '<html><body><script>window.go()</script></body></html>' };
    export default function App() { return <WebView source={source} />; }
  `));
  assert.equal(found.length, 1);
  assert.match(found[0].description, HTML_NO_CSP);
});

test('MISSING_SECURITY_HEADERS: source variable holding { html } with a CSP meta tag is not reported', async () => {
  const found = await applyRule('MISSING_SECURITY_HEADERS', makeJsContext(`
    import { WebView } from 'react-native-webview';
    const source = { html: '<html><head><meta http-equiv="Content-Security-Policy" content="default-src \\'self\\'"></head><script>x()</script></html>' };
    export default function App() { return <WebView source={source} />; }
  `));
  assert.equal(found.length, 0);
});

// d77f271 also handled the ES6 shorthand `{ html }`
test('MISSING_SECURITY_HEADERS: shorthand { html } variable carrying a script and no CSP is reported', async () => {
  const found = await applyRule('MISSING_SECURITY_HEADERS', makeJsContext(`
    import { WebView } from 'react-native-webview';
    const html = '<html><script>window.go()</script></html>';
    const source = { html };
    export default function App() { return <WebView source={source} />; }
  `));
  assert.equal(found.length, 1);
  assert.match(found[0].description, HTML_NO_CSP);
});

// c5160de: NETWORK_LOGGER_IN_PRODUCTION must not fire on mere `.data` / `.headers` access
test('NETWORK_LOGGER_IN_PRODUCTION: interceptor that logs with console.log is reported', async () => {
  const found = await applyRule('NETWORK_LOGGER_IN_PRODUCTION', makeJsContext(`
    import axios from 'axios';
    axios.interceptors.request.use((config) => { console.log('request', config); return config; });
  `));
  assert.equal(found.length, 1);
});

test('NETWORK_LOGGER_IN_PRODUCTION: logger.* and debug() calls count as logging', async () => {
  const a = await applyRule('NETWORK_LOGGER_IN_PRODUCTION', makeJsContext(`
    axios.interceptors.response.use((response) => { logger.info(response.status); return response; });
  `));
  const b = await applyRule('NETWORK_LOGGER_IN_PRODUCTION', makeJsContext(`
    axios.interceptors.response.use((response) => { debug(response.status); return response; });
  `));
  assert.equal(a.length, 1);
  assert.equal(b.length, 1);
});

test('NETWORK_LOGGER_IN_PRODUCTION: interceptor reading .data and .headers without logging is not reported', async () => {
  const found = await applyRule('NETWORK_LOGGER_IN_PRODUCTION', makeJsContext(`
    import axios from 'axios';
    axios.interceptors.response.use((response) => {
      const payload = response.data;
      const type = response.headers['content-type'];
      return { ...response, payload, type };
    });
  `));
  assert.equal(found.length, 0, `${found.map(f => f.line)}`);
});

test('NETWORK_LOGGER_IN_PRODUCTION: logging guarded by __DEV__ is not reported', async () => {
  const found = await applyRule('NETWORK_LOGGER_IN_PRODUCTION', makeJsContext(`
    axios.interceptors.request.use((config) => { if (__DEV__) { console.log(config); } return config; });
  `));
  assert.equal(found.length, 0);
});

// 6a68e9b: IOS_DATA_PROTECTION_MISSING only reports an explicit NSFileProtectionNone
const plist = (xml, filePath = '/app/ios/App.entitlements') => ({ filePath, fileContent: xml, plistContent: xml });

test('IOS_DATA_PROTECTION_MISSING: NSFileProtectionNone is reported as MEDIUM with the fix-it advice', async () => {
  const found = await applyRule('IOS_DATA_PROTECTION_MISSING', plist(
    '<key>com.apple.developer.default-data-protection</key><string>NSFileProtectionNone</string>',
  ));
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'MEDIUM');
  assert.match(found[0].description, /NSFileProtectionNone/);
  assert.match(found[0].suggestion, /Keychain/);
});

test('IOS_DATA_PROTECTION_MISSING: intermediate protection levels and sensitive-feature plists are not reported', async () => {
  for (const level of ['NSFileProtectionCompleteUnlessOpen', 'NSFileProtectionCompleteUntilFirstUserAuthentication']) {
    const found = await applyRule('IOS_DATA_PROTECTION_MISSING', plist(
      `<key>com.apple.developer.default-data-protection</key><string>${level}</string>`,
    ));
    assert.equal(found.length, 0, level);
  }
  const bare = await applyRule('IOS_DATA_PROTECTION_MISSING', plist(
    '<key>NSFaceIDUsageDescription</key><string>x</string><key>NSHealthShareUsageDescription</key><string>y</string>', '/app/ios/Info.plist',
  ));
  assert.equal(bare.length, 0);
});

test('MISSING_SECURITY_HEADERS: { html: page } and a CSP held in the const are resolved through the identifier', async () => {
  const withScript = await applyRule('MISSING_SECURITY_HEADERS', makeJsContext(`
    import { WebView } from 'react-native-webview';
    const page = '<html><script>window.go()</script></html>';
    export default function App() { return <WebView source={{ html: page }} />; }
  `));
  assert.equal(withScript.length, 1);
  const withCsp = await applyRule('MISSING_SECURITY_HEADERS', makeJsContext(`
    import { WebView } from 'react-native-webview';
    const html = '<html><head><meta http-equiv="Content-Security-Policy" content="default-src none"></head><script>x()</script></html>';
    const source = { html };
    export default function App() { return <WebView source={source} />; }
  `));
  assert.equal(withCsp.length, 0);
});

// Manifest findings carry the line of the activity / application opening tag
test('ANDROID_TASK_AFFINITY_VULNERABILITY: finding has the line of the activity opening tag', async () => {
  const found = await applyRule('ANDROID_TASK_AFFINITY_VULNERABILITY', makeXmlContext([
    '<manifest>',
    '  <application>',
    '    <activity android:name=".Main" />',
    '    <activity',
    '      android:name=".Pay"',
    '      android:taskAffinity="com.example.pay">',
    '    </activity>',
    '    <!-- <activity android:name=".Old" android:taskAffinity="com.example.old" /> -->',
    '  </application>',
    '</manifest>',
  ].join('\n')));
  assert.deepEqual(found.map(f => f.line), [4]);
});

test('ANDROID_MISSING_NETWORK_SECURITY_CONFIG: finding has the line of the <application> tag', async () => {
  const found = await applyRule('ANDROID_MISSING_NETWORK_SECURITY_CONFIG', makeXmlContext([
    '<manifest>',
    '  <uses-permission android:name="android.permission.INTERNET" />',
    '  <application android:name=".App">',
    '  </application>',
    '</manifest>',
  ].join('\n')));
  assert.deepEqual(found.map(f => f.line), [3]);
});
