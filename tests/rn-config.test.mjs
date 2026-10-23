import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { scan, byRule } from './helpers.mjs';
import { repoRoot } from './helpers.mjs';

const lines = (r, id, file) =>
  byRule(r, id).filter(f => !file || f.filePath.endsWith(file)).map(f => f.line).sort((a, b) => a - b);
const MANIFEST = 'AndroidManifest.xml';

// ---- THIRD_PARTY_SDK_RISK
test('THIRD_PARTY_SDK_RISK: adjustPadding / adjust-padding are not the Adjust SDK', () => {
  assert.equal(byRule(scan('rnc-sdk-neg'), 'THIRD_PARTY_SDK_RISK').length, 0);
});

test('THIRD_PARTY_SDK_RISK: declared SDK is reported once on package.json with its line', () => {
  // react-native-adjust plus two @segment/* packages: one finding per SDK, not per package
  const found = byRule(scan('rnc-sdk-pos'), 'THIRD_PARTY_SDK_RISK');
  assert.deepEqual(found.map(f => f.line), [5, 6]);
  assert.match(found[0].description, /adjust/);
  assert.match(found[1].description, /segment/);
  assert.equal(found[0].severity, 'LOW');
  assert.equal(found[0].confidence, 'medium');
});

test('THIRD_PARTY_SDK_RISK: an imported SDK is found without a package.json', () => {
  const found = byRule(scan('rnc-sdk-import'), 'THIRD_PARTY_SDK_RISK');
  assert.equal(found.length, 1);
  assert.match(found[0].description, /adjust/);
});

// ---- EVAL_USAGE
test('EVAL_USAGE: constant-string eval/Function is skipped, dynamic and new Function are flagged', () => {
  const r = scan('rnc-eval');
  assert.deepEqual(lines(r, 'EVAL_USAGE', 'lit.js'), []);
  assert.deepEqual(lines(r, 'EVAL_USAGE', 'dyn.js'), [2, 3]);
  assert.deepEqual(lines(r, 'INSECURE_DESERIALIZATION', 'lit.js'), []);
});

test('OBFUSCATED_EVAL_EXECUTION still fires on eval(Buffer.from(..).toString())', () => {
  assert.deepEqual(lines(scan('rnc-eval'), 'OBFUSCATED_EVAL_EXECUTION', 'obf.js'), [1]);
});

// ---- absence rules
test('absence rules: a declared detection/integrity library suppresses both', () => {
  const r = scan('rnc-absence-protected');
  assert.equal(byRule(r, 'ROOT_JAILBREAK_DETECTION_ABSENT').length, 0);
  assert.equal(byRule(r, 'MISSING_RUNTIME_INTEGRITY_CHECKS').length, 0);
});

test('absence rules: payments app without a library gets LOW/low findings on the entry file only', () => {
  const r = scan('rnc-absence-unprotected'); // react-native-device-info does not count as root detection
  for (const id of ['ROOT_JAILBREAK_DETECTION_ABSENT', 'MISSING_RUNTIME_INTEGRITY_CHECKS']) {
    const found = byRule(r, id);
    assert.equal(found.length, 1, id);
    assert.ok(found[0].filePath.endsWith('App.tsx'));
    assert.equal(found[0].severity, 'LOW');
    assert.equal(found[0].confidence, 'low');
  }
});

test('absence rules: domain words in code do not make an app high-risk', () => {
  const r = scan('rnc-absence-words');
  assert.equal(byRule(r, 'ROOT_JAILBREAK_DETECTION_ABSENT').length, 0);
  assert.equal(byRule(r, 'MISSING_RUNTIME_INTEGRITY_CHECKS').length, 0);
});

test('examples/secure-app no longer reports MISSING_RUNTIME_INTEGRITY_CHECKS', () => {
  const r = scan(resolve(repoRoot, 'examples/secure-app'));
  assert.equal(byRule(r, 'MISSING_RUNTIME_INTEGRITY_CHECKS').length, 0);
});

// ---- npm
test('SUSPICIOUS_LIFECYCLE_SCRIPT: patch-package || true and an unescaped-dot lookalike are fine', () => {
  assert.equal(byRule(scan('rnc-lifecycle-safe'), 'SUSPICIOUS_LIFECYCLE_SCRIPT').length, 0);
  assert.equal(byRule(scan('rnc-lifecycle-dot'), 'SUSPICIOUS_LIFECYCLE_SCRIPT').length, 0);
});

test('SUSPICIOUS_LIFECYCLE_SCRIPT: node preinstall.js, workflow scripts and curl|sh || true are flagged', () => {
  assert.deepEqual(lines(scan('rnc-lifecycle-bad'), 'SUSPICIOUS_LIFECYCLE_SCRIPT'), [4, 5, 6]);
});

test('SUSPICIOUS_LIFECYCLE_SCRIPT: || true after an unknown command is still flagged', () => {
  assert.deepEqual(lines(scan('rnc-lifecycle-unknown'), 'SUSPICIOUS_LIFECYCLE_SCRIPT'), [4]);
});

test('examples/supply-chain-test is still detected', () => {
  const r = scan(resolve(repoRoot, 'examples/supply-chain-test'));
  assert.deepEqual(lines(r, 'SUSPICIOUS_LIFECYCLE_SCRIPT'), [6, 7]);
  assert.equal(byRule(r, 'OBFUSCATED_EVAL_EXECUTION').length, 1);
});

test('NPM_VULNERABLE_DEPENDENCY: patched node-fetch 2.x, "latest" and open ranges are not flagged', () => {
  assert.equal(byRule(scan('rnc-npm-neg'), 'NPM_VULNERABLE_DEPENDENCY').length, 0);
});

test('NPM_VULNERABLE_DEPENDENCY: vulnerable pins are flagged, a caret range that may resolve to the fix is low confidence', () => {
  const found = byRule(scan('rnc-npm-pos'), 'NPM_VULNERABLE_DEPENDENCY');
  const by = Object.fromEntries(found.map(f => [f.line, f]));
  assert.equal(by[4].severity, 'HIGH'); // lodash 4.17.15
  assert.equal(by[4].confidence, undefined);
  assert.equal(by[5].severity, 'HIGH'); // node-fetch 3.0.0 (< 3.1.1)
  assert.equal(by[6].confidence, 'low'); // minimist ^1.2.0 can install 1.2.8
});

test('DEPRECATED_NPM_PACKAGE: devDependencies are LOW, pinned-safe colors/faker are exempt', () => {
  const neg = byRule(scan('rnc-npm-neg'), 'DEPRECATED_NPM_PACKAGE');
  assert.deepEqual(neg.map(f => [f.line, f.severity]), [[10, 'LOW']]); // request in devDependencies; faker 5.5.3 exempt
  const pos = byRule(scan('rnc-npm-pos'), 'DEPRECATED_NPM_PACKAGE');
  assert.deepEqual(pos.map(f => [f.line, f.severity]).sort(), [[7, 'MEDIUM'], [8, 'MEDIUM']]);
});

// ---- webview
test('WEBVIEW_ORIGIN_WHITELIST_WILDCARD: only a bare "*" is flagged, graded by source', () => {
  const r = scan('rnc-wv-wildcard');
  const found = Object.fromEntries(byRule(r, 'WEBVIEW_ORIGIN_WHITELIST_WILDCARD').map(f => [f.line, f]));
  assert.deepEqual(Object.keys(found).map(Number), [5, 9, 13]);
  assert.equal(found[5].severity, 'HIGH'); // non-literal uri
  assert.equal(found[9].severity, 'MEDIUM'); // literal https uri
  assert.equal(found[13].severity, 'LOW'); // static html: the documented reason to use '*'
  assert.equal(found[13].confidence, 'low');
});

test('WEBVIEW_ORIGIN_WHITELIST_WILDCARD: not reported where INSECURE_WEBVIEW already fires', () => {
  const r = scan('rnc-wv-wildcard');
  assert.deepEqual(lines(r, 'INSECURE_WEBVIEW'), [17]);
  assert.ok(!lines(r, 'WEBVIEW_ORIGIN_WHITELIST_WILDCARD').includes(17));
});

test('examples/vulnerable-app WebView gets no extra wildcard finding', () => {
  const r = scan(resolve(repoRoot, 'examples/vulnerable-app'));
  assert.equal(byRule(r, 'WEBVIEW_ORIGIN_WHITELIST_WILDCARD').length, 0);
  assert.equal(byRule(r, 'INSECURE_WEBVIEW').length, 1);
  assert.equal(byRule(r, 'WEBVIEW_UNVALIDATED_NAVIGATION').length, 1);
  // two remote WebViews since the published example added the webContentsDebuggingEnabled one
  assert.equal(byRule(r, 'MISSING_SECURITY_HEADERS').length, 2);
});

test('WebView rules: app-bundled html/require sources and checked handlers are not flagged', () => {
  const r = scan('rnc-wv-fp');
  for (const id of [
    'WEBVIEW_JAVASCRIPT_INJECTION',
    'WEBVIEW_UNVALIDATED_NAVIGATION',
    'WEBVIEW_DOM_STORAGE_ENABLED',
    'WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK',
  ]) {
    assert.deepEqual(lines(r, id), [], id);
  }
  // require() page, "description" in html, and a WebView without source: no header findings;
  // only the remote https uri on line 24 keeps its (existing) LOW finding.
  assert.deepEqual(lines(r, 'MISSING_SECURITY_HEADERS'), [24]);
});

test('WEBVIEW_FILE_ACCESS: allowFileAccess on bundled html is MEDIUM, the FromFileURLs flags stay HIGH', () => {
  const fp = byRule(scan('rnc-wv-fp'), 'WEBVIEW_FILE_ACCESS');
  assert.deepEqual(fp.map(f => [f.line, f.severity, f.confidence]), [[36, 'MEDIUM', 'medium']]);
  const pos = byRule(scan('rnc-wv-pos'), 'WEBVIEW_FILE_ACCESS');
  assert.deepEqual(pos.map(f => [f.line, f.severity]).sort((a, b) => a[0] - b[0]), [[22, 'HIGH'], [26, 'HIGH']]);
});

test('WEBVIEW_DOM_STORAGE_ENABLED: still reported for a remote page, skipped for bundled html', () => {
  assert.deepEqual(lines(scan('rnc-wv-pos'), 'WEBVIEW_DOM_STORAGE_ENABLED'), [38]);
  assert.deepEqual(lines(scan('rnc-wv-fp'), 'WEBVIEW_DOM_STORAGE_ENABLED'), []);
});

test('WEBVIEW_JAVASCRIPT_INJECTION: { uri: variable } and bare javaScriptEnabled are covered, fixed host is MEDIUM', () => {
  const found = byRule(scan('rnc-wv-pos'), 'WEBVIEW_JAVASCRIPT_INJECTION');
  assert.deepEqual(found.map(f => [f.line, f.severity]).sort((a, b) => a[0] - b[0]), [[6, 'HIGH'], [10, 'MEDIUM']]);
});

test('WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK: unchecked handler HIGH, handler defined elsewhere low confidence', () => {
  const found = byRule(scan('rnc-wv-pos'), 'WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK');
  const by = Object.fromEntries(found.map(f => [f.line, f]));
  assert.equal(by[14].confidence, 'low');
  assert.equal(by[18].confidence, undefined);
});

test('WEBVIEW_MIXED_CONTENT: mixedContentMode={"always"} expression form is found; aliased WebView import is scanned', () => {
  const r = scan('rnc-wv-pos');
  assert.deepEqual(lines(r, 'WEBVIEW_MIXED_CONTENT'), [30]);
  assert.ok(lines(r, 'WEBVIEW_FILE_ACCESS').includes(26)); // <RNWebView allowFileAccess>
});

test('MISSING_SECURITY_HEADERS: only a real <script> in html counts', () => {
  assert.ok(lines(scan('rnc-wv-pos'), 'MISSING_SECURITY_HEADERS').includes(34));
});

// ---- deep links
test('INSECURE_DEEPLINK_HANDLER: host check or named validator in the handler passes', () => {
  assert.deepEqual(lines(scan('rnc-deeplink'), 'INSECURE_DEEPLINK_HANDLER', 'guarded.ts'), []);
});

test('INSECURE_DEEPLINK_HANDLER: a comment or "Checkout" in a name is not validation', () => {
  assert.deepEqual(lines(scan('rnc-deeplink'), 'INSECURE_DEEPLINK_HANDLER', 'bare.ts'), [5, 11]);
});

test('INSECURE_DEEPLINK_HANDLER: an imported handler is reported with low confidence', () => {
  const [f] = byRule(scan('rnc-deeplink'), 'INSECURE_DEEPLINK_HANDLER').filter(x => x.filePath.endsWith('external.ts'));
  assert.equal(f.confidence, 'low');
});

test('INSECURE_DEEPLINK_HANDLER: Linking.getInitialURL().then(handler) is covered', () => {
  assert.deepEqual(lines(scan('rnc-deeplink'), 'INSECURE_DEEPLINK_HANDLER', 'external.ts'), [4, 7]);
});

test('examples/vulnerable-app deep link finding stays', () => {
  const r = scan(resolve(repoRoot, 'examples/vulnerable-app'));
  assert.deepEqual(lines(r, 'INSECURE_DEEPLINK_HANDLER'), [67]); // moved from 63 by the imports the published example added
});

// ---- dangerouslySetInnerHTML
test('UNSAFE_DANGEROUSLY_SET_INNER_HTML: sanitizer call or literal is LOW/medium, raw value stays HIGH', () => {
  const r = scan('rnc-html');
  const safe = byRule(r, 'UNSAFE_DANGEROUSLY_SET_INNER_HTML').filter(f => f.filePath.endsWith('clean.tsx'));
  assert.equal(safe.length, 3);
  for (const f of safe) {
    assert.equal(f.severity, 'LOW');
    assert.equal(f.confidence, 'medium');
  }
  const [bad] = byRule(r, 'UNSAFE_DANGEROUSLY_SET_INNER_HTML').filter(f => f.filePath.endsWith('raw.tsx'));
  assert.equal(bad.severity, 'HIGH');
});

// ---- Android
test('Android manifest: launcher, permission-protected, exported=false and commented-out components are not flagged', () => {
  const r = scan('rnc-android-neg');
  assert.equal(byRule(r, 'ANDROID_EXPORTED_COMPONENT').length, 0);
  assert.equal(byRule(r, 'ANDROID_UNPROTECTED_RECEIVER').length, 0);
});

test('ANDROID_BACKUP_ALLOWED: fullBackupContent/dataExtractionRules lowers it to LOW', () => {
  const [f] = byRule(scan('rnc-android-neg'), 'ANDROID_BACKUP_ALLOWED');
  assert.equal(f.severity, 'LOW');
  assert.equal(f.line, 10);
});

test('EXCESSIVE_PERMISSIONS: a permission removed with tools:node="remove" is not listed', () => {
  const [f] = byRule(scan('rnc-android-neg'), 'EXCESSIVE_PERMISSIONS');
  assert.match(f.description, /CAMERA/);
  assert.doesNotMatch(f.description, /READ_CONTACTS/);
});

test('Android manifest: exported share activity and receiver are still flagged, with lines', () => {
  const r = scan('rnc-android-pos');
  // not the self-closing exported=false service on 13; the receiver on 28 is reported once, by the more specific rule
  assert.deepEqual(lines(r, 'ANDROID_EXPORTED_COMPONENT'), [21]);
  assert.deepEqual(lines(r, 'ANDROID_UNPROTECTED_RECEIVER'), [28]);
  assert.deepEqual(lines(r, 'ANDROID_CLEARTEXT_ENABLED'), [9]);
  const [backup] = byRule(r, 'ANDROID_BACKUP_ALLOWED');
  assert.equal(backup.severity, 'MEDIUM');
  assert.equal(backup.line, 10);
});

// ---- iOS
test('iOS ATS: NSAllowsLocalNetworking only, localhost and plain subdomain entries are not flagged', () => {
  const r = scan('rnc-ios-neg');
  assert.equal(byRule(r, 'IOS_ATS_DISABLED').length, 0);
  assert.equal(byRule(r, 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE').length, 0);
  assert.equal(byRule(r, 'IOS_USAGE_DESCRIPTIONS_MISSING').length, 0); // "photos"/"Contacts" in a <string> value
});

test('IOS_ATS_DISABLED: ignored-on-iOS-10+ combination is LOW, plain arbitrary loads stays HIGH with a line', () => {
  const [web] = byRule(scan('rnc-ios-web'), 'IOS_ATS_DISABLED');
  assert.equal(web.severity, 'LOW');
  assert.equal(web.line, 7);
  const [pos] = byRule(scan('rnc-ios-pos'), 'IOS_ATS_DISABLED');
  assert.equal(pos.severity, 'HIGH');
  assert.equal(pos.line, 7);
});

test('IOS_ATS_EXCEPTION_TOO_PERMISSIVE: insecure HTTP + subdomains and TLS 1.0 are flagged per domain', () => {
  assert.deepEqual(lines(scan('rnc-ios-pos'), 'IOS_ATS_EXCEPTION_TOO_PERMISSIVE'), [16, 23]);
});

test('IOS_USAGE_DESCRIPTIONS_MISSING: placeholder text and background location are flagged, push modes are not', () => {
  const r = scan('rnc-ios-pos');
  const found = byRule(r, 'IOS_USAGE_DESCRIPTIONS_MISSING');
  assert.equal(found.length, 2);
  assert.ok(found.some(f => f.line === 34 && /placeholder/.test(f.description)));
  assert.ok(found.some(f => /Location \(Always\)/.test(f.description)));
});

test('examples/vulnerable-app manifests keep their findings, now with lines', () => {
  const r = scan(resolve(repoRoot, 'examples/vulnerable-app'));
  assert.deepEqual(lines(r, 'ANDROID_CLEARTEXT_ENABLED'), [12]);
  assert.deepEqual(lines(r, 'IOS_ATS_DISABLED'), [23]);
  assert.equal(byRule(r, 'ANDROID_BACKUP_ALLOWED').length, 1);
});

// ---- config
test('EXPO_INSECURE_PERMISSIONS: only app.json / app.config.json, with a line', () => {
  const found = byRule(scan('rnc-config'), 'EXPO_INSECURE_PERMISSIONS');
  assert.equal(found.length, 1);
  assert.ok(found[0].filePath.endsWith('/app.json'));
  assert.equal(found[0].line, 5);
});

test('WEBVIEW_ORIGIN_WHITELIST_WILDCARD: platform-conditional bundled source is LOW, dynamic uri stays HIGH', () => {
  const found = byRule(scan('rnc-wv-conditional-static'), 'WEBVIEW_ORIGIN_WHITELIST_WILDCARD');
  const bySeverity = Object.fromEntries(found.map(f => [f.line, f.severity]));
  assert.deepEqual(bySeverity, { 11: 'LOW', 15: 'HIGH' });
});
