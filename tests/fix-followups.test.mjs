import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, byRule, untrackedProject, fakeSecret } from './helpers.mjs';

const plist = body => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
${body}
</dict>
</plist>
`;

const urlTypes = `  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>myapp</string>
      </array>
    </dict>
    <dict>
      <key>CFBundleURLName</key>
      <string>com.example.auth</string>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>myapp-auth</string>
      </array>
    </dict>
  </array>`;

test('IOS_CUSTOM_URL_SCHEME_UNPROTECTED: one LOW/low-confidence finding per Info.plist naming every scheme', () => {
  const dir = untrackedProject({ 'ios/App/Info.plist': plist(`  <key>CFBundleName</key>\n  <string>App</string>\n${urlTypes}`) });
  const f = byRule(scan(dir), 'IOS_CUSTOM_URL_SCHEME_UNPROTECTED');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'LOW');
  assert.equal(f[0].confidence, 'low');
  assert.equal(f[0].line, 7);
  assert.match(f[0].description, /myapp\b.*myapp-auth|myapp-auth.*myapp\b/);
});

test('IOS_CUSTOM_URL_SCHEME_UNPROTECTED: Info.plist without URL types is quiet', () => {
  const dir = untrackedProject({ 'ios/App/Info.plist': plist('  <key>CFBundleName</key>\n  <string>App</string>') });
  assert.equal(byRule(scan(dir), 'IOS_CUSTOM_URL_SCHEME_UNPROTECTED').length, 0);
});

const entitlements = domains =>
  plist(`  <key>com.apple.developer.associated-domains</key>\n  <array>\n${domains.map(d => `    <string>${d}</string>`).join('\n')}\n  </array>`);

test('IOS_UNIVERSAL_LINKS_MISCONFIGURED: wildcard domain in .entitlements is MEDIUM with a line', () => {
  const dir = untrackedProject({ 'ios/App/App.entitlements': entitlements(['applinks:*.example.com']) });
  const f = byRule(scan(dir), 'IOS_UNIVERSAL_LINKS_MISCONFIGURED');
  assert.deepEqual(f.map(x => [x.line, x.severity]), [[5, 'MEDIUM']]);
  assert.ok(f[0].filePath.endsWith('App.entitlements'));
});

test('IOS_UNIVERSAL_LINKS_MISCONFIGURED: exact domains and ?mode= suffixes are not flagged; dotless host is LOW', () => {
  const ok = untrackedProject({
    'ios/App/App.entitlements': entitlements(['applinks:example.com', 'applinks:example.com?mode=developer', 'applinks:example.com?mode=managed', 'webcredentials:example.com']),
  });
  assert.equal(byRule(scan(ok), 'IOS_UNIVERSAL_LINKS_MISCONFIGURED').length, 0);
  const bad = untrackedProject({ 'ios/App/App.entitlements': entitlements(['applinks:localhost?mode=developer']) });
  assert.deepEqual(byRule(scan(bad), 'IOS_UNIVERSAL_LINKS_MISCONFIGURED').map(x => x.severity), ['LOW']);
});

test('REDUX_DEVTOOLS_ENABLED: TypeScript wrappers around window are unwrapped', () => {
  const dir = untrackedProject({
    'package.json': '{ "name": "app", "dependencies": { "react-native": "0.74.0" } }',
    'src/store.ts': [
      "export const a = (window as any).__REDUX_DEVTOOLS_EXTENSION__;",
      "export const b = (<any>window).__REDUX_DEVTOOLS_EXTENSION__;",
      "export const c = window!.__REDUX_DEVTOOLS_EXTENSION__;",
      "export const d = ((window)).__REDUX_DEVTOOLS_EXTENSION__;",
      "",
    ].join('\n'),
  });
  assert.deepEqual(byRule(scan(dir), 'REDUX_DEVTOOLS_ENABLED').map(f => f.line).sort(), [1, 2, 3, 4]);
});

test('HARDCODED_ENCRYPTION_KEY wins over HARDCODED_SECRETS on the same line', () => {
  const dir = untrackedProject({
    'src/crypto.ts': `const ENCRYPTION_KEY = '9f86d081884c7d659a2feaa0c55ad015';\nexport const x = ENCRYPTION_KEY;\n`,
  });
  const r = scan(dir);
  const onLine = r.findings.filter(f => f.line === 1).map(f => f.ruleId);
  assert.ok(onLine.includes('HARDCODED_ENCRYPTION_KEY'), `got ${onLine}`);
  assert.ok(!onLine.includes('HARDCODED_SECRETS'), `got ${onLine}`);
});

test('fixture markers are materialized into real-looking keys at scan time', () => {
  assert.match(fakeSecret('stripe_live'), /^sk_live_[A-Za-z0-9]{20,}$/);
  assert.match(fakeSecret('github_pat'), /^ghp_[A-Za-z0-9]{36}$/);
  assert.match(fakeSecret('aws_access_key'), /^AKIA[0-9A-Z]{16}$/);
  const r = scan('secrets-provider-high');
  assert.ok(byRule(r, 'API_KEY_EXPOSED').every(f => !f.filePath.startsWith(process.cwd() + '/tests')), 'scanned from a temp copy');
  assert.throws(() => fakeSecret('nope'));
});
