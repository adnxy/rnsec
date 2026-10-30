import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, byRule } from './helpers.mjs';

const at = (r, rule) => byRule(r, rule).map(f => `${f.filePath.split('/').pop()}:${f.line}:${f.severity}:${f.confidence ?? 'high'}`);

test('JWT_INSECURE_SIGNING: hardcoded secrets and alg none are HIGH', () => {
  const r = scan('rx-jwt-pos');
  assert.deepEqual(at(r, 'JWT_INSECURE_SIGNING'), [4, 5, 6, 7, 8].map(l => `auth.js:${l}:HIGH:high`));
});

test('JWT_INSECURE_SIGNING: env/identifier/empty/placeholder secrets, RS256 and non-jwt files are clean', () => {
  assert.deepEqual(byRule(scan('rx-jwt-neg'), 'JWT_INSECURE_SIGNING'), []);
});

test('HARDCODED_BASIC_AUTH_CREDENTIALS: URL userinfo and base64 encoders; localhost is low confidence', () => {
  const r = scan('rx-basic-pos');
  assert.deepEqual(at(r, 'HARDCODED_BASIC_AUTH_CREDENTIALS').sort(), [
    'creds.js:1:HIGH:medium',
    'creds.js:2:HIGH:medium',
    'creds.js:3:HIGH:medium',
    'creds.js:4:HIGH:medium',
    'creds.js:6:HIGH:low',
  ]);
  // `Basic <base64>` literals are API_KEY_EXPOSED's job, not duplicated here
  assert.ok(byRule(r, 'API_KEY_EXPOSED').some(f => f.line === 5));
});

test('HARDCODED_BASIC_AUTH_CREDENTIALS: placeholders, interpolation, route params and non-credentials are clean', () => {
  assert.deepEqual(byRule(scan('rx-basic-neg'), 'HARDCODED_BASIC_AUTH_CREDENTIALS'), []);
});

test('INSECURE_KEYCHAIN_USAGE: react-native-keychain ALWAYS accessibility is MEDIUM; SecureStore is not its business', () => {
  const r = scan('rx-keychain-pos');
  assert.deepEqual(at(r, 'INSECURE_KEYCHAIN_USAGE'), [6, 9].map(l => `store.js:${l}:MEDIUM:high`));
  // lines 7-8 are expo-secure-store (aliased and named-import forms): EXPO_SECURE_STORE_WEAK_OPTIONS owns them
  assert.deepEqual(at(r, 'EXPO_SECURE_STORE_WEAK_OPTIONS'), [7, 8].map(l => `store.js:${l}:MEDIUM:high`));
});

test('INSECURE_KEYCHAIN_USAGE: safe accessibility values and lookalike objects are clean', () => {
  const r = scan('rx-keychain-neg');
  assert.deepEqual(byRule(r, 'INSECURE_KEYCHAIN_USAGE'), []);
  assert.deepEqual(byRule(r, 'EXPO_SECURE_STORE_WEAK_OPTIONS'), []);
});

test('EXPO_SECURE_STORE_WEAK_OPTIONS: ALWAYS[_THIS_DEVICE_ONLY] regardless of key, HIGH for credential-like keys', () => {
  assert.deepEqual(at(scan('rx-securestore-pos'), 'EXPO_SECURE_STORE_WEAK_OPTIONS'), [
    'store.ts:4:HIGH:high', // auth_token
    'store.ts:5:MEDIUM:high', // theme
    'store.ts:6:MEDIUM:high', // userAgent is not credential-like
    'store.ts:9:MEDIUM:high', // shared options object, key unknown
  ]);
});

test('EXPO_SECURE_STORE_WEAK_OPTIONS: AFTER_FIRST_UNLOCK is Apple\'s recommended replacement and is not reported', () => {
  assert.deepEqual(byRule(scan('rx-securestore-neg'), 'EXPO_SECURE_STORE_WEAK_OPTIONS'), []);
});

test('INSECURE_WEBSOCKET: sole owner of cleartext ws://, reported once per public URL', () => {
  const r = scan('rx-ws-pos');
  assert.deepEqual(at(r, 'INSECURE_WEBSOCKET'), [2, 3, 4].map(l => `sock.js:${l}:MEDIUM:high`));
  assert.deepEqual(byRule(r, 'INSECURE_HTTP_URL'), [], 'INSECURE_HTTP_URL no longer reports ws://');
});

test('INSECURE_WEBSOCKET: wss, loopback, 10.0.2.2, LAN and dynamic hosts are clean', () => {
  const r = scan('rx-ws-neg');
  assert.deepEqual(byRule(r, 'INSECURE_WEBSOCKET'), []);
  assert.deepEqual(byRule(r, 'HARDCODED_IP_ADDRESS'), []);
  assert.deepEqual(byRule(r, 'INSECURE_HTTP_URL'), []);
});

test('HARDCODED_IP_ADDRESS: public IPs are reported (src/config is scanned); once per line behind the URL rules', () => {
  const r = scan('rx-ip-pos');
  // api.ts:2 is an object property, :3 a bare 'host' key; ws:// and http:// public IPs belong to the URL rules
  assert.deepEqual(at(r, 'HARDCODED_IP_ADDRESS'), ['api.ts:2:MEDIUM:high', 'api.ts:3:MEDIUM:high']);
  assert.deepEqual(at(r, 'INSECURE_WEBSOCKET'), ['api.ts:5:MEDIUM:high']);
  assert.deepEqual(at(r, 'INSECURE_HTTP_URL'), ['api.ts:6:MEDIUM:high']);
});

test('HARDCODED_IP_ADDRESS: loopback, private, link-local, emulator, 0.0.0.0, documentation and invalid IPs are clean', () => {
  assert.deepEqual(byRule(scan('rx-ip-neg'), 'HARDCODED_IP_ADDRESS'), []);
});

test('CERT_PINNING_DISABLED: react-native-ssl-pinning disableAllSecurity: true', () => {
  assert.deepEqual(at(scan('rx-pinning-pos'), 'CERT_PINNING_DISABLED'), ['net.js:2:MEDIUM:high']);
  assert.deepEqual(byRule(scan('rx-pinning-neg'), 'CERT_PINNING_DISABLED'), []);
});

test('INSECURE_LINKING_OPEN: constants, fixed-host templates and i18n keys are clean; route, server and deep-link data fire', () => {
  const r = scan('rnc-linking-origin');
  const hits = byRule(r, 'INSECURE_LINKING_OPEN').map(f => `${f.line}:${f.confidence}`);
  // 31 route params (medium), 37 server response (medium), 41 dynamic scheme/host and 45 bare parameter (low),
  // 50 deep-link event (medium); 59 is guarded by startsWith + canOpenURL; 68 is hook state set from props (low),
  // not a constant just because useState('') was seeded with one; 75 is stored data read through an imported model
  assert.deepEqual(hits, ['31:medium', '37:medium', '41:low', '45:low', '50:medium', '68:low', '75:medium']);
});

test('CUSTOM_CRYPTO_IMPLEMENTATION: whole name tokens, primitives in the body, weak-digest key derivation kept', () => {
  const r = scan('crypto-custom');
  const hits = byRule(r, 'CUSTOM_CRYPTO_IMPLEMENTATION');
  // XOR loop (6), rotate (11), S-box table (13), MD5-derived key and IV (14), call to a local xorEncrypt (20)
  assert.deepEqual(hits.map(f => f.line), [6, 11, 13, 14, 20]);
  for (const f of hits) {
    assert.equal(f.severity, 'MEDIUM');
    assert.equal(f.confidence, 'low');
  }
  assert.match(hits.find(f => f.line === 14).description, /MD5/);
});
