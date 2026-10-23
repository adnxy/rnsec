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
