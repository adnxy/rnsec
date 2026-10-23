import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, byRule } from './helpers.mjs';

const lines = (r, rule) => byRule(r, rule).map(f => f.line);
const descs = (r, rule) => byRule(r, rule).map(f => f.description);

test('INSECURE_HTTP_URL: local/private hosts are ignored, public http (incl. look-alikes) is reported', () => {
  const r = scan('net-http-urls');
  // lines 6-17 of api.js are localhost, 10.0.2.2, 127.0.0.1, [::1], *.local, 192.168, 172.20, templates, 10.x, baseURL
  assert.deepEqual(lines(r, 'INSECURE_HTTP_URL'), [19, 20, 21, 22, 23, 24, 25]);
  const d = descs(r, 'INSECURE_HTTP_URL').join('\n');
  assert.match(d, /110\.0\.0\.1/, '110.0.0.1 is public, not 10.0.x');
  assert.match(d, /notlocalhost\.example\.com/);
  assert.match(d, /172\.32\.0\.1/);
});

test('DEBUG_ENDPOINTS_EXPOSED: anchored segments, local hosts skipped, no regex lastIndex leak', () => {
  const r = scan('net-debug-endpoints');
  // five consecutive positives (a leaking /g regex would drop some); safe[] is lines 1-7
  assert.deepEqual(lines(r, 'DEBUG_ENDPOINTS_EXPOSED'), [9, 10, 11, 12, 13]);
});

test('TEST_CREDENTIALS_IN_CODE: whole-word names, literal values only, lib/modules no longer skipped', () => {
  const r = scan('net-test-credentials');
  const hits = byRule(r, 'TEST_CREDENTIALS_IN_CODE').map(f => `${f.filePath.split('net-test-credentials/')[1]}:${f.line}`);
  assert.ok(!hits.some(h => h.startsWith('creds.js')), `bypass/passport/empty/dynamic must not fire: ${hits}`);
  assert.deepEqual(
    hits.sort(),
    ['seed.js:1', 'seed.js:2', 'seed.js:2', 'seed.js:4', 'seed.js:5', 'src/lib/seed.js:1', 'src/modules/seed.js:1'].sort(),
  );
});

test('SENSITIVE_LOGGING: values yes, keywords inside plain strings no', () => {
  const r = scan('net-sensitive-logging');
  // lines 2-9, 15 are keyword-only strings, safe names, redacted literals or non-sensitive values
  assert.deepEqual(lines(r, 'SENSITIVE_LOGGING'), [10, 11, 12, 13, 14, 16, 17, 18]);
  const byLine = Object.fromEntries(byRule(r, 'SENSITIVE_LOGGING').map(f => [f.line, f]));
  assert.equal(byLine[10].confidence, undefined, "console.log('token:', token) is a high confidence hit");
  assert.equal(byLine[16].confidence, 'medium', 'label-only hit is medium confidence');
});

test('WEAK_HASH_ALGORITHM: security context stays HIGH, checksums/cache keys drop to LOW/low', () => {
  const r = scan('net-weak-hash');
  const by = Object.fromEntries(byRule(r, 'WEAK_HASH_ALGORITHM').map(f => [f.line, f]));
  assert.deepEqual(Object.keys(by).map(Number), [5, 8, 11, 14, 17, 21, 27, 30]);
  for (const l of [5, 8, 11, 30]) {
    assert.equal(by[l].severity, 'LOW');
    assert.equal(by[l].confidence, 'low');
  }
  for (const l of [14, 17, 21, 27]) { // 27 is expo-crypto CryptoDigestAlgorithm.SHA1 fed with `password`
    assert.equal(by[l].severity, 'HIGH', `line ${l}`);
    assert.equal(by[l].confidence, undefined);
  }
});

test('INSECURE_RANDOM: only values flowing into token/nonce/otp/... names', () => {
  const r = scan('net-insecure-random');
  assert.deepEqual(lines(r, 'INSECURE_RANDOM'), [29, 33, 36, 38, 41, 44, 47, 53, 57]); // 53/57: generateToken accumulator and Array.from generator; retryTokenFetch/refreshTokenDelay/generateAnimationFrame stay clean
  const date = byRule(r, 'INSECURE_RANDOM').find(f => f.line === 47);
  assert.equal(date.severity, 'MEDIUM');
  assert.equal(date.confidence, 'medium');
});

test('NO_REQUEST_TIMEOUT: LOW/medium, and not reported when a timeout mechanism is present', () => {
  const r = scan('net-timeout');
  assert.deepEqual(lines(r, 'NO_REQUEST_TIMEOUT'), [4, 21, 24]);
  for (const f of byRule(r, 'NO_REQUEST_TIMEOUT')) {
    assert.equal(f.severity, 'LOW');
    assert.equal(f.confidence, 'medium');
  }
  assert.deepEqual(lines(scan('net-timeout-axios-instance'), 'NO_REQUEST_TIMEOUT'), [], 'axios.defaults.timeout covers calls');
});

test('WEAK_TLS_CONFIGURATION: string literals only; disabling flags and negated cipher lists are fine', () => {
  const r = scan('net-tls');
  assert.deepEqual(lines(r, 'WEAK_TLS_CONFIGURATION'), [12, 13, 14, 15]);
});

test('JWT / OAuth / cert pinning / biometric false-positive fixes', () => {
  const r = scan('net-misc-auth');
  assert.deepEqual(lines(r, 'JWT_NO_EXPIRY_CHECK'), [11], 'push/device/csrf tokens are not JWTs');
  assert.equal(byRule(r, 'JWT_NO_EXPIRY_CHECK')[0].confidence, 'medium');
  assert.deepEqual(lines(r, 'OAUTH_TOKEN_IN_URL'), [15, 18], 'prose mentioning "http ... ?token=" is not a URL');
  assert.deepEqual(lines(r, 'CERT_PINNING_DISABLED'), [22, 23], 'trustAllCerts:true and rejectUnauthorized:false only');
  assert.deepEqual(lines(r, 'IMPROPER_BIOMETRIC_FALLBACK'), [], 'spin/shipping/mapping and comments are not credentials');
  assert.deepEqual(lines(scan('net-jwt-expired-message'), 'JWT_NO_EXPIRY_CHECK'), [3], 'the word "expired" in a string is not an expiry check');
  assert.deepEqual(lines(scan('net-misc-auth-jwt'), 'JWT_NO_EXPIRY_CHECK'), [], 'jwt-decode in file');
  assert.deepEqual(lines(scan('net-biometric-literal'), 'IMPROPER_BIOMETRIC_FALLBACK'), [2], 'real literal PIN still found');
});

test('WEAK_CIPHER_OR_MODE: ECB/DES/3DES/RC4 and constant IVs found, AES-CBC/GCM and comments are not', () => {
  const r = scan('net-weak-cipher');
  const hits = byRule(r, 'WEAK_CIPHER_OR_MODE');
  // safe code is lines 1-16
  assert.deepEqual(hits.map(f => f.line), [18, 19, 20, 21, 23, 26, 28, 30, 33, 35, 37]);
  const ivs = hits.filter(f => f.severity === 'MEDIUM');
  assert.deepEqual(ivs.map(f => f.line), [30, 33, 35], 'DEFAULT_IV counts, `div` does not');
  for (const f of hits) assert.equal(f.confidence, f.severity === 'HIGH' ? 'high' : 'medium');
});

test('SENSITIVE_DATA_IN_ERROR_MESSAGES: AST based, alerts with error details only', () => {
  const r = scan('net-error-messages');
  // safe: console.log(error.message), generic alerts, a comment mentioning Alert.alert, stderr.message
  assert.deepEqual(lines(r, 'SENSITIVE_DATA_IN_ERROR_MESSAGES'), [25, 32, 37]);
  const by = Object.fromEntries(byRule(r, 'SENSITIVE_DATA_IN_ERROR_MESSAGES').map(f => [f.line, f]));
  assert.equal(by[25].confidence, undefined, 'Alert.alert(e.message) in catch(e) is a real exposure');
  assert.equal(by[37].confidence, 'low', 'console.error(error) only reaches device logs');
});

test('TEXT_INPUT_NO_SECURE matches whole words, supports autoComplete, ignores prop spreads', () => {
  const r = scan('auth-textinput');
  const lines = byRule(r, 'TEXT_INPUT_NO_SECURE').map(f => f.line);
  assert.deepEqual(lines, [9, 18], `passport/passwordless/spread must not fire, got ${lines}`);
});
