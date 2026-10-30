import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, byRule } from './helpers.mjs';

const r = () => scan('fp-misc');

test('JSON.parse is not "insecure deserialization", but eval on dynamic input is still reported', () => {
  const result = r();
  assert.ok(!byRule(result, 'INSECURE_DESERIALIZATION').some(f => f.line === 5), 'JSON.parse(response) must not be reported');
  // reported once, by EVAL_USAGE (the engine keeps one finding per eval line)
  assert.deepEqual(byRule(result, 'EVAL_USAGE').map(f => f.line), [9]);
});

test('biometric use alone is not a finding (device passcode fallback is the platform default)', () => {
  assert.equal(byRule(r(), 'IMPROPER_BIOMETRIC_FALLBACK').length, 0);
});

test('plain console.error(error) is routine logging, not a finding', () => {
  assert.equal(byRule(r(), 'SENSITIVE_DATA_IN_ERROR_MESSAGES').length, 0);
});

test('JS bundled under android/app/src/*/assets is not first-party source', () => {
  const files = new Set(r().findings.map(f => f.filePath));
  assert.ok(![...files].some(p => p.includes('/assets/')), `assets must be skipped, got ${[...files]}`);
});
