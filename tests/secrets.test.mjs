import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { scan, ids, byRule } from './helpers.mjs';

const linesOf = (r, ruleId) => byRule(r, ruleId).map(f => f.line);
const secretLines = r => [...new Set([...linesOf(r, 'API_KEY_EXPOSED'), ...linesOf(r, 'HARDCODED_SECRETS')])].sort((a, b) => a - b);

// --- API_KEY_EXPOSED -------------------------------------------------------

test('public-by-design identifiers are one LOW/medium finding each', () => {
  const r = scan('secrets-public-ids');
  const f = byRule(r, 'API_KEY_EXPOSED');
  assert.deepEqual(f.map(x => x.line), [2, 5, 6, 7, 10], "Firebase, Stripe pk, Google OAuth, Sentry DSN and a wrapped Firebase key ending in -, one finding per secret");
  for (const x of f) {
    assert.equal(x.severity, 'LOW');
    assert.equal(x.confidence, 'medium');
  }
  assert.match(f[0].suggestion, /[Rr]estrict/);
  assert.equal(byRule(r, 'HARDCODED_SECRETS').length, 0, 'no HARDCODED_SECRETS (not even HIGH on the wrapped declaration line)');
});

test('a Gemini key (same AIza format) stays HIGH', () => {
  const f = byRule(scan('secrets-gemini'), 'API_KEY_EXPOSED');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'HIGH');
});

test('provider secrets stay HIGH, one finding each (sk_live, AWS, GitHub, private key)', () => {
  const f = byRule(scan('secrets-provider-high'), 'API_KEY_EXPOSED');
  assert.deepEqual(f.map(x => x.line), [1, 2, 3, 4]);
  assert.ok(f.every(x => x.severity === 'HIGH'));
});

test('placeholders, sample tokens, bare header constants and context-free loose matches are not reported', () => {
  const r = scan('secrets-placeholders');
  assert.deepEqual(byRule(r, 'API_KEY_EXPOSED').map(f => `${f.line}:${f.description}`), []);
});

test('a real key is still reported when the word "example" is nearby', () => {
  const r = scan('secrets-near-example');
  assert.deepEqual(linesOf(r, 'API_KEY_EXPOSED'), [2]);
});

test('loose patterns fire with keyword context and entropy; anon JWT is LOW', () => {
  const r = scan('secrets-loose-positive');
  const f = byRule(r, 'API_KEY_EXPOSED');
  assert.deepEqual(f.map(x => x.line), [1, 2, 3, 4, 5, 6, 7, 8]);
  const byLine = Object.fromEntries(f.map(x => [x.line, x]));
  assert.equal(byLine[3].confidence, 'medium');
  assert.equal(byLine[7].confidence, 'medium');
  assert.equal(byLine[8].severity, 'LOW');
});

test('HARDCODED_SECRETS: labels, storage-key constants, env lookups and form fields are not secrets', () => {
  const r = scan('secrets-hardcoded-neg');
  assert.deepEqual(byRule(r, 'HARDCODED_SECRETS').map(f => `${f.line}:${f.description}`), []);
});

test('HARDCODED_SECRETS: real literals are still found (password, client secret, token, private key)', () => {
  const r = scan('secrets-hardcoded-pos');
  assert.deepEqual(secretLines(r), [1, 3, 4, 6, 7]);
  assert.deepEqual(linesOf(r, 'HARDCODED_SECRETS').filter(l => [1, 6, 7].includes(l)), [1, 6, 7]);
});

test('Bearer token inside a comment and a concatenated PEM key are still reported (no comment skipping)', () => {
  const r = scan('secrets-comment-and-pem');
  assert.deepEqual(linesOf(r, 'API_KEY_EXPOSED'), [1, 3]);
});

// --- storage rules ---------------------------------------------------------

test('AsyncStorage: aliased import, derived storage, const keys, wrappers and multiSet are tracked', () => {
  const r = scan('secrets-asyncstorage');
  assert.deepEqual(linesOf(r, 'ASYNCSTORAGE_SENSITIVE_KEY'), [13, 14, 15, 16, 18, 19]);
  assert.deepEqual(linesOf(r, 'ASYNCSTORAGE_PII_DATA'), [17]);
});

test('AsyncStorage: tokenizer_enabled, bypass_count, token_expiry, ip_address, email_verified are not flagged', () => {
  const r = scan('secrets-asyncstorage');
  const flagged = [...byRule(r, 'ASYNCSTORAGE_SENSITIVE_KEY'), ...byRule(r, 'ASYNCSTORAGE_PII_DATA')];
  assert.ok(flagged.every(f => f.line <= 19), 'nothing from the benign() function (line 22+)');
});

test('AsyncStorage: "last" marks metadata only when the key does not end in a credential word', () => {
  const r = scan('secrets-asyncstorage-last');
  // lines 4-16 hold the keys that must be flagged, every key after them must not be
  assert.deepEqual(linesOf(r, 'ASYNCSTORAGE_SENSITIVE_KEY'), [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  assert.deepEqual(linesOf(r, 'ASYNCSTORAGE_PII_DATA'), [], 'lastEmail / last_phone_number stay unflagged');
});

test('clipboard / file / redux-persist: app-private paths, secure storage and non-sensitive copies are quiet', () => {
  const r = scan('secrets-storage-neg');
  assert.deepEqual(ids(r).filter(id => /CLIPBOARD|FILE_STORAGE|REDUX/.test(id)), []);
});

test('clipboard / file / redux-persist: real problems are found through import aliases', () => {
  const r = scan('secrets-storage-pos');
  assert.deepEqual(linesOf(r, 'INSECURE_FILE_STORAGE'), [8, 9]);
  assert.equal(byRule(r, 'INSECURE_FILE_STORAGE')[0].severity, 'HIGH');
  assert.deepEqual(linesOf(r, 'CLIPBOARD_SENSITIVE_DATA'), [10]);
  assert.equal(linesOf(r, 'REDUX_PERSIST_NO_ENCRYPTION').length, 1);
});

// --- ENV_FILE_COMMITTED / API_KEY_EXPOSED on .env ---------------------------

function tempProject(files, { track }) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'rnsec-env-')));
  const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'ignore' });
  git('init', '-q');
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  if (track) git('add', '-A');
  return dir;
}
const rand = (n) => randomBytes(n).toString('base64url').slice(0, n);

test('ENV_FILE_COMMITTED fires for a git-tracked .env with a real secret, on the right line, masked', () => {
  const secret = rand(40);
  const dir = tempProject({
    '.env': `# app config\nAPI_URL=https://api.myshop.dev\nAPP_NAME=shop\nJWT_SECRET=${secret}\nSTRIPE_PUBLIC=\n`,
    'App.tsx': 'export default function App() { return null; }\n',
  }, { track: true });
  try {
    const r = scan(dir);
    const f = byRule(r, 'ENV_FILE_COMMITTED');
    assert.equal(f.length, 1, ids(r).join());
    assert.equal(f[0].line, 4);
    assert.ok(!JSON.stringify(f[0]).includes(secret), 'secret value must be masked');
    assert.match(f[0].description, /JWT_SECRET/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ENV_FILE_COMMITTED stays quiet for an untracked .env', () => {
  const dir = tempProject({
    '.env': `JWT_SECRET=${rand(40)}\n`,
    'App.tsx': 'export default function App() { return null; }\n',
  }, { track: false });
  try {
    const r = scan(dir);
    assert.deepEqual(ids(r).filter(id => id === 'ENV_FILE_COMMITTED' || id === 'API_KEY_EXPOSED'), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ENV_FILE_COMMITTED ignores API_URL, empty values and placeholders', () => {
  const dir = tempProject({
    '.env': 'API_URL=https://api.myshop.dev\nAPI_KEY=\nSECRET_TOKEN=your_token_here\nDEBUG_TOKEN="changeme"\nAPI_ENABLED=true\n',
    'App.tsx': 'export default function App() { return null; }\n',
  }, { track: true });
  try {
    assert.equal(byRule(scan(dir), 'ENV_FILE_COMMITTED').length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('API_KEY_EXPOSED works on tracked .env files (provider key and unquoted API_KEY)', () => {
  const dir = tempProject({
    '.env': `STRIPE_KEY=sk_live_${rand(30).replace(/[-_]/g, 'a')}\nMAPS_API_KEY=${rand(36)}\n`,
    'App.tsx': 'export default function App() { return null; }\n',
  }, { track: true });
  try {
    const r = scan(dir);
    assert.deepEqual(linesOf(r, 'API_KEY_EXPOSED'), [1, 2]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('generic API key in .env: identifiers such as *_API_KEY_ISSUER_ID / *_KEY_ID are not secrets', async () => {
  const { gitProject } = await import('./helpers.mjs');
  const env = [
    'APP_STORE_CONNECT_API_KEY_ISSUER_ID="3f2a9c1e-7b4d-4e8a-9c21-5d6e7f8a9b0c"',
    'APP_STORE_CONNECT_API_KEY_KEY_ID="ABC123DEF4"',
    'RETAILER_API_KEY="Zq8vN2mXk4Rt7LpW9sYb3HcD5fGj6KaE1uT0"',
    'MAPS_API_KEY_ANDROID="Hw5nR8cT2yQ7vB3xZk9LmP4dFgJ6sA1eU0oI"',
  ].join('\n') + '\n';
  const r = scan(gitProject({ '.env': env }));
  const lines = r.findings.filter(f => f.ruleId === 'API_KEY_EXPOSED').map(f => f.line);
  assert.deepEqual(lines, [3, 4], 'only real *_API_KEY values (also with a platform suffix) are reported');
});
