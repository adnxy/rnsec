import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { scan, byRule, repoRoot, gitProject } from './helpers.mjs';
import { isSensitiveNavigationParamName } from '../dist/scanners/react-native/reactNativeScanner.js';

// Absence-of-feature rules (snapshot / screenshot protection, session timeout) and NO_REQUEST_TIMEOUT report from
// `finalize`: one finding per project, judged on the whole project, in full scans and in --changed-files scans.

const bin = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');
const run = (args) => spawnSync('node', [bin, 'scan', ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
const json = (dir, extra = []) => JSON.parse(run(['-p', dir, '--json', ...extra]).stdout);
const commit = (dir) => {
  execFileSync('git', ['add', '-A'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', 'c'], { cwd: dir });
};
const stage = (dir, files) => {
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(join(dir, rel, '..'), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  execFileSync('git', ['add', '-A'], { cwd: dir });
};
const pkg = (deps = {}) => JSON.stringify({ name: 'app', version: '1.0.0', dependencies: { 'react-native': '0.74.0', ...deps } });
const rel = (dir, f) => f.filePath.slice(f.filePath.indexOf(dir.split('/').pop()) + dir.split('/').pop().length + 1);

// ───────────────────────── IOS_MISSING_APP_SNAPSHOT_PROTECTION ─────────────────────────
const SNAP = 'IOS_MISSING_APP_SNAPSHOT_PROTECTION';
const walletApp = {
  'package.json': pkg(),
  'App.tsx': "// wallet app\nexport default function App() { return null; }\n",
  'index.js': "import './App'; // wallet\n",
  'src/index.ts': "export const wallet = 1;\n",
};

test('snapshot: sensitive app without protection gives ONE finding at App.tsx with count and examples', () => {
  const dir = gitProject(walletApp, { commit: true });
  const found = byRule(json(dir), SNAP);
  assert.equal(found.length, 1);
  assert.equal(rel(dir, found[0]), 'App.tsx');
  assert.equal(found[0].line, 1);
  assert.equal(found[0].confidence, 'low');
  assert.equal(found[0].severity, 'LOW');
  assert.match(found[0].description, /\(3 files, e\.g\. App\.tsx, index\.js, src\/index\.ts\)/);
});

test('snapshot: protection anywhere in the project means no finding', () => {
  const variants = {
    'blur handler in AppDelegate': { 'ios/App/AppDelegate.mm': '- (void)applicationWillResignActive:(UIApplication *)a { [self.window addSubview:self.blurView]; }\n' },
    'swift scene delegate with UIVisualEffectView': { 'ios/App/SceneDelegate.swift': 'func sceneDidEnterBackground(_ s: UIScene) { let v = UIVisualEffectView() }\n' },
    'AppState inactive + BlurView in another file': { 'src/Privacy.tsx': "import { BlurView } from '@react-native-community/blur';\nAppState.addEventListener('change', s => { if (s === 'inactive') show(); });\n" },
    'protection package in package.json': { 'package.json': pkg({ 'react-native-privacy-snapshot': '1.0.0' }) },
    'expo-screen-capture in code': { 'src/lock.ts': "import * as ScreenCapture from 'expo-screen-capture';\n" },
  };
  for (const [name, extra] of Object.entries(variants)) {
    const dir = gitProject({ ...walletApp, ...extra }, { commit: true });
    assert.equal(byRule(json(dir), SNAP).length, 0, name);
  }
});

test('snapshot: lifecycle names alone, or a splash AppState handler, are not protection', () => {
  const dir = gitProject(
    {
      ...walletApp,
      'ios/App/AppDelegate.mm': '- (void)applicationDidBecomeActive:(UIApplication *)a { [self sync]; }\n- (void)applicationDidEnterBackground:(UIApplication *)a { [self flush]; }\n',
      'src/Splash.tsx': "AppState.addEventListener('change', s => { if (s === 'background') SplashScreen.hide(); });\n",
    },
    { commit: true }
  );
  assert.equal(byRule(json(dir), SNAP).length, 1);
});

test('snapshot: non-sensitive project, and keywords only in scripts/tests, give nothing', () => {
  const plain = gitProject({ 'package.json': pkg(), 'App.tsx': 'export default function App() { return null; }\n' }, { commit: true });
  assert.equal(byRule(json(plain), SNAP).length, 0);
  const scripts = gitProject(
    { 'package.json': pkg(), 'App.tsx': 'export default function App() { return null; }\n', 'scripts/index.js': '// wallet banking\n', 'e2e/index.js': '// payment\n' },
    { commit: true }
  );
  assert.equal(byRule(json(scripts), SNAP).length, 0);
});

test('snapshot: protection that only exists in an e2e helper does not silence the finding', () => {
  const dir = gitProject({ ...walletApp, 'e2e/helper.js': "import 'react-native-privacy-snapshot';\n" }, { commit: true });
  assert.equal(byRule(json(dir), SNAP).length, 1);
});

test('snapshot: ignoredRules and rnsec-ignore', () => {
  const ignored = gitProject({ ...walletApp, '.rnsec.json': JSON.stringify({ ignoredRules: [SNAP] }) }, { commit: true });
  assert.equal(byRule(json(ignored), SNAP).length, 0);

  // directive on the anchor's line 1: the finding is suppressed and counted
  const anchorIgnored = gitProject({ ...walletApp, 'App.tsx': `// rnsec-ignore: ${SNAP}\n// wallet app\nexport default function App() { return null; }\n` }, { commit: true });
  const r = json(anchorIgnored);
  const found = byRule(r, SNAP);
  // the per-file ignore removes App.tsx from the evidence: the anchor moves to the next file
  assert.equal(found.length, 1);
  assert.equal(rel(anchorIgnored, found[0]), 'index.js');
  assert.match(found[0].description, /\(2 files/);

  const allIgnored = gitProject(
    Object.fromEntries(Object.entries(walletApp).map(([k, v]) => [k, k === 'package.json' ? v : `// rnsec-ignore: ${SNAP}\n${v}`])),
    { commit: true }
  );
  assert.equal(byRule(json(allIgnored), SNAP).length, 0);
});

test('snapshot: the baseline fingerprint survives more evidence files and edits elsewhere', () => {
  const dir = gitProject(walletApp, { commit: true });
  const baseline = join(mkdtempSync(join(tmpdir(), 'rnsec-bl-')), 'baseline.json');
  run(['-p', dir, '--json', '--write-baseline', baseline]);
  assert.ok(JSON.parse(readFileSync(baseline, 'utf8')).findings.some(f => f.ruleId === SNAP));
  stage(dir, { 'src/payment.ts': '// payment\nexport const x = 1;\n', 'src/index.ts': '// wallet\nexport const wallet = 2;\n' });
  const after = json(dir, ['--baseline', baseline]);
  assert.equal(byRule(after, SNAP).length, 0, 'still hidden by the baseline');
  assert.equal(after.baselinedCount >= 1, true);
});

test('snapshot: --changed-files judges the whole project, and needs a changed evidence file', () => {
  // evidence file changed, no protection anywhere: reported
  const dir = gitProject({ ...walletApp }, { commit: true });
  stage(dir, { 'App.tsx': "// wallet app\nexport default function App() { return 1; }\n" });
  const changed = byRule(json(dir, ['--changed-files', 'HEAD']), SNAP);
  assert.equal(changed.length, 1);
  assert.equal(rel(dir, changed[0]), 'App.tsx');
  assert.match(changed[0].description, /\(1 file, e\.g\. App\.tsx\)/);

  // protection lives in an UNCHANGED native file: silences the finding exactly like a full scan
  const guarded = gitProject({ ...walletApp, 'ios/App/AppDelegate.mm': '- (void)applicationWillResignActive:(UIApplication *)a { [self.window addSubview:self.cover]; }\n' }, { commit: true });
  stage(guarded, { 'App.tsx': "// wallet app\nexport default function App() { return 1; }\n" });
  assert.equal(byRule(json(guarded, ['--changed-files', 'HEAD']), SNAP).length, 0);
  assert.equal(byRule(json(guarded), SNAP).length, 0);

  // the package.json dependency is also read in a partial scan
  const dep = gitProject({ ...walletApp, 'package.json': pkg({ 'react-native-privacy-snapshot': '1.0.0' }) }, { commit: true });
  stage(dep, { 'App.tsx': "// wallet app\nexport default function App() { return 1; }\n" });
  assert.equal(byRule(json(dep, ['--changed-files', 'HEAD']), SNAP).length, 0);

  // only an unrelated file changed: no evidence in scope, no finding (the full scan still reports)
  const quiet = gitProject({ ...walletApp }, { commit: true });
  stage(quiet, { 'src/util.ts': 'export const a = 1;\n' });
  assert.equal(byRule(json(quiet, ['--changed-files', 'HEAD']), SNAP).length, 0);
  assert.equal(byRule(json(quiet), SNAP).length, 1);
});

// ───────────────────────── SCREENSHOT_PROTECTION_MISSING ─────────────────────────
const SHOT = 'SCREENSHOT_PROTECTION_MISSING';
const screen = (name) =>
  `import React from 'react';\nimport { TextInput, View } from 'react-native';\nexport default function ${name}() {\n  return <View><TextInput secureTextEntry placeholder="x" /></View>;\n}\n`;
const screens = { 'package.json': pkg(), 'src/screens/LoginScreen.tsx': screen('Login'), 'src/screens/PinScreen.tsx': screen('Pin'), 'src/screens/Wallet/SeedScreen.tsx': screen('Seed') };

test('screenshot: several unprotected sensitive screens give ONE finding', () => {
  const dir = gitProject(screens, { commit: true });
  const found = byRule(json(dir), SHOT);
  assert.equal(found.length, 1);
  assert.equal(rel(dir, found[0]), 'src/screens/LoginScreen.tsx');
  assert.match(found[0].description, /\(3 files, e\.g\. src\/screens\/LoginScreen\.tsx, src\/screens\/PinScreen\.tsx, src\/screens\/Wallet\/SeedScreen\.tsx\)/);
  assert.equal(found[0].confidence, 'low');
});

test('screenshot: protection elsewhere (JS, FLAG_SECURE, package) silences it', () => {
  const variants = {
    'expo-screen-capture in another file': { 'src/hooks/useGuard.ts': "import { usePreventScreenCapture } from 'expo-screen-capture';\n" },
    'FLAG_SECURE in MainActivity': { 'android/app/src/main/java/com/x/MainActivity.java': 'class MainActivity { void f() { getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE); } }\n' },
    'FLAG_SECURE in Kotlin': { 'android/app/src/main/java/com/x/MainActivity.kt': 'class MainActivity { fun f() { window.addFlags(WindowManager.LayoutParams.FLAG_SECURE) } }\n' },
    'capture-protection package': { 'package.json': pkg({ 'react-native-capture-protection': '1.0.0' }) },
  };
  for (const [name, extra] of Object.entries(variants)) {
    const dir = gitProject({ ...screens, ...extra }, { commit: true });
    assert.equal(byRule(json(dir), SHOT).length, 0, name);
  }
});

test('screenshot: secureTextEntry={false} is not a sensitive screen; ignoredRules is respected', () => {
  const off = gitProject({ 'package.json': pkg(), 'src/screens/Plain.tsx': screen('Plain').replace('secureTextEntry', 'secureTextEntry={false}') }, { commit: true });
  assert.equal(byRule(json(off), SHOT).length, 0);
  const ignored = gitProject({ ...screens, '.rnsec.json': JSON.stringify({ ignoredRules: [SHOT] }) }, { commit: true });
  assert.equal(byRule(json(ignored), SHOT).length, 0);
});

test('screenshot: --changed-files reads FLAG_SECURE from unchanged native files', () => {
  const dir = gitProject({ ...screens, 'android/app/src/main/java/com/x/MainActivity.java': 'class A { int f = WindowManager.LayoutParams.FLAG_SECURE; }\n' }, { commit: true });
  stage(dir, { 'src/screens/LoginScreen.tsx': screen('Login') + '// changed\n' });
  assert.equal(byRule(json(dir, ['--changed-files', 'HEAD']), SHOT).length, 0);
  const bare = gitProject(screens, { commit: true });
  stage(bare, { 'src/screens/LoginScreen.tsx': screen('Login') + '// changed\n' });
  const f = byRule(json(bare, ['--changed-files', 'HEAD']), SHOT);
  assert.equal(f.length, 1);
  assert.match(f[0].description, /\(1 file, e\.g\. src\/screens\/LoginScreen\.tsx\)/);
});

// ───────────────────────── MISSING_SESSION_TIMEOUT ─────────────────────────
const SESS = 'MISSING_SESSION_TIMEOUT';
const authFile = "export async function login(user, pass) {\n  const t = await api.post('/login', { user, pass });\n  await AsyncStorage.setItem('session_token', t);\n}\n";
const authApp = { 'package.json': pkg(), 'src/auth/authService.ts': authFile, 'src/auth/loginApi.ts': authFile, 'src/session/sessionStore.ts': authFile };

test('session: unprotected auth files give ONE finding (MEDIUM, low confidence)', () => {
  const dir = gitProject(authApp, { commit: true });
  const found = byRule(json(dir), SESS);
  assert.equal(found.length, 1);
  assert.equal(rel(dir, found[0]), 'src/auth/authService.ts');
  assert.equal(found[0].severity, 'MEDIUM');
  assert.equal(found[0].confidence, 'low');
  assert.match(found[0].description, /\(3 files, e\.g\. src\/auth\/authService\.ts, src\/auth\/loginApi\.ts, src\/session\/sessionStore\.ts\)/);
});

test('session: token expiry, inactivity or lock logic anywhere in the project silences it', () => {
  const variants = {
    'token expiry check': { 'src/net/http.ts': 'export const isTokenExpired = (t) => decode(t).exp * 1000 < Date.now();\n' },
    'jwt-decode': { 'src/net/jwt.ts': "import jwtDecode from 'jwt-decode';\n" },
    'oauth expires_in next to token': { 'src/net/oauth.ts': 'const token = res.access_token; const ttl = res.expires_in;\n' },
    'inactivity timer': { 'src/idle.ts': 'export function startInactivityTimer() {}\n' },
    'AppState + logout + timer': { 'src/lock.ts': "AppState.addEventListener('change', s => { if (s === 'background') setTimeout(() => logout(), 1000); });\n" },
    'inactivity package': { 'package.json': pkg({ 'react-native-user-inactivity': '1.0.0' }) },
  };
  for (const [name, extra] of Object.entries(variants)) {
    const dir = gitProject({ ...authApp, ...extra }, { commit: true });
    assert.equal(byRule(json(dir), SESS).length, 0, name);
  }
});

test('session: AppState alone, an unrelated expiry and non-auth files are not evidence either way', () => {
  const dir = gitProject(
    { ...authApp, 'src/appState.ts': "AppState.addEventListener('change', () => {});\n", 'src/cache.ts': 'export const couponExpiry = 5;\n' },
    { commit: true }
  );
  assert.equal(byRule(json(dir), SESS).length, 1);
  const none = gitProject({ 'package.json': pkg(), 'src/utils/api.ts': authFile }, { commit: true });
  assert.equal(byRule(json(none), SESS).length, 0);
});

test('session: ignoredRules and --changed-files', () => {
  const ignored = gitProject({ ...authApp, '.rnsec.json': JSON.stringify({ ignoredRules: [SESS] }) }, { commit: true });
  assert.equal(byRule(json(ignored), SESS).length, 0);

  const guarded = gitProject({ ...authApp, 'src/net/http.ts': 'export const isTokenExpired = (t) => true;\n' }, { commit: true });
  stage(guarded, { 'src/auth/authService.ts': authFile + '// changed\n' });
  assert.equal(byRule(json(guarded, ['--changed-files', 'HEAD']), SESS).length, 0, 'unchanged expiry logic still counts');

  const bare = gitProject(authApp, { commit: true });
  stage(bare, { 'src/auth/authService.ts': authFile + '// changed\n' });
  const f = byRule(json(bare, ['--changed-files', 'HEAD']), SESS);
  assert.equal(f.length, 1);
  assert.match(f[0].description, /\(1 file, e\.g\. src\/auth\/authService\.ts\)/);
});

// ───────────────────────── NO_REQUEST_TIMEOUT ─────────────────────────
const NRT = 'NO_REQUEST_TIMEOUT';
const callers = (dir) => byRule(json(dir), NRT).map(f => `${rel(dir, f)}:${f.line}`).sort();

test('timeout: a raw global fetch / axios call without any timeout is still reported (LOW)', () => {
  const dir = gitProject(
    { 'package.json': pkg(), 'src/a.ts': "export const a = () => fetch('https://api.example.com/a');\n", 'src/b.ts': "import axios from 'axios';\nexport const b = () => axios.get('https://api.example.com/b', { headers: {} });\n" },
    { commit: true }
  );
  assert.deepEqual(callers(dir), ['src/a.ts:1', 'src/b.ts:2']);
  assert.equal(byRule(json(dir), NRT)[0].severity, 'LOW');
});

test('timeout: shadowed fetch, project wrappers and local resources are not reported', () => {
  const dir = gitProject(
    {
      'package.json': pkg(),
      // a local function named fetch, called with non-network arguments
      'src/shadow.ts': "function fetch(w: string, recurse = false) { return w; }\nexport const a = fetch('x', true);\n",
      // a parameter named fetch
      'src/param.ts': 'export const p = (fetch: any) => fetch("https://api.example.com");\n',
      // imported project wrappers (relative and aliased)
      'src/wrapper.ts': "import fetch from './http';\nimport { fetch as f2 } from '@/lib/net';\nexport const w = () => [fetch('https://a.example.com'), f2('https://b.example.com')];\n",
      'src/http.ts': 'export default (u: string) => u;\n',
      // local resources never leave the device
      'src/local.ts': "export const l = () => [fetch('file:///tmp/a'), fetch('blob:abc'), fetch(`data:text/plain;base64,${x}`), fetch(require('./a.png'))];\nconst u = URL.createObjectURL(b);\nexport const m = () => fetch(u);\n",
    },
    { commit: true }
  );
  assert.deepEqual(callers(dir), []);
});

test('timeout: options that carry no timeout are still reported (inline, behind a local const, or passed through a wrapper)', () => {
  const dir = gitProject(
    {
      'package.json': pkg(),
      'src/a.ts': [
        "export const a = () => fetch('https://api.example.com/a', { method: 'POST' });",
        "const init = { method: 'GET', headers: {} };",
        "export const b = () => fetch('https://api.example.com/b', init);",
        "const base = { headers: {} };",
        "export const c = () => fetch('https://api.example.com/c', { ...base });",
        "export const d = () => fetch('https://api.example.com/d', { method: 'GET', signal: AbortSignal.timeout(5000) });",
        "const guarded = { signal: AbortSignal.timeout(5000) };",
        "export const e = () => fetch('https://api.example.com/e', guarded);",
        "export const f = (opts: RequestInit) => fetch('https://api.example.com/f', opts);",
        "export const g = (opts: RequestInit) => fetch('https://api.example.com/g', { ...opts, headers: {} });",
      ].join('\n'),
    },
    { commit: true }
  );
  assert.deepEqual(callers(dir), ['src/a.ts:1', 'src/a.ts:10', 'src/a.ts:3', 'src/a.ts:5', 'src/a.ts:9']); // sorted as strings
});

test('timeout: fetch from a global-equivalent package is still the global fetch', () => {
  const dir = gitProject(
    { 'package.json': pkg(), 'src/nf.ts': "import fetch from 'cross-fetch';\nexport const a = () => fetch('https://api.example.com/a');\n" },
    { commit: true }
  );
  assert.deepEqual(callers(dir), ['src/nf.ts:2']);
});

test('timeout: axios.defaults.timeout anywhere clears axios calls (not fetch); a global fetch override clears fetch', () => {
  const files = {
    'package.json': pkg(),
    'src/api.ts': "import axios from 'axios';\nexport const g = () => axios.get('https://api.example.com/x', { headers: {} });\nexport const f = () => fetch('https://api.example.com/y');\n",
  };
  const bare = gitProject(files, { commit: true });
  assert.deepEqual(callers(bare), ['src/api.ts:2', 'src/api.ts:3']);

  const axiosDefault = gitProject({ ...files, 'src/setup.ts': "import axios from 'axios';\naxios.defaults.timeout = 10000;\n" }, { commit: true });
  assert.deepEqual(callers(axiosDefault), ['src/api.ts:3']);

  const patched = gitProject({ ...files, 'src/setup.ts': "const orig = globalThis.fetch;\nglobalThis.fetch = (u, i) => orig(u, { ...i, signal: AbortSignal.timeout(5000) });\n" }, { commit: true });
  assert.deepEqual(callers(patched), ['src/api.ts:2']);

  // an override that only forwards (mock-server / native transport shims) adds no timeout: the calls stay reported
  const forwarding = gitProject({ ...files, 'src/setup.ts': "const orig = globalThis.fetch;\nglobalThis.fetch = (u, i) => orig(u, i);\n" }, { commit: true });
  assert.deepEqual(callers(forwarding), ['src/api.ts:2', 'src/api.ts:3']);
});

test('timeout: --changed-files reads project defaults from unchanged files', () => {
  const api = "import axios from 'axios';\nexport const g = () => axios.get('https://api.example.com/x', { headers: {} });\n";
  const dir = gitProject({ 'package.json': pkg(), 'src/api.ts': api, 'src/setup.ts': "import axios from 'axios';\naxios.defaults.timeout = 10000;\n" }, { commit: true });
  stage(dir, { 'src/api.ts': api + '// changed\n' });
  assert.deepEqual(byRule(json(dir, ['--changed-files', 'HEAD']), NRT), []);
  const patched = gitProject({ 'package.json': pkg(), 'src/f.ts': "export const f = () => fetch('https://api.example.com/y');\n", 'src/setup.ts': "const orig = globalThis.fetch;\nglobalThis.fetch = (u, i) => orig(u, { ...i, signal: AbortSignal.timeout(5000) });\n" }, { commit: true });
  stage(patched, { 'src/f.ts': "export const f = () => fetch('https://api.example.com/y'); // changed\n" });
  assert.deepEqual(byRule(json(patched, ['--changed-files', 'HEAD']), NRT), []);
  const forwarding = gitProject({ 'package.json': pkg(), 'src/f.ts': "export const f = () => fetch('https://api.example.com/y');\n", 'src/setup.ts': "globalThis.fetch = (u, i) => orig(u, i);\n" }, { commit: true });
  stage(forwarding, { 'src/f.ts': "export const f = () => fetch('https://api.example.com/y'); // changed\n" });
  assert.equal(byRule(json(forwarding, ['--changed-files', 'HEAD']), NRT).length, 1);
  const bare = gitProject({ 'package.json': pkg(), 'src/api.ts': api }, { commit: true });
  stage(bare, { 'src/api.ts': api + '// changed\n' });
  assert.equal(byRule(json(bare, ['--changed-files', 'HEAD']), NRT).length, 1);
});

test('timeout: rnsec-ignore on the call line and ignoredRules still work', () => {
  const files = { 'package.json': pkg(), 'src/a.ts': "// rnsec-ignore: NO_REQUEST_TIMEOUT streaming endpoint\nexport const a = () => fetch('https://api.example.com/a');\nexport const b = () => fetch('https://api.example.com/b');\n" };
  const dir = gitProject(files, { commit: true });
  assert.deepEqual(callers(dir), ['src/a.ts:3']);
  const ignored = gitProject({ ...files, '.rnsec.json': JSON.stringify({ ignoredRules: [NRT] }) }, { commit: true });
  assert.deepEqual(callers(ignored), []);
});

// ───────────────────────── ANDROID platform-required exports ─────────────────────────
test('android: launcher, share, widget, settings, SDK and specific deep-link components are not reported', () => {
  const r = scan('android-platform-exports');
  for (const id of ['ANDROID_EXPORTED_COMPONENT', 'ANDROID_INTENT_FILTER_PERMISSIVE', 'ANDROID_UNPROTECTED_RECEIVER']) {
    assert.deepEqual(byRule(r, id).map(f => f.line), [], id);
  }
});

test('android: providers, filterless services, wildcard or catch-all links and mixed filters stay reported', () => {
  const r = scan('android-platform-exports-pos');
  assert.deepEqual(byRule(r, 'ANDROID_EXPORTED_COMPONENT').map(f => f.line), [3, 4, 5, 6, 14, 22, 30, 39]);
  // catch-all https link, wildcard host, wildcard scheme, VIEW+DEFAULT file handler; the commented-out SENDTO filter is ignored
  assert.deepEqual(byRule(r, 'ANDROID_INTENT_FILTER_PERMISSIVE').map(f => f.line), [7, 15, 23, 40]);
});

// ───────────────────────── DEPENDENCY_NONREGISTRY_SOURCE ─────────────────────────
test('dependencies: short SHAs and tags are pins (LOW); branches, bare repos and tarballs stay MEDIUM; local protocols are quiet', () => {
  const deps = {
    full: 'github:o/full#' + 'a'.repeat(40).replace(/a/g, '1'),
    short: 'github:o/short#df82345',
    short6: 'github:o/short6#59a037',
    tag: 'github:o/tag#v1.2.3',
    gitplus: 'git+https://github.com/o/gitplus.git#7ec4b19',
    branch: 'github:o/branch#main',
    wordlike: 'github:o/wordlike#feedbeef',
    nopin: 'github:o/nopin',
    tarball: 'https://example.com/pkg.tgz',
    ws: 'workspace:*',
    file: 'file:../pkg',
    link: 'link:../pkg',
    portal: 'portal:../pkg',
    registry: '^1.2.3',
  };
  const dir = gitProject({ 'package.json': JSON.stringify({ name: 'app', version: '1.0.0', dependencies: deps }) }, { commit: true });
  const found = Object.fromEntries(byRule(json(dir), 'DEPENDENCY_NONREGISTRY_SOURCE').map(f => [f.description.match(/^"([^"]+)"/)[1], f]));
  assert.deepEqual(Object.keys(found).sort(), ['branch', 'full', 'gitplus', 'nopin', 'short', 'short6', 'tag', 'tarball', 'wordlike']);
  for (const name of ['full', 'short', 'short6', 'tag', 'gitplus']) {
    assert.equal(found[name].severity, 'LOW', name);
    assert.match(found[name].description, /pinned to a commit or tag/, name);
  }
  for (const name of ['branch', 'wordlike', 'nopin']) {
    assert.equal(found[name].severity, 'MEDIUM', name);
    assert.match(found[name].description, /without a commit pin/, name);
  }
  assert.equal(found.tarball.severity, 'MEDIUM');
});

// ───────────────────────── SENSITIVE_NAVIGATION_PARAMS ─────────────────────────
test('navigation params: credentials by whole word; assets, ids and callbacks are not', () => {
  for (const name of ['password', 'ssoToken', 'tokenForProviderToBeLinked', 'accessToken', 'refresh_token', 'token', 'api_key', 'apiKey', 'pin', 'userPin', 'cvv', 'cardNumber', 'secretRecoveryPhrase', 'creditCard', 'authToken', 'idToken', 'newpassword', 'clientsecret', 'userpassword', 'confirmPassword', 'SSN']) {
    assert.ok(isSensitiveNavigationParamName(name), name);
  }
  for (const name of ['tokenSymbol', 'tokenAddress', 'selectedToken', 'excludeRwaTokens', 'addTokenList', 'gasTokenAddress', 'srcTokenAsset', 'tokenDetailsSource', 'tokenImageUrl', 'preferredPaymentToken', 'shippingAddress', 'tokenId', 'userId', 'title', 'spinner', 'className', 'shipping']) {
    assert.ok(!isSensitiveNavigationParamName(name), name);
  }
});

test('navigation params: reported per call site, callbacks skipped', () => {
  const dir = gitProject(
    {
      'package.json': pkg(),
      'src/nav.ts': [
        "export function a(navigation) {",
        "  navigation.navigate('Link', { ssoToken: t });",
        "  navigation.navigate('Pwd', { password: p, other: 1 });",
        "  navigation.push('Asset', { tokenSymbol: 'ETH', selectedToken: tk, excludeRwaTokens: true });",
        "  navigation.navigate('Cb', { onPasswordSet: () => {} });",
        "  navigation.navigate('Ship', { shippingAddress: addr });",
        '}',
      ].join('\n'),
    },
    { commit: true }
  );
  assert.deepEqual(byRule(json(dir), 'SENSITIVE_NAVIGATION_PARAMS').map(f => f.line), [2, 3]);
});

// ───────────────────────── IOS_BACKGROUND_MODES_UNNECESSARY ─────────────────────────
const plist = (modes) =>
  `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n  <key>UIBackgroundModes</key>\n  <array>\n${modes.map(m => `    <string>${m}</string>`).join('\n')}\n  </array>\n</dict>\n</plist>\n`;
const modesOf = (dir) => byRule(json(dir), 'IOS_BACKGROUND_MODES_UNNECESSARY').map(f => f.description.match(/'([^']+)'/)[1]).sort();

test('background modes: a mode backed by its library in dependencies is in use, the rest are reported', () => {
  const all = ['location', 'fetch', 'remote-notification', 'voip', 'audio'];
  const bare = gitProject({ 'package.json': pkg(), 'ios/App/Info.plist': plist(all) }, { commit: true });
  assert.deepEqual(modesOf(bare), ['audio', 'fetch', 'location', 'remote-notification', 'voip']);

  const backed = gitProject(
    { 'package.json': pkg({ 'expo-location': '1.0.0', 'expo-notifications': '1.0.0', 'react-native-track-player': '1.0.0' }), 'ios/App/Info.plist': plist(all) },
    { commit: true }
  );
  assert.deepEqual(modesOf(backed), ['fetch', 'voip']);

  // an unrelated library does not back a mode
  const wrong = gitProject({ 'package.json': pkg({ 'expo-location': '1.0.0' }), 'ios/App/Info.plist': plist(['audio']) }, { commit: true });
  assert.deepEqual(modesOf(wrong), ['audio']);
});
