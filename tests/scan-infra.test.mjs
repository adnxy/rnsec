import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { execFileSync } from 'node:child_process';
import { walkProjectFiles, isCollectedFile } from '../dist/core/fileWalker.js';
import { RuleEngine } from '../dist/core/ruleEngine.js';
import { resolveAndroidTargetSdk } from '../dist/utils/androidSdk.js';
import { isNonProductionPath, isAndroidDebugSourceSet } from '../dist/utils/pathFilters.js';
import { scan, byRule, gitProject } from './helpers.mjs';

const rel = (dir, files) => files.map(f => relative(dir, f)).sort();
const write = (dir, files) => {
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), c);
  }
};
const plainDir = files => {
  const dir = mkdtempSync(join(tmpdir(), 'rnsec-infra-'));
  write(dir, files);
  return dir;
};

const NATIVE = {
  'android/app/src/main/java/com/x/Main.java': 'class Main {}',
  'android/app/src/main/java/com/x/App.kt': 'class App',
  'ios/App/AppDelegate.swift': 'class A {}',
  'ios/App/Foo.m': '@implementation Foo @end',
  'ios/App/Bar.mm': '@implementation Bar @end',
};
const NATIVE_EXCLUDED = {
  'ios/Pods/Lib/Lib.m': 'x',
  'android/.gradle/x/Y.java': 'x',
  'ios/build/DerivedData/Z.swift': 'x',
  'ios/DerivedData/Z.swift': 'x',
  'ios/Carthage/Checkouts/C.swift': 'x',
  'ios/Some.framework/Headers/S.m': 'x',
  'ios/Some.xcframework/S.m': 'x',
  'android/app/src/test/java/com/x/UnitTest.java': 'x',
  'android/app/src/androidTest/java/com/x/InstTest.kt': 'x',
  'android/app/src/testDebug/java/com/x/D.java': 'x',
  'android/app/src/testRelease/java/com/x/R.java': 'x',
  'ios/AppTests/AppTests.swift': 'x',
  'ios/AppUITests/UI.swift': 'x',
  'android/app/src/main/java/com/x/FooTest.java': 'x',
  'android/app/src/main/java/com/x/FooTest.kt': 'x',
  'ios/App/FooTests.swift': 'x',
  'ios/App/FooTests.m': 'x',
  'ios/App/FooTests.mm': 'x',
};

test('walker collects native sources and skips vendored / build / test code', async () => {
  const dir = gitProject({ ...NATIVE, ...NATIVE_EXCLUDED }, { commit: true });
  const group = await walkProjectFiles(dir);
  assert.deepEqual(rel(dir, group.nativeFiles), Object.keys(NATIVE).sort());
  // the engine-level / --changed-files filter agrees with the walker
  for (const p of Object.keys(NATIVE_EXCLUDED)) {
    assert.ok(isNonProductionPath(join(dir, p), dir), `${p} must be non-production`);
  }
  for (const p of Object.keys(NATIVE)) {
    assert.ok(!isNonProductionPath(join(dir, p), dir), `${p} must be production`);
    assert.ok(isCollectedFile(join(dir, p)));
  }
});

const OTHER = {
  'ios/App/App.entitlements': '<plist/>',
  'firestore.rules': 'rules_version = 2;',
  'storage.rules': 'x',
  'sub/extra.rules': 'x',
  'database.rules.json': '{}',
  'sub/other.rules.json': '{}',
  'firebase.json': '{}',
  'package-lock.json': '{}',
  'npm-shrinkwrap.json': '{}',
  'yarn.lock': 'x',
  'pnpm-lock.yaml': 'x',
  'android/app/src/main/res/xml/file_paths.xml': '<paths/>',
  'android/app/src/main/res/xml/network_security_config.xml': '<network-security-config/>',
  'android/app/src/debug/res/xml/dbg.xml': '<x/>',
  'android/app/src/main/res/values/strings.xml': '<resources/>',
};
const PROPS = {
  'android/sentry.properties': 'auth.token=x',
  'android/keystore.properties': 'storePassword=x',
  'signing.properties': 'x',
  'credentials.json': '{}',
};

test('walker collects entitlements, firebase rules, lockfiles and res/xml; tracked-only properties', async () => {
  const dir = gitProject({ ...OTHER, ...PROPS }, { commit: true });
  const group = await walkProjectFiles(dir);
  assert.deepEqual(rel(dir, group.entitlementFiles), ['ios/App/App.entitlements']);
  assert.deepEqual(rel(dir, group.firebaseRuleFiles), ['database.rules.json', 'firebase.json', 'firestore.rules', 'storage.rules', 'sub/extra.rules', 'sub/other.rules.json']);
  assert.deepEqual(rel(dir, group.lockfiles), ['npm-shrinkwrap.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock']);
  // debug source set dropped; network_security_config.xml only once (in xmlFiles)
  assert.deepEqual(rel(dir, group.resXmlFiles), ['android/app/src/main/res/xml/file_paths.xml']);
  assert.ok(rel(dir, group.xmlFiles).includes('android/app/src/main/res/xml/network_security_config.xml'));
  assert.deepEqual(rel(dir, group.credentialPropertyFiles), Object.keys(PROPS).sort());
  for (const p of [...Object.keys(OTHER), ...Object.keys(PROPS)].filter(p => !p.includes('/debug/') && !p.includes('values'))) {
    assert.ok(isCollectedFile(join(dir, p)), `${p} must be collected by --changed-files too`);
  }
  assert.ok(!isCollectedFile(join(dir, 'android/app/src/main/res/values/strings.xml')));

  const untracked = gitProject({});
  write(untracked, PROPS);
  assert.deepEqual((await walkProjectFiles(untracked)).credentialPropertyFiles, []);
});

test('contexts: language for native files, plistContent for entitlements, fileContent for the rest', async () => {
  const dir = gitProject(
    { ...NATIVE, ...OTHER, 'android/sentry.properties': 'auth.token=x', 'package.json': '{"name":"x"}' },
    { commit: true }
  );
  const seen = {};
  const engine = new RuleEngine();
  engine.registerRuleGroup({
    category: 'CONFIG',
    rules: [
      {
        id: 'PROBE',
        description: 'probe',
        severity: 'LOW',
        fileTypes: ['.java', '.kt', '.swift', '.m', '.mm', '.entitlements', '.rules', 'yarn.lock', 'package-lock.json', 'sentry.properties', '.json', '.xml', '**/res/xml/*.xml'],
        apply: async ctx => {
          (seen[relative(dir, ctx.filePath)] ??= []).push(ctx);
          return [];
        },
      },
    ],
  });
  await engine.runRulesOnProject(dir);
  const ctx = p => seen[p]?.[0];
  assert.equal(ctx('android/app/src/main/java/com/x/Main.java').language, 'java');
  assert.equal(ctx('android/app/src/main/java/com/x/App.kt').language, 'kotlin');
  assert.equal(ctx('ios/App/AppDelegate.swift').language, 'swift');
  assert.equal(ctx('ios/App/Foo.m').language, 'objc');
  assert.equal(ctx('ios/App/Bar.mm').language, 'objc');
  assert.equal(ctx('ios/App/Foo.m').fileContent, '@implementation Foo @end');
  assert.equal(ctx('ios/App/App.entitlements').plistContent, '<plist/>');
  assert.equal(ctx('ios/App/App.entitlements').language, undefined);
  assert.equal(ctx('yarn.lock').fileContent, 'x');
  assert.equal(ctx('yarn.lock').config, undefined);
  assert.equal(ctx('firestore.rules').fileContent, 'rules_version = 2;');
  assert.equal(ctx('android/app/src/main/res/xml/file_paths.xml').xmlContent, '<paths/>');
  assert.equal(ctx('android/sentry.properties').fileContent, 'auth.token=x');
  assert.equal(ctx('android/sentry.properties').config, undefined);
  assert.ok(ctx('package.json').config, 'JSON files keep their parsed config');

  // generic '.json' / '.xml' rules never see the new file kinds (they would be huge or off-topic for those rules)
  const generic = {};
  const genericEngine = new RuleEngine();
  genericEngine.registerRuleGroup({
    category: 'CONFIG',
    rules: [{ id: 'G', description: 'g', severity: 'LOW', fileTypes: ['.json', '.xml'], apply: async c => { generic[relative(dir, c.filePath)] = true; return []; } }],
  });
  await genericEngine.runRulesOnProject(dir);
  assert.deepEqual(Object.keys(generic).sort(), ['android/app/src/main/res/xml/network_security_config.xml', 'package.json']);
});

const MANIFEST = `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:usesCleartextTraffic="true" android:label="x" />
</manifest>
`;

test('Android debug / debugOptimized source sets (any module) never produce findings', () => {
  const dir = gitProject(
    {
      'android/app/src/main/AndroidManifest.xml': MANIFEST,
      'android/app/src/debug/AndroidManifest.xml': MANIFEST,
      'android/app/src/debugOptimized/AndroidManifest.xml': MANIFEST,
      'android/lib/src/debug/AndroidManifest.xml': MANIFEST,
    },
    { commit: true }
  );
  const files = byRule(scan(dir), 'ANDROID_CLEARTEXT_ENABLED').map(f => relative(dir, f.filePath.replace(/^.*?(?=android\/)/, dir + '/')));
  assert.deepEqual(files, ['android/app/src/main/AndroidManifest.xml']);
  assert.ok(isAndroidDebugSourceSet('/p/android/app/src/debugOptimized/AndroidManifest.xml', '/p'));
  assert.ok(isAndroidDebugSourceSet('/p/android/lib/src/debug/java/A.java', '/p'));
  assert.ok(!isAndroidDebugSourceSet('/p/android/app/src/main/debugger/A.java', '/p'));
  assert.ok(!isAndroidDebugSourceSet('/p/android/app/src/release/A.java', '/p'));
});

test('--changed-files applies the same debug source set filter', () => {
  const dir = gitProject({
    'android/app/src/main/AndroidManifest.xml': MANIFEST,
    'android/app/src/debug/AndroidManifest.xml': MANIFEST,
  });
  const r = scan(dir, ['--changed-files', 'HEAD']);
  assert.equal(byRule(r, 'ANDROID_CLEARTEXT_ENABLED').length, 1);
});

test('findings inside native dev-only code are dropped, the else branch is kept', async () => {
  const dir = gitProject(
    {
      'android/app/src/main/java/A.java': ['void f() {', '  if (BuildConfig.DEBUG) {', '    probe();', '  } else {', '    probe();', '  }', '}'].join('\n'),
      'ios/B.swift': ['#if DEBUG', 'probe()', '#else', 'probe()', '#endif'].join('\n'),
      'ios/C.m': ['#ifdef DEBUG', 'probe();', '#endif', 'probe();'].join('\n'),
    },
    { commit: true }
  );
  const engine = new RuleEngine();
  engine.registerRuleGroup({
    category: 'CONFIG',
    rules: [
      {
        id: 'PROBE',
        description: 'probe',
        severity: 'LOW',
        fileTypes: ['.java', '.swift', '.m'],
        apply: async ctx =>
          ctx.fileContent.split('\n').flatMap((l, i) => (l.includes('probe') ? [{ ruleId: 'PROBE', description: 'p', severity: 'LOW', filePath: ctx.filePath, line: i + 1 }] : [])),
      },
    ],
  });
  const { findings } = await engine.runRulesOnProject(dir);
  const got = findings.map(f => `${relative(dir, f.filePath)}:${f.line}`).sort();
  assert.deepEqual(got, ['android/app/src/main/java/A.java:5', 'ios/B.swift:4', 'ios/C.m:4']);
});

test('androidTargetSdk: build.gradle literal forms', async () => {
  for (const [file, line, expected] of [
    ['build.gradle', '        targetSdkVersion 34', 34],
    ['build.gradle', '        targetSdkVersion = 33', 33],
    ['build.gradle.kts', '        targetSdk = 35', 35],
    ['build.gradle', '        // targetSdkVersion 20\n        targetSdkVersion 31', 31],
  ]) {
    const dir = plainDir({ [`android/app/${file}`]: `android {\n  compileSdkVersion 99\n  defaultConfig {\n${line}\n  }\n}\n` });
    assert.equal(await resolveAndroidTargetSdk(dir), expected, line);
  }
});

test('androidTargetSdk: rootProject.ext reference resolves from android/build.gradle', async () => {
  const app = 'android { defaultConfig { targetSdkVersion rootProject.ext.targetSdkVersion } }';
  const dir = plainDir({
    'android/app/build.gradle': app,
    'android/build.gradle': 'buildscript { ext {\n  compileSdkVersion = 36\n  targetSdkVersion = 35\n} }',
  });
  assert.equal(await resolveAndroidTargetSdk(dir), 35);
  const kts = plainDir({
    'android/app/build.gradle.kts': 'android { defaultConfig { targetSdk = rootProject.extra["targetSdkVersion"] as Int } }',
    'android/build.gradle.kts': 'extra["x"] = 1\nval targetSdkVersion = 34',
  });
  assert.equal(await resolveAndroidTargetSdk(kts), 34);
  // an unresolvable reference falls through to the later sources
  const fallthrough = plainDir({
    'android/app/build.gradle': app,
    'app.json': JSON.stringify({ expo: { plugins: [['expo-build-properties', { android: { targetSdkVersion: 36 } }]] } }),
  });
  assert.equal(await resolveAndroidTargetSdk(fallthrough), 36);
});

test('androidTargetSdk: Expo app.json / app.config.json and the manifest <uses-sdk>', async () => {
  const plugins = [['expo-camera'], ['expo-build-properties', { android: { targetSdkVersion: 35 }, ios: {} }]];
  assert.equal(await resolveAndroidTargetSdk(plainDir({ 'app.json': JSON.stringify({ expo: { plugins } }) })), 35);
  assert.equal(await resolveAndroidTargetSdk(plainDir({ 'app.config.json': JSON.stringify({ plugins }) })), 35);
  const manifest = '<manifest><uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/></manifest>';
  assert.equal(await resolveAndroidTargetSdk(plainDir({ 'android/app/src/main/AndroidManifest.xml': manifest })), 33);
  // first hit wins: build.gradle beats app.json beats the manifest
  const all = plainDir({
    'android/app/build.gradle': 'targetSdkVersion 34',
    'app.json': JSON.stringify({ expo: { plugins } }),
    'android/app/src/main/AndroidManifest.xml': manifest,
  });
  assert.equal(await resolveAndroidTargetSdk(all), 34);
  assert.equal(await resolveAndroidTargetSdk(plainDir({ 'package.json': '{}' })), undefined);
});

test('androidTargetSdk reaches rules through context.project', async () => {
  const dir = plainDir({ 'android/app/build.gradle': 'targetSdkVersion 34', 'android/app/src/main/java/A.java': 'class A {}' });
  let sdk = 'unset';
  const engine = new RuleEngine();
  engine.registerRuleGroup({
    category: 'CONFIG',
    rules: [{ id: 'P', description: 'p', severity: 'LOW', fileTypes: ['.java'], apply: async c => ((sdk = c.project?.androidTargetSdk), []) }],
  });
  await engine.runRulesOnProject(dir);
  assert.equal(sdk, 34);
});

const HTTP = "fetch('http://api.example-corp.com/x');\n";
const gitIn = (dir, ...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
const httpFiles = r => [...new Set(byRule(r, 'INSECURE_HTTP_URL').map(f => f.filePath.split(/rnsec-git-[^/]+\//)[1]))].sort();

test('.gitignore is respected; tracked files survive; --no-gitignore and respectGitignore:false opt out', () => {
  const dir = gitProject({
    '.gitignore': 'src/generated/\nlocal.ts\nforced.ts\n',
    'src/App.ts': HTTP,
    'src/generated/Api.ts': HTTP,
    'local.ts': HTTP,
    'forced.ts': HTTP,
  });
  gitIn(dir, 'add', '-f', 'forced.ts');
  gitIn(dir, 'commit', '-q', '-m', 'files');
  assert.deepEqual(httpFiles(scan(dir)), ['forced.ts', 'src/App.ts']);
  assert.deepEqual(httpFiles(scan(dir, ['--no-gitignore'])), ['forced.ts', 'local.ts', 'src/App.ts', 'src/generated/Api.ts']);

  writeFileSync(join(dir, '.rnsec.json'), JSON.stringify({ respectGitignore: false }));
  assert.equal(httpFiles(scan(dir)).length, 4);
});

test('runRulesOnFiles (--changed-files) honours .gitignore unless disabled', async () => {
  const dir = gitProject({ '.gitignore': 'ignored.ts\n', 'a.ts': HTTP, 'ignored.ts': HTTP });
  const run = async respect => {
    const engine = new RuleEngine();
    engine.setRespectGitignore(respect);
    engine.registerRuleGroup({
      category: 'CONFIG',
      rules: [{ id: 'P', description: 'p', severity: 'LOW', fileTypes: ['.ts'], apply: async c => [{ ruleId: 'P', description: 'p', severity: 'LOW', filePath: c.filePath, line: 1 }] }],
    });
    return (await engine.runRulesOnFiles([join(dir, 'a.ts'), join(dir, 'ignored.ts')], undefined, dir)).findings.map(f => relative(dir, f.filePath)).sort();
  };
  assert.deepEqual(await run(true), ['a.ts']);
  assert.deepEqual(await run(false), ['a.ts', 'ignored.ts']);
});

test('gitignore filtering is a no-op outside a git work tree', () => {
  const dir = plainDir({ '.gitignore': 'a.ts\n', 'a.ts': HTTP });
  const r = scan(dir);
  assert.equal(byRule(r, 'INSECURE_HTTP_URL').length, 1);
});

test('files inside an untracked nested git repository are not treated as ignored', () => {
  const dir = gitProject({ '.gitignore': 'ignored.ts\n', 'src/App.ts': HTTP, 'ignored.ts': HTTP });
  mkdirSync(join(dir, 'nested/lib'), { recursive: true });
  gitIn(join(dir, 'nested/lib'), 'init', '-q');
  writeFileSync(join(dir, 'nested/lib/x.ts'), HTTP);
  assert.deepEqual(httpFiles(scan(dir, ['--no-gitignore'])).filter(f => f !== 'ignored.ts'), ['nested/lib/x.ts', 'src/App.ts']);
  assert.deepEqual(httpFiles(scan(dir)), ['nested/lib/x.ts', 'src/App.ts']);
});
