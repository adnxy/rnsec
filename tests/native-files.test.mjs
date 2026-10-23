import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { scan, byRule, ids, gitProject, untrackedProject } from './helpers.mjs';

// All fixtures are generated at test time inside temp git repos; no key material or token-shaped string lives in the repo.
const where = (r, id) => byRule(r, id).map(f => `${f.filePath.split(/rnsec-git-[^/]+\//)[1]}:${f.line}:${f.severity}:${f.confidence}`).sort();

const pw = () => randomBytes(9).toString('base64').replace(/[^A-Za-z0-9]/g, 'q'); // realistic random password

test('ANDROID_SIGNING_CREDENTIALS_HARDCODED: build.gradle literals flagged, debug/env/properties refs ignored', () => {
  const store = pw();
  const key = pw();
  const gradle = [
    'android {',                                                   // 1
    '  signingConfigs {',                                          // 2
    '    debug {',                                                 // 3
    "      storePassword 'android'",                               // 4
    "      keyPassword 'android'",                                 // 5
    '    }',                                                       // 6
    '    release {',                                               // 7
    `      storePassword '${store}'`,                              // 8
    `      keyPassword = "${key}"`,                                // 9
    "      keyAlias 'upload'",                                     // 10
    '    }',                                                       // 11
    '    staging {',                                               // 12
    "      storePassword System.getenv('STORE_PW')",               // 13
    "      keyPassword keystoreProperties['keyPassword']",         // 14
    '      storePassword MYAPP_UPLOAD_STORE_PASSWORD',             // 15
    "      keyPassword project.findProperty('KEY_PW')",            // 16
    '      storePassword "${System.getenv("X")}"',                 // 17
    `      // storePassword '${store}'`,                           // 18
    "      keyPassword 'changeme'",                                // 19
    '    }',                                                       // 20
    '  }',                                                         // 21
    '}',
  ].join('\n');
  const kts = [
    'android {',
    '  signingConfigs {',
    '    create("release") {',
    `      storePassword = "${store}"`,                            // 4
    '      keyPassword = System.getenv("KEY_PW")',
    '    }',
    '    getByName("debug") {',
    `      storePassword = "${key}"`,                              // not flagged: debug
    '    }',
    '  }',
    '}',
  ].join('\n');
  const dir = gitProject({ 'android/app/build.gradle': gradle, 'android-kts/app/build.gradle.kts': kts });
  const r = scan(dir);
  assert.deepEqual(where(r, 'ANDROID_SIGNING_CREDENTIALS_HARDCODED'), [
    'android-kts/app/build.gradle.kts:4:HIGH:high',
    'android/app/build.gradle:8:HIGH:high',
    'android/app/build.gradle:9:HIGH:high',
  ]);
  const text = JSON.stringify(r.findings);
  assert.ok(!text.includes(store) && !text.includes(key), 'password values must be masked');
});

test('ANDROID_SIGNING_CREDENTIALS_HARDCODED: gradle.properties', () => {
  const secret = pw();
  const props = [
    'org.gradle.jvmargs=-Xmx2048m',                // 1
    'android.useAndroidX=true',                    // 2
    'MYAPP_UPLOAD_STORE_FILE=my-upload-key.keystore', // 3
    'MYAPP_UPLOAD_KEY_ALIAS=my-key-alias',         // 4
    `MYAPP_UPLOAD_STORE_PASSWORD=${secret}`,       // 5
    'MYAPP_UPLOAD_KEY_PASSWORD=*****',             // 6
    `#RELEASE_STORE_PASSWORD=${secret}`,           // 7 commented
    'RELEASE_KEY_PASSWORD=',                       // 8 empty
    'android.injected.signing.store.password=changeme', // 9
    `storePassword=${secret}`,                     // 10
  ].join('\n');
  const r = scan(gitProject({ 'android/gradle.properties': props }));
  assert.deepEqual(where(r, 'ANDROID_SIGNING_CREDENTIALS_HARDCODED'), [
    'android/gradle.properties:10:HIGH:high',
    'android/gradle.properties:5:HIGH:high',
  ]);
  assert.ok(!JSON.stringify(r.findings).includes(secret));
});

test('ANDROID_SIGNING_CREDENTIALS_HARDCODED: untracked gradle.properties is not collected', () => {
  const r = scan(untrackedProject({ 'android/gradle.properties': `MYAPP_UPLOAD_STORE_PASSWORD=${pw()}\n` }));
  assert.deepEqual(byRule(r, 'ANDROID_SIGNING_CREDENTIALS_HARDCODED'), []);
});

test('NPM_REGISTRY_CONFIG_INSECURE: .npmrc', () => {
  const token = 'npm_' + randomBytes(18).toString('hex');
  const npmrc = [
    '# comment',                                              // 1
    `//registry.npmjs.org/:_authToken=${token}`,              // 2 HIGH
    '//registry.npmjs.org/:_authToken=${NPM_TOKEN}',          // 3 env ref
    '//npm.pkg.github.com/:_authToken=<your-token>',          // 4 placeholder
    `;//other.example.org/:_authToken=${token}`,              // 5 commented
    'strict-ssl=false',                                       // 6 MEDIUM
    'registry=http://registry.corp-mirror.net/',              // 7 MEDIUM
    '@acme:registry=http://localhost:4873/',                  // 8 local ok
    '@acme2:registry=https://npm.pkg.github.com/',            // 9 https ok
    'registry=http://10.0.2.2:4873/',                         // 10 private ok
    'save-exact=true',                                        // 11
  ].join('\n');
  const r = scan(gitProject({ '.npmrc': npmrc }));
  assert.deepEqual(where(r, 'NPM_REGISTRY_CONFIG_INSECURE'), ['.npmrc:2:HIGH:high', '.npmrc:6:MEDIUM:high', '.npmrc:7:MEDIUM:high']);
  assert.ok(!JSON.stringify(r.findings).includes(token));
});

test('NPM_REGISTRY_CONFIG_INSECURE: .yarnrc.yml', () => {
  const token = randomBytes(18).toString('hex');
  const yarnrc = [
    'nodeLinker: node-modules',                       // 1
    'enableStrictSsl: false',                         // 2 MEDIUM
    'npmRegistryServer: "http://registry.corp-mirror.net"', // 3 MEDIUM
    'npmRegistries:',                                 // 4
    '  "//registry.npmjs.org":',                      // 5
    `    npmAuthToken: ${token}`,                     // 6 HIGH
    '  "//npm.pkg.github.com":',                      // 7
    '    npmAuthToken: "${NPM_TOKEN:-}"',             // 8 env ok
    '    npmAuthIdent: "${NPM_IDENT}"',               // 9 env ok
    'unsafeHttpWhitelist:',                           // 10
    '  - localhost',                                  // 11 ok
    '  - "*.corp.example.net"',                       // 12 MEDIUM
    '# enableStrictSsl: false',                       // 13
  ].join('\n');
  const r = scan(gitProject({ '.yarnrc.yml': yarnrc }));
  const got = byRule(r, 'NPM_REGISTRY_CONFIG_INSECURE').map(f => `${f.line}:${f.severity}:${f.confidence}`).sort();
  assert.deepEqual(got, ['12:MEDIUM:high', '2:MEDIUM:high', '3:MEDIUM:high', '6:HIGH:high']);
  assert.ok(!JSON.stringify(r.findings).includes(token));
});

test('NPM_REGISTRY_CONFIG_INSECURE: untracked .npmrc is not reported', () => {
  const r = scan(untrackedProject({ '.npmrc': 'strict-ssl=false\n' }));
  assert.deepEqual(byRule(r, 'NPM_REGISTRY_CONFIG_INSECURE'), []);
});

test('COMMITTED_CREDENTIAL_FILE: tracked keystores/certs/profiles', () => {
  const files = {
    'android/app/upload.jks': randomBytes(64),
    'android/app/release.keystore': randomBytes(64),
    'android/app/debug.keystore': randomBytes(64),
    'ios/cert.p12': randomBytes(64),
    'ios/AuthKey_ABC.p8': randomBytes(64),
    'ios/profile.mobileprovision': randomBytes(64),
  };
  const r = scan(gitProject(files));
  const got = byRule(r, 'COMMITTED_CREDENTIAL_FILE').map(f => `${f.filePath.split('/').pop()}:${f.line}:${f.severity}:${f.confidence}`).sort();
  assert.deepEqual(got, [
    'AuthKey_ABC.p8:1:HIGH:high',
    'cert.p12:1:HIGH:high',
    'profile.mobileprovision:1:MEDIUM:high',
    'release.keystore:1:HIGH:high',
    'upload.jks:1:HIGH:high',
  ]);
});

test('COMMITTED_CREDENTIAL_FILE: untracked keystore is not reported', () => {
  const r = scan(untrackedProject({ 'android/app/upload.jks': randomBytes(64) }));
  assert.deepEqual(byRule(r, 'COMMITTED_CREDENTIAL_FILE'), []);
});

test('COMMITTED_CREDENTIAL_FILE: service-account JSON reported once on the private_key line', () => {
  const fakeKey = '-----BEGIN ' + 'PRIVATE KEY-----\n' + randomBytes(120).toString('base64').replace(/(.{64})/g, '$1\n') + '\n-----END ' + 'PRIVATE KEY-----\n';
  const sa = JSON.stringify({
    type: 'service_account',
    project_id: 'demo-app',
    private_key_id: randomBytes(20).toString('hex'),
    private_key: fakeKey,
    client_email: 'firebase-adminsdk-x@demo-app.iam.gserviceaccount.com',
  }, null, 2);
  const lineOfKey = sa.split('\n').findIndex(l => l.includes('"private_key"')) + 1;
  const noKey = JSON.stringify({ type: 'service_account', project_id: 'demo-app', private_key: '' }, null, 2);
  const notSa = JSON.stringify({ type: 'authorized_user', private_key: fakeKey }, null, 2);
  const r = scan(gitProject({
    'config/firebase-adminsdk-abc.json': sa,
    'config/play-service-account-empty.json': noKey,
    'config/google-play-other.json': notSa,
    'android/app/google-services.json': JSON.stringify({ project_info: { project_id: 'demo-app' }, client: [] }),
  }));
  const hits = byRule(r, 'COMMITTED_CREDENTIAL_FILE');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].line, lineOfKey);
  assert.equal(hits[0].severity, 'HIGH');
  assert.equal(hits[0].confidence, 'high');
  assert.match(hits[0].filePath, /firebase-adminsdk-abc\.json$/);
  // same line must not also carry an API_KEY_EXPOSED / HARDCODED_SECRETS finding
  const sameLine = r.findings.filter(f => f.filePath === hits[0].filePath && f.line === lineOfKey);
  assert.deepEqual(sameLine.map(f => f.ruleId), ['COMMITTED_CREDENTIAL_FILE']);
});
