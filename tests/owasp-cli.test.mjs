import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot, untrackedProject, gitProject } from './helpers.mjs';

const bin = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');
const rnsec = (args, opts = {}) =>
  spawnSync('node', [bin, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' }, maxBuffer: 64 * 1024 * 1024, ...opts });
const scan = (args, opts) => rnsec(['scan', ...args], opts);
const scratch = () => mkdtempSync(join(tmpdir(), 'rnsec-owasp-'));
const load = async file => import(pathToFileURL(resolve(repoRoot, 'dist', file)).href);
/** Drops the two fields that legitimately differ between runs */
const stable = result => ({ ...result, timestamp: undefined, duration: undefined });

const { RULE_STANDARDS } = await load('standards/owasp/mappings.js');
const { buildCoverage, detectProjectPlatforms } = await load('standards/owasp/coverage.js');
const { loadOwaspSnapshot } = await load('standards/owasp/snapshot.js');
const CONTROLS = Object.keys(loadOwaspSnapshot().masvs.controls);

const MANIFEST = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <application android:label="App" android:allowBackup="true"></application>
</manifest>
`;
const PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
</dict></plist>
`;
const TOKEN = "import AsyncStorage from '@react-native-async-storage/async-storage';\nAsyncStorage.setItem('authToken', token);\n";

/** Small Expo + native project: AsyncStorage token (HIGH), allowBackup, ATS off */
const project = (extra = {}) =>
  untrackedProject({
    'package.json': JSON.stringify({ name: 'demo', dependencies: { expo: '51.0.0', 'react-native': '0.74.0' } }),
    'app.json': JSON.stringify({ expo: { name: 'demo', slug: 'demo' } }),
    'android/app/src/main/AndroidManifest.xml': MANIFEST,
    'ios/App/Info.plist': PLIST,
    'src/auth.js': TOKEN,
    ...extra,
  });

const json = (dir, args = []) => {
  const r = scan(['-p', dir, '--json', ...args]);
  return { ...JSON.parse(r.stdout), exitCode: r.status };
};

// A MASVS-claim of success must never appear, in any output
const VERDICT = /(MASVS[^\n]*(compliant|passed))|((compliant|passed)[^\n]*MASVS)/i;

// ---- --owasp JSON ----

test('--owasp adds standards, rule title/platform and a coverage section; default JSON stays unchanged', () => {
  const dir = project();
  const plain = json(dir);
  assert.equal(plain.owasp, undefined);
  for (const f of plain.findings) {
    assert.ok(!('standards' in f) && !('title' in f) && !('platform' in f), `${f.ruleId} has OWASP fields without --owasp`);
  }

  const r = json(dir, ['--owasp']);
  assert.deepEqual(r.findings.map(f => f.ruleId), plain.findings.map(f => f.ruleId));
  const f = r.findings.find(x => x.ruleId === 'ASYNCSTORAGE_SENSITIVE_KEY');
  assert.equal(f.title, RULE_STANDARDS.ASYNCSTORAGE_SENSITIVE_KEY.title);
  assert.deepEqual(f.platform, RULE_STANDARDS.ASYNCSTORAGE_SENSITIVE_KEY.platform);
  assert.deepEqual(f.standards.masvs, RULE_STANDARDS.ASYNCSTORAGE_SENSITIVE_KEY.masvs);
  assert.ok(f.standards.maswe.includes('MASWE-0001'));
  assert.ok(Array.isArray(f.standards.mastg) && Array.isArray(f.standards.cwe));
  assert.ok(['high', 'medium', 'low'].includes(f.standards.confidence));

  const o = r.owasp;
  assert.equal(o.standards.masvs, '2.1.0');
  assert.equal(o.standards.maswe, '1.0.0');
  assert.ok(o.standards.mastg);
  assert.equal(o.scope, 'project');
  assert.equal(o.controls.length, 24);
  assert.deepEqual(o.controls.map(c => c.id), [...CONTROLS].sort());
  const s = o.summary;
  assert.equal(s.controls, 24);
  assert.equal(s.failed + s.checked + s.checkedHeuristic + s.notApplicable + s.notAssessed, 24);
  assert.ok(s.automatedRules > 50);
  assert.match(o.disclaimer, /does not establish MASVS compliance/);
  assert.doesNotMatch(JSON.stringify(o), VERDICT);
  assert.doesNotMatch(JSON.stringify(o), /(\/Users\/|\/var\/|\/tmp\/)/, 'no absolute paths in the owasp section');
});

test('config "owasp": true behaves like --owasp; a non-boolean is a usage error', () => {
  const r = json(project({ '.rnsec.json': '{ "owasp": true }' }));
  assert.ok(r.owasp);
  assert.ok(r.findings.some(f => f.standards));
  const bad = scan(['-p', project({ '.rnsec.json': '{ "owasp": "yes" }' }), '--json']);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /"owasp" in the config must be true or false/);
});

test('coverage: failed where a finding maps, not-assessed where no rule does, rule ids per control', () => {
  const r = json(project(), ['--owasp']);
  const byId = Object.fromEntries(r.owasp.controls.map(c => [c.id, c]));
  const mappedControls = new Set(Object.values(RULE_STANDARDS).flatMap(s => s.masvs));
  const unmapped = CONTROLS.filter(c => !mappedControls.has(c));
  assert.ok(unmapped.length > 0, 'some MASVS controls have no automated rule');
  for (const id of unmapped) {
    assert.equal(byId[id].status, 'not-assessed', id);
    assert.deepEqual(byId[id].rules, []);
  }
  for (const id of ['MASVS-STORAGE-1', 'MASVS-NETWORK-1']) {
    assert.equal(byId[id].status, 'failed', id);
    assert.ok(byId[id].findings > 0 && byId[id].rules.length > 0);
  }
  assert.ok(byId['MASVS-STORAGE-1'].rules.includes('ASYNCSTORAGE_SENSITIVE_KEY'));
  assert.ok(r.owasp.controls.some(c => c.status === 'checked'));
  // a control is failed exactly when a reported finding maps to it
  const failed = new Set(r.findings.flatMap(f => f.standards?.masvs ?? []));
  for (const c of r.owasp.controls) assert.equal(c.status === 'failed', failed.has(c.id), c.id);
});

test('coverage: ignoredRules turn a control into not-assessed', () => {
  const perControl = {};
  for (const [id, s] of Object.entries(RULE_STANDARDS)) for (const c of s.masvs) (perControl[c] ??= []).push(id);
  const [control, [rule]] = Object.entries(perControl).find(([, rules]) => rules.length === 1);
  const dir = project({ '.rnsec.json': JSON.stringify({ ignoredRules: [rule] }) });
  const c = json(dir, ['--owasp']).owasp.controls.find(x => x.id === control);
  assert.equal(c.status, 'not-assessed');
  assert.ok(!c.rules.includes(rule));
});

test('coverage: --changed-files is labelled as a partial scan', () => {
  const dir = gitProject({ 'src/auth.js': TOKEN });
  const r = json(dir, ['--owasp', '--changed-files', 'HEAD']);
  assert.equal(r.owasp.scope, 'changed-files');
  assert.match(r.owasp.disclaimer, /only the changed files/);
});

test('buildCoverage: heuristic, not-applicable, hidden-by-min-confidence and scope', () => {
  const lowRule = Object.entries(RULE_STANDARDS).find(([, s]) => s.confidence === 'low' && s.platform.includes('cross-platform'))[0];
  const lowControl = RULE_STANDARDS[lowRule].masvs[0];
  const base = { findings: [], platforms: { android: true, ios: true, expo: true } };
  const row = (input, id) => buildCoverage({ ...base, ...input }).controls.find(c => c.id === id);

  assert.equal(row({ ranRuleIds: [lowRule] }, lowControl).status, 'checked-heuristic');
  assert.equal(row({ ranRuleIds: [lowRule], hiddenRuleIds: [lowRule] }, lowControl).status, 'not-assessed');
  assert.equal(row({ ranRuleIds: [] }, lowControl).status, 'not-assessed');

  const android = 'ANDROID_BACKUP_ALLOWED';
  const androidControl = RULE_STANDARDS[android].masvs[0];
  assert.deepEqual(RULE_STANDARDS[android].platform, ['android']);
  const iosOnly = { android: false, ios: true, expo: false };
  const na = row({ ranRuleIds: [android], platforms: iosOnly }, androidControl);
  assert.equal(na.status, 'not-applicable');
  assert.deepEqual(na.rules, [android]);
  assert.equal(buildCoverage({ ...base, ranRuleIds: [android], platforms: iosOnly }).summary.automatedRules, 0);
  assert.equal(row({ ranRuleIds: [android] }, androidControl).status, 'checked');
  // a finding always wins over not-applicable
  const finding = { ruleId: android, severity: 'MEDIUM', description: 'x', filePath: 'x' };
  assert.equal(row({ ranRuleIds: [android], findings: [finding], platforms: iosOnly }, androidControl).status, 'failed');

  assert.equal(buildCoverage({ ...base, ranRuleIds: [] }).scope, 'project');
  assert.equal(buildCoverage({ ...base, ranRuleIds: [], scope: 'changed-files' }).scope, 'changed-files');
});

test('detectProjectPlatforms: native dirs, Expo config, no signal', () => {
  const dir = files => untrackedProject(files);
  assert.deepEqual(detectProjectPlatforms(dir({ 'ios/App/Info.plist': PLIST })), { android: false, ios: true, expo: false });
  assert.deepEqual(detectProjectPlatforms(dir({ 'android/build.gradle': '' })), { android: true, ios: false, expo: false });
  assert.deepEqual(detectProjectPlatforms(dir({ 'app.json': '{"expo":{"name":"x"}}' })), { android: true, ios: true, expo: true });
  assert.deepEqual(detectProjectPlatforms(dir({ 'app.json': '{"expo":{"platforms":["ios"]}}' })), { android: false, ios: true, expo: true });
  assert.deepEqual(detectProjectPlatforms(dir({ 'src/a.js': '' })), { android: true, ios: true, expo: true }, 'no signal: nothing is claimed absent');
});

// ---- console ----

test('console --owasp: refs per finding, coverage after the findings, no compliance verdict', () => {
  const cwd = scratch();
  const r = scan(['-p', project(), '--owasp'], { cwd });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /OWASP: MASVS-[A-Z0-9-]+(?: · MASVS-[A-Z0-9-]+)* · MASWE-0001 · /);
  const at = r.stdout.indexOf('OWASP MASVS 2.1.0 coverage');
  assert.ok(at > r.stdout.indexOf('SCAN SUMMARY'), 'coverage comes after the findings and summary');
  assert.match(r.stdout, /Static analysis does not establish MASVS compliance/);
  assert.match(r.stdout, /MASVS-STORAGE-1\s+FAILED/);
  assert.match(r.stdout, /not assessed/);
  assert.doesNotMatch(r.stdout, VERDICT);

  const clean = untrackedProject({ 'package.json': '{"name":"x"}', 'src/a.js': 'export const a = 1;\n' });
  const c = scan(['-p', clean, '--owasp'], { cwd });
  assert.equal(c.status, 0);
  assert.match(c.stdout, /OWASP MASVS 2\.1\.0 coverage/);
  assert.doesNotMatch(c.stdout, VERDICT);
  assert.doesNotMatch(c.stdout, /passed all/, 'no verdict line next to the MASVS section');

  const plain = scan(['-p', project()], { cwd });
  assert.doesNotMatch(plain.stdout, /OWASP/);
});

// ---- --format ----

test('--format sarif: stdout is pure SARIF, notes go to stderr, no report files, same text as --sarif <file>', () => {
  const cwd = scratch();
  const file = join(scratch(), 'out.sarif');
  const dir = project({ '.rnsec.json': '{ "ignoredRules": ["NO_REQUEST_TIMEOUT"] }' });
  const r = scan(['-p', dir, '--format', 'sarif', '--sarif', file], { cwd });
  assert.equal(r.status, 1);
  const sarif = JSON.parse(r.stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.match(r.stderr, /Ignoring 1 rule/);
  assert.doesNotMatch(r.stdout, /Ignoring|rnsec-report|SCAN SUMMARY/);
  assert.equal(readFileSync(file, 'utf8'), r.stdout, 'file and stdout carry the same document');
  assert.deepEqual(readdirSync(cwd), [], 'no default HTML/JSON report written');
  assert.ok(sarif.runs[0].results.length > 0);
});

test('--format json equals --json; console is the default; bad values exit 2', () => {
  const dir = project();
  const a = JSON.parse(scan(['-p', dir, '--json']).stdout);
  const b = JSON.parse(scan(['-p', dir, '--format', 'json']).stdout);
  assert.deepEqual(stable(b), stable(a));
  assert.match(scan(['-p', dir, '--format', 'console'], { cwd: scratch() }).stdout, /SCAN SUMMARY/);

  const bad = scan(['-p', dir, '--format', 'xml']);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /--format must be json, sarif or console/);
  const clash = scan(['-p', dir, '--json', '--format', 'sarif']);
  assert.equal(clash.status, 2);
  assert.match(clash.stderr, /cannot be combined/);
});

// ---- SARIF content ----

const sarifOf = (dir, args = []) => JSON.parse(scan(['-p', dir, '--format', 'sarif', ...args]).stdout);

test('SARIF 2.1.0 structure: required properties, valid indexes and enums', () => {
  const sarif = sarifOf(project());
  assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.equal(sarif.version, '2.1.0');
  assert.ok(Array.isArray(sarif.runs) && sarif.runs.length === 1);
  const run = sarif.runs[0];
  const driver = run.tool.driver;
  assert.equal(typeof driver.name, 'string');
  const rules = driver.rules;
  assert.equal(new Set(rules.map(r => r.id)).size, rules.length);
  const LEVELS = ['none', 'note', 'warning', 'error'];
  for (const r of rules) {
    assert.equal(typeof r.id, 'string');
    assert.ok(LEVELS.includes(r.defaultConfiguration.level));
    assert.ok(r.properties.tags.every(t => typeof t === 'string'));
    if (r.helpUri !== undefined) assert.match(r.helpUri, /^https:\/\/mas\.owasp\.org\//);
  }
  for (const res of run.results) {
    assert.equal(rules[res.ruleIndex].id, res.ruleId);
    assert.ok(LEVELS.includes(res.level));
    assert.equal(typeof res.message.text, 'string');
    const loc = res.locations[0].physicalLocation;
    assert.equal(typeof loc.artifactLocation.uri, 'string');
    assert.ok(Number.isInteger(loc.region.startLine) && loc.region.startLine >= 1);
  }
  assert.ok(run.originalUriBaseIds['%SRCROOT%'].uri.endsWith('/'));
  assert.doesNotMatch(JSON.stringify(sarif), /"timestamp"|startTimeUtc|endTimeUtc/, 'no timestamps');
});

test('SARIF: tags, helpUri, MASVS taxonomy and relationships come from the mapping (with and without --owasp)', () => {
  for (const args of [[], ['--owasp']]) {
    const run = sarifOf(project(), args).runs[0];
    const rule = run.tool.driver.rules.find(r => r.id === 'ASYNCSTORAGE_SENSITIVE_KEY');
    const s = RULE_STANDARDS.ASYNCSTORAGE_SENSITIVE_KEY;
    const expected = ['security', ...s.masvs, ...s.maswe, ...s.mastg, ...s.cwe.map(n => `external/cwe/cwe-${n}`)];
    assert.deepEqual(rule.properties.tags, expected);
    assert.ok(!rule.properties.tags.includes('react-native'));
    assert.equal(rule.helpUri, 'https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/');
    assert.equal(rule.properties.precision, 'medium');

    assert.equal(run.taxonomies.length, 1);
    const tax = run.taxonomies[0];
    assert.equal(tax.name, 'OWASP MASVS');
    assert.equal(tax.version, '2.1.0');
    assert.equal(tax.organization, 'OWASP');
    assert.match(tax.downloadUri, /^https:\/\/github\.com\/OWASP\/masvs\/releases\//);
    const taxa = tax.taxa.map(t => t.id);
    assert.deepEqual(taxa, [...taxa].sort());
    assert.ok(tax.taxa.every(t => t.shortDescription.text && t.helpUri));
    const rels = run.tool.driver.rules.flatMap(r => r.relationships ?? []);
    assert.ok(rels.length > 50);
    for (const rel of rels) {
      assert.deepEqual(rel.kinds, ['relevant']);
      assert.equal(rel.target.toolComponent.name, 'OWASP MASVS');
      assert.equal(taxa[rel.target.index], rel.target.id, 'relationship target exists in the taxa');
    }
    assert.deepEqual(rule.relationships.map(r => r.target.id), s.masvs);
    const unmapped = run.tool.driver.rules.find(r => r.id === 'HARDCODED_IP_ADDRESS');
    assert.deepEqual(unmapped.properties.tags, ['security']);
    assert.equal(unmapped.relationships, undefined);
    assert.equal(unmapped.helpUri, undefined);
  }
});

test('SARIF: critical maps to level error and security-severity 9.5', () => {
  const dir = project({ '.rnsec.json': '{ "severityOverrides": { "ASYNCSTORAGE_SENSITIVE_KEY": "CRITICAL" } }' });
  const run = sarifOf(dir).runs[0];
  const rule = run.tool.driver.rules.find(r => r.id === 'ASYNCSTORAGE_SENSITIVE_KEY');
  assert.equal(rule.defaultConfiguration.level, 'error');
  assert.equal(rule.properties['security-severity'], '9.5');
  const res = run.results.find(r => r.ruleId === 'ASYNCSTORAGE_SENSITIVE_KEY');
  assert.equal(res.level, 'error');
});

// ---- critical severity and exit codes ----

test('--fail-on critical|high|none and the critical override', () => {
  const dir = project(); // HIGH finding present, nothing critical
  assert.equal(scan(['-p', dir, '--json', '--fail-on', 'critical']).status, 0);
  assert.equal(scan(['-p', dir, '--json', '--fail-on', 'high']).status, 1);
  assert.equal(scan(['-p', dir, '--json']).status, 1, 'default fail-on is high');
  assert.equal(scan(['-p', dir, '--json', '--fail-on', 'none']).status, 0);

  const crit = project({ '.rnsec.json': '{ "severityOverrides": { "ASYNCSTORAGE_SENSITIVE_KEY": "critical" } }' });
  const r = json(crit);
  assert.equal(r.findings.find(f => f.ruleId === 'ASYNCSTORAGE_SENSITIVE_KEY').severity, 'CRITICAL');
  assert.equal(r.exitCode, 1, 'critical fails the default --fail-on high');
  assert.equal(scan(['-p', crit, '--json', '--fail-on', 'critical']).status, 1);
  assert.equal(scan(['-p', crit, '--json', '--fail-on', 'none']).status, 0);
  const viaConfig = project({ '.rnsec.json': '{ "failOn": "critical" }' });
  assert.equal(scan(['-p', viaConfig, '--json']).status, 0);
});

test('critical findings show in console, markdown and HTML summaries; a baseline hides them', () => {
  const dir = project({ '.rnsec.json': '{ "severityOverrides": { "ASYNCSTORAGE_SENSITIVE_KEY": "CRITICAL" } }' });
  const out = scratch();
  const md = join(out, 'r.md');
  const html = join(out, 'r.html');
  const r = scan(['-p', dir, '--md', md, '--html', html, '--output', join(out, 'r.json')], { cwd: out });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /CRITICAL SEVERITY - 1 ISSUE/);
  assert.match(r.stdout, /Critical:\s+1/);
  assert.match(r.stdout, /RISK LEVEL: CRITICAL/);
  assert.match(readFileSync(md, 'utf8'), /\| 🟣 Critical \| 1 \|/);
  assert.match(readFileSync(md, 'utf8'), /Critical Severity/);
  const page = readFileSync(html, 'utf8');
  assert.match(page, /summary-card critical/);
  assert.match(page, /severity-badge critical/);
  assert.equal(JSON.parse(readFileSync(join(out, 'r.json'), 'utf8')).findings.find(f => f.severity === 'CRITICAL').ruleId, 'ASYNCSTORAGE_SENSITIVE_KEY');

  const baseline = join(out, 'baseline.json');
  scan(['-p', dir, '--json', '--write-baseline', baseline]);
  const hidden = scan(['-p', dir, '--json', '--baseline', baseline, '--fail-on', 'critical']);
  assert.equal(hidden.status, 0);
  assert.equal(JSON.parse(hidden.stdout).findings.some(f => f.severity === 'CRITICAL'), false);
});

test('exit codes: 0 clean, 1 findings, 2 for usage and scan errors', () => {
  const clean = untrackedProject({ 'package.json': '{"name":"x"}', 'src/a.js': 'export const a = 1;\n' });
  assert.equal(scan(['-p', clean, '--json']).status, 0);
  assert.equal(scan(['-p', project(), '--json']).status, 1);
  for (const args of [
    ['scan', '-p', clean, '--bogus'],
    ['scan', '-p', clean, '--fail-on', 'bogus'],
    ['scan', '-p', clean, '--min-confidence', 'bogus'],
    ['scan', '-p', clean, '--format', 'bogus'],
    ['scan', '-p', clean, '--fail-on'],
    ['scan', '-p', clean, '--baseline', join(scratch(), 'missing.json')],
    ['scan', '-p', join(scratch(), 'no-such-dir')],
    ['nope'],
  ]) {
    assert.equal(rnsec(args).status, 2, args.join(' '));
  }
  assert.equal(rnsec(['--version']).status, 0);
  assert.equal(rnsec(['scan', '--help']).status, 0);
  assert.equal(rnsec(['rules']).status, 0);
});

// ---- rules --owasp ----

test('rules --owasp lists every rule with MASVS and MASWE ids', () => {
  const r = rnsec(['rules', '--owasp']);
  assert.equal(r.status, 0);
  const lines = r.stdout.split('\n');
  assert.match(lines[0], /^ID\s+SEVERITY\s+MASVS\s+MASWE\s+TITLE$/);
  const total = Number(rnsec(['rules']).stdout.match(/Total:\s*(\d+) security rules/)[1]);
  const rows = lines.slice(1).filter(l => /^[A-Z][A-Z0-9_]+\s/.test(l));
  assert.equal(rows.length, total);
  const row = id => rows.find(l => l.startsWith(id + ' ')).split(/\s+/);
  const backup = row('ANDROID_BACKUP_ALLOWED');
  assert.equal(backup[1], 'MEDIUM');
  assert.equal(backup[2], 'MASVS-STORAGE-2');
  assert.equal(backup[3], 'MASWE-0006');
  assert.deepEqual(row('HARDCODED_IP_ADDRESS').slice(2, 4), ['-', '-']);
  assert.deepEqual(rows.map(l => l.split(/\s+/)[0]), rows.map(l => l.split(/\s+/)[0]).sort());
  assert.equal(r.stdout, rnsec(['rules', '--owasp']).stdout, 'deterministic');
});

// ---- determinism ----

test('two runs give identical findings, owasp section and SARIF', () => {
  const dir = project();
  const a = json(dir, ['--owasp']);
  const b = json(dir, ['--owasp']);
  assert.deepEqual(stable(a), stable(b));
  const key = f => [f.filePath, f.line ?? 0, f.column ?? 0, f.ruleId];
  const sorted = [...a.findings].sort((x, y) => (JSON.stringify(key(x)) < JSON.stringify(key(y)) ? -1 : 1));
  assert.deepEqual(a.findings.map(f => f.fingerprint).length, sorted.length);
  for (let i = 1; i < a.findings.length; i++) {
    const [p, q] = [a.findings[i - 1], a.findings[i]];
    assert.ok(p.filePath < q.filePath || (p.filePath === q.filePath && (p.line ?? 0) <= (q.line ?? 0)), 'findings are sorted by file and line');
  }
  assert.equal(scan(['-p', dir, '--format', 'sarif']).stdout, scan(['-p', dir, '--format', 'sarif']).stdout);
});

// A reader that closes the pipe early (`| head`) is not a scan failure: no EPIPE stack trace, exit code unchanged
for (const format of ['json', 'sarif']) {
  test(`--format ${format}: reader closing stdout early exits quietly with the scan's own code`, async () => {
    const child = spawn('node', [bin, 'scan', '-p', join(repoRoot, 'tests', 'cases'), '--format', format], {
      env: { ...process.env, NO_COLOR: '1' },
    });
    let stderr = '';
    child.stderr.on('data', d => { stderr += d; });
    await new Promise(res => child.stdout.once('data', res));
    child.stdout.destroy();
    const code = await new Promise(res => child.on('close', res));
    assert.doesNotMatch(stderr, /EPIPE|at .*\(node:/);
    assert.ok(code === 0 || code === 1, `exit code ${code}`);
  });
}
