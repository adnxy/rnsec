import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { scan, byRule, repoRoot, casesDir, untrackedProject, fakeSecret } from './helpers.mjs';

const bin = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');
const run = (args, opts = {}) =>
  spawnSync('node', [bin, 'scan', ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' }, ...opts });
const scratch = () => mkdtempSync(join(tmpdir(), 'rnsec-ci-'));

// One MEDIUM finding (http URL) and, optionally, one HIGH finding (hardcoded key)
const medium = "const a = 1;\nfetch('http://api.example.com/plain', { timeout: 5 });\n";
const high = `const config = {\n  stripeKey: '${fakeSecret('stripe_live')}',\n};\n`;

test('--fail-on: default high, medium/low thresholds, none, invalid', () => {
  const dir = untrackedProject({ 'src/a.js': medium });
  assert.equal(run(['-p', dir, '--json']).status, 0, 'MEDIUM only: default stays green');
  assert.equal(run(['-p', dir, '--json', '--fail-on', 'medium']).status, 1);
  assert.equal(run(['-p', dir, '--json', '--fail-on', 'low']).status, 1);
  const h = untrackedProject({ 'src/a.js': high });
  assert.equal(run(['-p', h, '--json']).status, 1, 'HIGH fails by default');
  assert.equal(run(['-p', h, '--json', '--fail-on', 'none']).status, 0);
  const bad = run(['-p', dir, '--json', '--fail-on', 'bogus']);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /--fail-on must be high, medium, low or none/);
});

test('config failOn applies, and the CLI flag beats it', () => {
  const dir = untrackedProject({ 'src/a.js': medium, '.rnsec.json': '{ "failOn": "medium" }' });
  assert.equal(run(['-p', dir, '--json']).status, 1);
  assert.equal(run(['-p', dir, '--json', '--fail-on', 'none']).status, 0);
  const bad = untrackedProject({ 'src/a.js': medium, '.rnsec.json': '{ "failOn": "nope" }' });
  assert.match(run(['-p', bad, '--json']).stderr, /"failOn" in the config must be/);
});

test('severityOverrides change severity in output and exit code', () => {
  const dir = untrackedProject({
    'src/a.js': medium,
    '.rnsec.json': '{ "severityOverrides": { "INSECURE_HTTP_URL": "HIGH", "NOT_A_RULE": "LOW" } }',
  });
  const r = scan(dir);
  assert.ok(byRule(r, 'INSECURE_HTTP_URL').every(f => f.severity === 'HIGH'));
  assert.equal(r.exitCode, 1);
  const p = run(['-p', dir, '--json']);
  assert.match(p.stderr, /unknown rule id\(s\): NOT_A_RULE/);
  assert.equal((p.stderr.match(/unknown rule id/g) ?? []).length, 1);

  const down = untrackedProject({ 'src/a.js': high, '.rnsec.json': '{ "severityOverrides": { "API_KEY_EXPOSED": "LOW" } }' });
  const d = scan(down);
  assert.ok(byRule(d, 'API_KEY_EXPOSED').every(f => f.severity === 'LOW'));
  assert.equal(d.exitCode, 0, 'downgraded finding no longer fails the build');

  const invalid = untrackedProject({ 'src/a.js': medium, '.rnsec.json': '{ "severityOverrides": { "INSECURE_HTTP_URL": "CRITICAL" } }' });
  const bad = run(['-p', invalid, '--json']);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /severityOverrides\["INSECURE_HTTP_URL"\] must be HIGH, MEDIUM or LOW/);
});

test('findings carry a stable fingerprint in JSON output', () => {
  const dir = untrackedProject({ 'src/a.js': medium });
  const a = scan(dir).findings.map(f => f.fingerprint);
  const b = scan(dir).findings.map(f => f.fingerprint);
  assert.ok(a.length > 0 && a.every(f => /^[0-9a-f]{64}$/.test(f)));
  assert.deepEqual(a, b);
});

test('identical lines in one file get distinct fingerprints', () => {
  const line = "fetch('http://api.example.com/plain', { timeout: 5 });\n";
  const dir = untrackedProject({ 'src/a.js': line + line });
  const fps = byRule(scan(dir), 'INSECURE_HTTP_URL').map(f => f.fingerprint);
  assert.equal(fps.length, 2);
  assert.equal(new Set(fps).size, 2);
});

test('baseline: finding stays baselined after lines are inserted above; new findings are reported', () => {
  const dir = untrackedProject({ 'src/a.js': medium });
  const baseline = join(scratch(), 'baseline.json');
  const w = run(['-p', dir, '--json', '--write-baseline', baseline, '--fail-on', 'low']);
  assert.equal(w.status, 0, 'write-baseline always exits 0');
  const written = JSON.parse(readFileSync(baseline, 'utf8'));
  assert.equal(written.version, 1);
  assert.equal(written.tool, 'rnsec');
  assert.ok(written.generatedAt);
  const entry = written.findings.find(f => f.ruleId === 'INSECURE_HTTP_URL');
  assert.equal(entry.file, 'src/a.js');
  assert.equal(entry.line, 2);
  assert.ok(entry.fingerprint && entry.description);

  // Move the code down, add an unrelated new violation elsewhere
  writeFileSync(join(dir, 'src/a.js'), '// one\n// two\n// three\n' + medium);
  writeFileSync(join(dir, 'src/b.js'), "fetch('http://other.example.com/new', { timeout: 5 });\n");
  const p = run(['-p', dir, '--json', '--baseline', baseline]);
  const result = JSON.parse(p.stdout);
  const http = byRule(result, 'INSECURE_HTTP_URL');
  assert.equal(http.length, 1, 'only the new finding remains');
  assert.match(http[0].filePath, /src\/b\.js$/);
  assert.equal(result.baselinedCount, 1);
  assert.match(p.stderr, /1 finding\(s\) hidden by baseline/);
});

test('baseline: exit code is computed after filtering; config baseline key works', () => {
  const dir = untrackedProject({ 'src/a.js': high });
  const baseline = join(dir, 'rnsec-baseline.json');
  assert.equal(run(['-p', dir, '--json']).status, 1);
  run(['-p', dir, '--json', '--write-baseline', baseline]);
  assert.equal(run(['-p', dir, '--json', '--baseline', baseline]).status, 0);
  writeFileSync(join(dir, '.rnsec.json'), '{ "baseline": "rnsec-baseline.json" }');
  const r = run(['-p', dir, '--json']);
  assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout).findings.filter(f => f.ruleId === 'API_KEY_EXPOSED'), []);
});

test('baseline: missing or invalid file is a clear error', () => {
  const dir = untrackedProject({ 'src/a.js': medium });
  const missing = run(['-p', dir, '--json', '--baseline', join(scratch(), 'nope.json')]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /Could not read baseline/);
  const bogus = join(scratch(), 'bogus.json');
  writeFileSync(bogus, '{"hello":1}');
  assert.match(run(['-p', dir, '--json', '--baseline', bogus]).stderr, /not a valid rnsec baseline/);
});

// ---- SARIF ----

const sarifRun = (dir, args = []) => {
  const out = join(scratch(), 'out.sarif');
  const r = run(['-p', dir, '--json', '--sarif', out, ...args]);
  return { sarif: JSON.parse(readFileSync(out, 'utf8')), json: JSON.parse(r.stdout), proc: r };
};

test('SARIF: top-level structure and tool driver', () => {
  const { sarif } = sarifRun(untrackedProject({ 'src/a.js': medium }));
  assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.equal(sarif.version, '2.1.0');
  const run0 = sarif.runs[0];
  const driver = run0.tool.driver;
  assert.equal(driver.name, 'rnsec');
  assert.match(driver.semanticVersion, /^\d+\.\d+\.\d+/);
  assert.equal(driver.version, driver.semanticVersion);
  assert.equal(driver.informationUri, 'https://github.com/adnxy/rnsec');
  assert.deepEqual(run0.invocations, [{ executionSuccessful: true }]);
  assert.match(run0.originalUriBaseIds['%SRCROOT%'].uri, /^file:\/\/\/.*\/$/);
});

test('SARIF: rules are complete, unique, and well-formed', () => {
  const { sarif } = sarifRun(untrackedProject({ 'src/a.js': medium }));
  const rules = sarif.runs[0].tool.driver.rules;
  assert.ok(rules.length > 50, 'every registered rule is emitted');
  assert.equal(new Set(rules.map(r => r.id)).size, rules.length);
  const levels = { error: '8.0', warning: '5.5', note: '3.0' };
  for (const r of rules) {
    assert.ok(r.name.length > 0 && r.name.length <= 255);
    assert.match(r.name, /^[A-Za-z0-9]+$/);
    assert.ok(r.shortDescription.text.length <= 1024 && r.fullDescription.text.length <= 1024);
    assert.ok(r.help.text && r.help.markdown);
    assert.ok(r.properties.tags.includes('security'));
    assert.ok(r.properties.precision);
    assert.equal(r.properties['security-severity'], levels[r.defaultConfiguration.level]);
    assert.equal(typeof r.properties['security-severity'], 'string');
  }
  const http = rules.find(r => r.id === 'INSECURE_HTTP_URL');
  assert.equal(http.name, 'InsecureHttpUrl');
});

test('SARIF: results point at the right rule, with relative URIs, levels and fingerprints', () => {
  const dir = untrackedProject({ 'src/a.js': medium + high });
  const { sarif, json } = sarifRun(dir);
  const rules = sarif.runs[0].tool.driver.rules;
  const results = sarif.runs[0].results;
  assert.equal(results.length, json.findings.length);
  const levelOf = { HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };
  results.forEach((res, i) => {
    assert.equal(rules[res.ruleIndex].id, res.ruleId);
    const f = json.findings[i];
    assert.equal(res.level, levelOf[f.severity]);
    const loc = res.locations[0].physicalLocation;
    assert.equal(loc.artifactLocation.uri, 'src/a.js');
    assert.equal(loc.artifactLocation.uriBaseId, '%SRCROOT%');
    assert.equal(loc.region.startLine, f.line);
    assert.ok(loc.region.startColumn >= 1);
    assert.equal(res.partialFingerprints['rnsec/v1'], f.fingerprint);
    assert.ok(!('primaryLocationLineHash' in res.partialFingerprints));
    assert.ok(res.properties.confidence);
    assert.ok(res.message.text.startsWith(f.description));
  });
  assert.ok(results.some(r => r.level === 'error') && results.some(r => r.level === 'warning'));
});

test('SARIF: severity overrides are reflected in result levels and rule defaults', () => {
  const dir = untrackedProject({ 'src/a.js': medium, '.rnsec.json': '{ "severityOverrides": { "INSECURE_HTTP_URL": "LOW" } }' });
  const { sarif } = sarifRun(dir);
  const rule = sarif.runs[0].tool.driver.rules.find(r => r.id === 'INSECURE_HTTP_URL');
  assert.equal(rule.defaultConfiguration.level, 'note');
  assert.equal(rule.properties['security-severity'], '3.0');
  assert.ok(sarif.runs[0].results.filter(r => r.ruleId === 'INSECURE_HTTP_URL').every(r => r.level === 'note'));
});

test('SARIF: project-level findings get line 1 / column 1', () => {
  const { sarif, json } = sarifRun(join(casesDir, 'rnc-ios-pos'));
  const projectLevel = json.findings.find(f => f.line === undefined);
  assert.ok(projectLevel, 'fixture should yield a finding without a line');
  const res = sarif.runs[0].results.find(r => r.partialFingerprints['rnsec/v1'] === projectLevel.fingerprint);
  const region = res.locations[0].physicalLocation.region;
  assert.equal(region.startLine, 1);
  assert.equal(region.startColumn, 1);
});

test('SARIF: scanning a subdirectory of a git repo yields repo-root-relative URIs', () => {
  const dir = untrackedProject({ 'apps/mobile/src/a.js': medium });
  const { sarif } = sarifRun(join(dir, 'apps/mobile'));
  const uris = sarif.runs[0].results.map(r => r.locations[0].physicalLocation.artifactLocation.uri);
  assert.ok(uris.length > 0);
  assert.ok(uris.every(u => u === 'apps/mobile/src/a.js'), uris.join(','));
  const base = sarif.runs[0].originalUriBaseIds['%SRCROOT%'].uri;
  assert.equal(base, pathToFileURL(realRoot(dir)).href + '/');
});

test('SARIF: outside git, URIs are relative to the scan root', () => {
  const dir = scratch();
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src/a.js'), medium);
  const { sarif } = sarifRun(dir);
  const uris = sarif.runs[0].results.map(r => r.locations[0].physicalLocation.artifactLocation.uri);
  assert.ok(uris.length > 0 && uris.every(u => u === 'src/a.js'), uris.join(','));
});

test('SARIF: long descriptions and names are truncated to GitHub limits', async () => {
  const { SarifReporter } = await import(pathToFileURL(resolve(repoRoot, 'dist/core/sarifReporter.js')).href);
  const long = 'x'.repeat(5000);
  const rule = { id: 'A'.repeat(400).split('').join('_'), description: long, severity: 'LOW', fileTypes: [] };
  const sarif = new SarifReporter().generate([], [rule], { repoRoot: tmpdir() });
  const r = sarif.runs[0].tool.driver.rules[0];
  assert.ok(r.name.length <= 255);
  assert.ok(r.shortDescription.text.length <= 1024);
  assert.ok(r.fullDescription.text.length <= 1024);
  assert.ok(r.help.text.length <= 1024);
});

test('--sarif does not disturb pure-JSON stdout', () => {
  const dir = untrackedProject({ 'src/a.js': medium });
  const out = join(scratch(), 'x.sarif');
  const r = run(['-p', dir, '--json', '--sarif', out, '--baseline', join(scratch(), 'none.json')]);
  assert.equal(r.status, 1);
  const ok = run(['-p', dir, '--json', '--sarif', out]);
  assert.doesNotThrow(() => JSON.parse(ok.stdout));
});

test('no ExperimentalWarning about JSON modules on stderr', () => {
  const r = spawnSync('node', [bin, '--version'], { encoding: 'utf8' });
  assert.doesNotMatch(r.stdout + r.stderr, /Importing JSON modules/);
});

import { realpathSync } from 'node:fs';
function realRoot(dir) {
  return realpathSync(dir);
}
