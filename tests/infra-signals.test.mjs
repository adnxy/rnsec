import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { isNonAppSourcePath, isGeneratedBundlePath, isGeneratedBundleContent } from '../dist/utils/pathFilters.js';
import { RuleEngine } from '../dist/core/ruleEngine.js';
import { gitProject } from './helpers.mjs';

test('isNonAppSourcePath: tooling folders and root-level config files', () => {
  const root = '/p';
  for (const f of ['scripts/a.js', 'src/script/a.js', 'detox/x.js', 'e2e/x.ts', 'tools/x.js', 'tooling/x.js', 'ci/x.js', '.github/w.js',
    'fastlane/Fastfile.js', '.circleci/c.js', 'src/__tests__/a.ts', 'babel.config.js', 'metro.config.cjs', 'jest.setup.js', 'jest.config.ts',
    'webpack.config.js', 'eslint.config.mjs', 'app.config.ts']) {
    assert.ok(isNonAppSourcePath(`${root}/${f}`, root), f);
  }
  for (const f of ['src/App.tsx', 'src/config.ts', 'src/utils/babel.config.js', 'index.js', 'src/tooltips/a.js']) {
    assert.ok(!isNonAppSourcePath(`${root}/${f}`, root), f);
  }
  // the scan root's own location does not matter
  assert.ok(!isNonAppSourcePath('/work/scripts/app/src/App.tsx', '/work/scripts/app'));
});

test('generated bundle predicates', () => {
  for (const f of ['android/app/src/main/res/raw/index.js', 'a/main.bundle.js', 'a/lib.min.js', 'a/vendorBundle.js']) {
    assert.ok(isGeneratedBundlePath(`/p/${f}`), f);
  }
  assert.ok(!isGeneratedBundlePath('/p/src/bundler.js'));
  assert.ok(isGeneratedBundleContent('x'.repeat(2500)));
  assert.ok(isGeneratedBundleContent('var a;\n/******/ (function(modules) { // webpackBootstrap\n'));
  assert.ok(isGeneratedBundleContent('__d(function(g,r,i,a,m,e,d){},0,[]);'));
  assert.ok(!isGeneratedBundleContent('const a = 1;\nconst b = 2;\n'));
});

async function runProbe(dir) {
  const seen = {};
  const engine = new RuleEngine();
  engine.registerRuleGroup({
    category: 'CONFIG',
    rules: [{ id: 'P', description: 'p', severity: 'LOW', fileTypes: ['.js'], apply: async c => ((seen[relative(dir, c.filePath)] = c), []) }],
  });
  await engine.runRulesOnProject(dir);
  return seen;
}

test('contexts carry isNonAppSource / isGeneratedBundle; files are still walked', async () => {
  const dir = gitProject(
    { 'src/App.js': 'const a = 1;\n', 'scripts/deploy.js': 'x', 'eslint.config.js': 'module.exports = {}', 'src/min.js': 'v'.repeat(2500), 'assets/app.bundle.js': 'x' },
    { commit: true }
  );
  const seen = await runProbe(dir);
  assert.equal(seen['src/App.js'].isNonAppSource, false);
  assert.equal(seen['src/App.js'].isGeneratedBundle, false);
  assert.equal(seen['scripts/deploy.js'].isNonAppSource, true);
  assert.equal(seen['eslint.config.js'].isNonAppSource, true);
  assert.equal(seen['src/min.js'].isGeneratedBundle, true);
  assert.equal(seen['assets/app.bundle.js'].isGeneratedBundle, true);
});

test('ProjectInfo.stripsConsoleInRelease from babel config sources', async () => {
  const probe = async files => {
    const dir = mkdtempSync(join(tmpdir(), 'rnsec-babel-'));
    for (const [p, c] of Object.entries(files)) {
      mkdirSync(join(dir, p, '..'), { recursive: true });
      writeFileSync(join(dir, p), c);
    }
    let info;
    const engine = new RuleEngine();
    engine.registerRuleGroup({ category: 'CONFIG', rules: [{ id: 'P', description: 'p', severity: 'LOW', fileTypes: ['.js'], apply: async c => ((info = c.project), []) }] });
    await engine.runRulesOnProject(dir);
    return info.stripsConsoleInRelease;
  };
  const js = { 'index.js': 'x' };
  assert.equal(await probe({ ...js }), false);
  assert.equal(await probe({ ...js, 'babel.config.js': "module.exports = { env: { production: { plugins: ['transform-remove-console'] } } };" }), true);
  assert.equal(await probe({ ...js, '.babelrc': '{"plugins":["transform-remove-console"]}' }), true);
  assert.equal(await probe({ ...js, 'package.json': '{"babel":{"plugins":["transform-remove-console"]}}' }), true);
  assert.equal(await probe({ ...js, 'babel.config.js': 'module.exports = {}', 'package.json': '{}' }), false);
});

function dummyEngine(ignored = []) {
  const evidence = [];
  let begun = 0;
  let projectSeen;
  const engine = new RuleEngine();
  engine.setIgnoredRules(ignored);
  engine.registerRuleGroup({
    category: 'CONFIG',
    rules: [
      {
        id: 'PROJECT_LEVEL',
        description: 'project',
        severity: 'LOW',
        fileTypes: ['.js'],
        beginScan: () => { begun++; evidence.length = 0; },
        apply: async c => (evidence.push(c.filePath), []),
        finalize: async project => {
          projectSeen = project;
          return [
            { ruleId: 'PROJECT_LEVEL', description: `saw ${evidence.length}`, severity: 'LOW', filePath: evidence[0], line: 1 },
            { ruleId: 'PROJECT_LEVEL', description: 'no file', severity: 'LOW', filePath: '' },
          ];
        },
      },
    ],
  });
  return { engine, evidence, begun: () => begun, project: () => projectSeen };
}

test('Rule.beginScan / Rule.finalize: project findings after all files (full scan and runRulesOnFiles)', async () => {
  const dir = gitProject({ 'a.js': 'x\n', 'b.js': 'y\n' }, { commit: true });
  const d = dummyEngine();
  const full = await d.engine.runRulesOnProject(dir);
  assert.equal(d.begun(), 1);
  assert.deepEqual(full.findings.map(f => f.description).sort(), ['no file', 'saw 2']);
  assert.equal(d.project().rootDir, dir.replace(/^\/private/, '') === dir ? dir : d.project().rootDir);

  const partial = await d.engine.runRulesOnFiles([join(dir, 'a.js')], undefined, dir);
  assert.equal(d.begun(), 2, 'state is reset for every scan');
  assert.deepEqual(partial.findings.map(f => f.description).sort(), ['no file', 'saw 1']);
});

test('finalize findings honour rnsec-ignore and ignoredRules', async () => {
  const dir = gitProject({ 'a.js': '// rnsec-ignore: PROJECT_LEVEL\nx\n', 'b.js': 'y\n' }, { commit: true });
  // first evidence file is a.js, line 1 carries the directive
  const r = await dummyEngine().engine.runRulesOnProject(dir);
  assert.deepEqual(r.findings.map(f => f.description), ['no file']);
  assert.equal(r.suppressedCount, 1);
  const none = await dummyEngine(['PROJECT_LEVEL']).engine.runRulesOnProject(dir);
  assert.deepEqual(none.findings, []);
});
