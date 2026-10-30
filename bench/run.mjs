#!/usr/bin/env node
// Clone (or reuse) the pinned corpus apps and scan each with the built CLI.
// Usage: node bench/run.mjs --dir <clones dir> --out <results dir> [--only name,name] [--verbose] [--no-clone]
// Clones are untrusted: nothing is installed or built in them, and npm is shadowed by a stub on PATH.
import { spawnSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, openSync, closeSync, chmodSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const cli = join(repo, 'dist', 'index.js');

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? undefined : args[i + 1];
};
const flag = (name) => args.includes(`--${name}`);

const dir = opt('dir');
const out = opt('out');
if (!dir || !out) {
  console.error('usage: node bench/run.mjs --dir <clones dir> --out <results dir> [--only a,b] [--verbose] [--no-clone]');
  process.exit(2);
}
if (!existsSync(cli)) {
  console.error(`${cli} not found: run "npm run build" first`);
  process.exit(2);
}
const inRepo = (p) => resolve(p) === repo || resolve(p).startsWith(repo + '/');
if (inRepo(dir) || inRepo(out)) {
  console.error('--dir and --out must be outside the rnsec repository');
  process.exit(2);
}

const corpus = JSON.parse(readFileSync(join(here, 'corpus.json'), 'utf8'));
const only = opt('only')?.split(',');
const apps = corpus.apps.filter((a) => !only || only.includes(a.name));
mkdirSync(dir, { recursive: true });
mkdirSync(out, { recursive: true });

// npm stub: records every call and fails, so a stray `npm audit` cannot run anything in a clone
const stubDir = join(out, '.npm-stub');
const callLog = join(out, 'npm-calls.log');
mkdirSync(stubDir, { recursive: true });
writeFileSync(callLog, '');
writeFileSync(join(stubDir, 'npm'), `#!/bin/sh\necho "npm $* (cwd $PWD)" >> "${callLog}"\nexit 1\n`);
chmodSync(join(stubDir, 'npm'), 0o755);

const gitEnv = { ...process.env, GIT_LFS_SKIP_SMUDGE: '1', GIT_TERMINAL_PROMPT: '0' };
const git = (cwd, ...a) =>
  spawnSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', ...a], { cwd, env: gitEnv, encoding: 'utf8' });

function ensureClone(app) {
  const root = join(dir, app.name);
  const info = { shaExact: true, note: '' };
  if (!existsSync(join(root, '.git'))) {
    mkdirSync(root, { recursive: true });
    const r = git(dir, 'clone', '--depth', '1', '--single-branch', '--filter=blob:limit=1m', '--no-checkout', app.url, root);
    if (r.status !== 0) throw new Error(`clone failed: ${r.stderr.trim()}`);
  }
  if (app.sha) {
    if (git(root, 'rev-parse', 'HEAD').stdout.trim() !== app.sha) {
      const f = git(root, 'fetch', '--depth', '1', 'origin', app.sha);
      if (f.status !== 0) {
        info.shaExact = false;
        info.note = `could not fetch ${app.sha}: ${f.stderr.trim().split('\n').pop()}`;
      } else {
        const c = git(root, 'checkout', '--detach', 'FETCH_HEAD');
        if (c.status !== 0) throw new Error(`checkout failed: ${c.stderr.trim()}`);
      }
    }
  }
  if (!existsSync(join(root, '.git', 'index'))) {
    const c = git(root, 'checkout', '--detach', 'HEAD');
    if (c.status !== 0) throw new Error(`checkout failed: ${c.stderr.trim()}`);
  }
  info.headSha = git(root, 'rev-parse', 'HEAD').stdout.trim();
  if (app.sha === null) info.note = info.note || 'no pinned sha: scanned the default branch HEAD';
  return { root, info };
}

// Disable npm vulnerability scanning via .rnsec.json in the scan root (a merge with an existing config)
function writeConfig(scanRoot) {
  const p = join(scanRoot, '.rnsec.json');
  let cfg = {};
  let preexisting = false;
  if (existsSync(p)) {
    preexisting = true;
    try { cfg = JSON.parse(readFileSync(p, 'utf8')); } catch { cfg = {}; preexisting = 'unparsable'; }
  }
  for (const other of ['.rnsec.jsonc', '.rnsec.config.json']) {
    if (existsSync(join(scanRoot, other))) preexisting = `${other} also present`;
  }
  cfg.npmVulnerabilityScanning = { ...(cfg.npmVulnerabilityScanning || {}), enabled: false };
  writeFileSync(p, JSON.stringify(cfg, null, 2));
  return preexisting;
}

function scan(app, scanRoot) {
  return new Promise((res) => {
    const stdoutPath = join(out, `${app.name}.json`);
    const stderrPath = join(out, `${app.name}.stderr.txt`);
    const so = openSync(stdoutPath, 'w');
    const se = openSync(stderrPath, 'w');
    const env = { ...process.env, PATH: `${stubDir}:${process.env.PATH}` };
    if (flag('verbose')) env.RNSEC_VERBOSE = '1';
    const t0 = process.hrtime.bigint();
    const child = spawn(process.execPath, [cli, 'scan', '-p', scanRoot, '--format', 'json'], { env, stdio: ['ignore', so, se] });
    child.on('close', (code, signal) => {
      closeSync(so);
      closeSync(se);
      res({ exitCode: code, signal, seconds: Number(process.hrtime.bigint() - t0) / 1e9, stdoutPath, stderrPath });
    });
  });
}

const rnsecVersion = JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8')).version;
const rnsecHead = spawnSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: repo, encoding: 'utf8' }).stdout.trim();
for (const app of apps) {
  process.stderr.write(`== ${app.name}\n`);
  const meta = { name: app.name, path: app.path, pinnedSha: app.sha, rnsecVersion, rnsecHead };
  try {
    if (!flag('no-clone')) {
      const { root, info } = ensureClone(app);
      Object.assign(meta, info);
    }
    const scanRoot = join(dir, app.name, app.path === '.' ? '' : app.path);
    if (!existsSync(scanRoot)) throw new Error(`scan path missing: ${scanRoot}`);
    meta.preexistingConfig = writeConfig(scanRoot);
    const before = readFileSync(callLog, 'utf8').split('\n').filter(Boolean).length;
    const r = await scan(app, scanRoot);
    Object.assign(meta, r);
    meta.npmCalls = readFileSync(callLog, 'utf8').split('\n').filter(Boolean).length - before;
    try {
      const j = JSON.parse(readFileSync(r.stdoutPath, 'utf8'));
      meta.findings = j.findings.length;
      meta.scannedFiles = j.scannedFiles;
    } catch (e) {
      meta.error = `stdout is not JSON: ${e.message}`;
    }
  } catch (e) {
    meta.error = String(e.message || e);
  }
  writeFileSync(join(out, `${app.name}.meta.json`), JSON.stringify(meta, null, 2));
  process.stderr.write(`   exit ${meta.exitCode} ${meta.seconds?.toFixed(1)}s findings ${meta.findings} npmCalls ${meta.npmCalls}${meta.error ? ' ERROR ' + meta.error : ''}\n`);
}
