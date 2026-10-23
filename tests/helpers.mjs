import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
export const repoRoot = resolve(here, '..');
export const casesDir = join(here, 'cases');

// Tests run the built CLI. Override with RNSEC_BIN=.build-x/index.js to test a private build.
const cli = resolve(repoRoot, process.env.RNSEC_BIN ?? 'dist/index.js');

// Fake credentials in the shape of real provider keys. They are assembled from pieces so that no
// source file holds a literal that secret scanners (GitHub push protection) would flag.
const FAKE_SECRETS = {
  stripe_live: () => 'sk_' + 'live_' + '51Nq7XaB3cD9eF2gH5iJ8kL1mN4oP7qR0sT',
  stripe_live_b: () => 'sk_' + 'live_' + 'V3nuLJyJnrR5avQWwOCvUQRBIjF02F',
  stripe_live_c: () => 'sk_' + 'live_' + 'KCdGAhTbO5bunFaQIBYHails6RS5OQ',
  stripe_live_placeholder: () => 'sk_' + 'live_' + 'x'.repeat(28),
  aws_access_key: () => 'AK' + 'IA' + 'YJPB4Q6JYFYKMAV2',
  twilio_loose: () => 'S' + 'K' + 'd4b308a7341feb545e6bdb28e89e2a60',
  mailgun_loose: () => 'key' + '-' + 'ce31f28822a7a376aad952985053fdaa',
  twilio_placeholder: () => 'S' + 'K' + 'a253bacc99f487d5e5b87c834b646b7c',
  mailgun_placeholder: () => 'key' + '-' + '3e7163cd9f330caf4fcb1c7bf33cd818',
  github_pat: () => 'gh' + 'p_' + 'KDfymGlnEJbC2gmKLvGB1e6qGtmo1wNh17Q7',
};

export function fakeSecret(kind) {
  const make = FAKE_SECRETS[kind];
  if (!make) throw new Error(`unknown fake secret kind: ${kind}`);
  return make();
}

const MARKER = /\{\{fake:([a-z_0-9]+)\}\}/g;

/** Copy `src` to `dest`, replacing `{{fake:kind}}` markers in place. Returns true when any marker was found. */
function materialize(src, dest) {
  let found = false;
  mkdirSync(dest, { recursive: true });
  for (const name of readdirSync(src)) {
    const from = join(src, name);
    const to = join(dest, name);
    if (statSync(from).isDirectory()) {
      found = materialize(from, to) || found;
      continue;
    }
    const text = readFileSync(from, 'utf8');
    const out = text.replace(MARKER, (_, kind) => fakeSecret(kind));
    found = found || out !== text;
    writeFileSync(to, out);
  }
  return found;
}

/**
 * Scan a directory as its own project root and return the parsed JSON result.
 * `caseName` is resolved under tests/cases/ unless an absolute path is given.
 * Fixtures holding `{{fake:kind}}` markers are scanned from a temp copy with the markers
 * replaced (see fakeSecret), so provider-shaped keys never sit in the repo.
 */
export function scan(caseName, extraArgs = []) {
  let dir = caseName.startsWith('/') ? caseName : join(casesDir, caseName);
  if (!caseName.startsWith('/')) {
    // Copy the whole case folder so a nested scan root (dev-assets-path/dev/assets/app) keeps its path segments
    const [top, ...rest] = caseName.split('/');
    const copy = join(mkdtempSync(join(tmpdir(), 'rnsec-case-')), top);
    if (materialize(join(casesDir, top), copy)) dir = join(copy, ...rest);
  }
  const run = spawnSync('node', [cli, 'scan', '--path', dir, '--json', ...extraArgs], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    maxBuffer: 64 * 1024 * 1024,
  });
  // stdout must be pure JSON (so `rnsec scan --json | jq` works); informational lines go to stderr
  let result;
  try {
    result = JSON.parse(run.stdout);
  } catch (error) {
    throw new Error(`stdout is not pure JSON for ${caseName}: ${error.message}\n--- stdout ---\n${run.stdout.slice(0, 500)}\n--- stderr ---\n${run.stderr}`);
  }
  result.exitCode = run.status;
  return result;
}

export const ids = result => result.findings.map(f => f.ruleId);
export const byRule = (result, ruleId) => result.findings.filter(f => f.ruleId === ruleId);

/**
 * Create a throw-away git repo containing `files` (path -> content), all staged
 * but with an initial commit that holds only a README, so `--changed-files HEAD`
 * sees them. Generate any key material here instead of committing it as a fixture.
 */
export function gitProject(files, { commit = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'rnsec-git-'));
  const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
  git('init', '-q');
  git('config', 'user.email', 't@example-corp.com');
  git('config', 'user.name', 'tester');
  writeFileSync(join(dir, 'README.md'), 'x');
  git('add', '.');
  git('commit', '-q', '-m', 'base');
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content);
  }
  git('add', '-A');
  if (commit) git('commit', '-q', '-m', 'files');
  return dir;
}

/** Write files into a directory that is NOT tracked by git (never `git add`ed). */
export function untrackedProject(files) {
  const dir = gitProject({});
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}
