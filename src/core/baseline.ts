import { createHash } from 'crypto';
import { readFileSync, realpathSync } from 'fs';
import { readFile, writeFile } from 'fs/promises';
import { isAbsolute, relative, resolve } from 'path';
import type { Finding } from '../types/findings.js';
import { getGitRoot } from '../utils/gitUtils.js';

export interface BaselineFile {
  version: 1;
  tool: 'rnsec';
  generatedAt: string;
  findings: Array<{ fingerprint: string; ruleId: string; file: string; line?: number; description: string }>;
}

function realPath(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
}

/**
 * Directory that finding paths are made relative to: the git repository root
 * (what GitHub resolves SARIF URIs against), or the scan root outside git.
 */
export async function resolveRepoRoot(scanRoot: string): Promise<string> {
  const gitRoot = await getGitRoot(scanRoot);
  return realPath(gitRoot ?? scanRoot);
}

/** Forward-slash path of `filePath` relative to `root` (both resolved through symlinks) */
export function relativeToRoot(filePath: string, root: string): string {
  const rel = relative(root, realPath(filePath));
  const out = rel.startsWith('..') || isAbsolute(rel) ? filePath : rel;
  return out.split('\\').join('/');
}

function normalizeLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/**
 * Sets `fingerprint` on every finding: sha256 of ruleId + repo-relative path + the
 * whitespace-normalized source line (not its number, so it survives code moving) +
 * an occurrence index separating identical keys within a file.
 */
export function assignFingerprints(findings: Finding[], root: string): void {
  const lineCache = new Map<string, string[] | null>();
  const linesOf = (filePath: string): string[] | null => {
    if (!lineCache.has(filePath)) {
      try {
        lineCache.set(filePath, readFileSync(filePath, 'utf-8').split(/\r?\n/));
      } catch {
        lineCache.set(filePath, null);
      }
    }
    return lineCache.get(filePath)!;
  };

  const ordered = [...findings].sort(
    (a, b) => a.filePath.localeCompare(b.filePath) || (a.line ?? 0) - (b.line ?? 0) || (a.column ?? 0) - (b.column ?? 0)
  );
  const seen = new Map<string, number>();
  for (const f of ordered) {
    const lines = f.line ? linesOf(f.filePath) : null;
    // Project-level findings have no source line: fall back to the description
    const text = normalizeLine(lines?.[f.line! - 1] ?? '') || f.description;
    const key = [f.ruleId, relativeToRoot(f.filePath, root), text].join('\0');
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);
    f.fingerprint = createHash('sha256').update(`${key}\0${occurrence}`).digest('hex');
  }
}

export async function writeBaseline(file: string, findings: Finding[], root: string): Promise<void> {
  const baseline: BaselineFile = {
    version: 1,
    tool: 'rnsec',
    generatedAt: new Date().toISOString(),
    findings: findings.map(f => ({
      fingerprint: f.fingerprint!,
      ruleId: f.ruleId,
      file: relativeToRoot(f.filePath, root),
      line: f.line,
      description: f.description,
    })),
  };
  await writeFile(file, JSON.stringify(baseline, null, 2) + '\n');
}

/** Reads a baseline file and returns the set of fingerprints it lists. Throws a readable error. */
export async function readBaseline(file: string): Promise<Set<string>> {
  let data: any;
  try {
    data = JSON.parse(await readFile(file, 'utf-8'));
  } catch (error) {
    throw new Error(`Could not read baseline ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!data || data.version !== 1 || !Array.isArray(data.findings)) {
    throw new Error(`Baseline ${file} is not a valid rnsec baseline (expected version 1 with a findings array)`);
  }
  return new Set(data.findings.map((f: any) => f?.fingerprint).filter((f: unknown) => typeof f === 'string'));
}
