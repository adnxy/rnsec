import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import { resolve, dirname } from 'path';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

/**
 * Get list of files changed since a specific git reference
 * @param gitRef - Git reference (branch, commit hash, tag)
 * @param rootDir - Root directory of the project
 * @returns Array of changed file paths
 */
export async function getChangedFiles(gitRef: string, rootDir: string): Promise<string[]> {
  // git would parse a leading "-" as an option (--output=<file> writes a file)
  if (gitRef.startsWith('-')) {
    throw new Error(`Invalid git reference "${gitRef}": it must not start with "-"`);
  }
  try {
    const resolvedRoot = resolve(rootDir);

    // --relative: paths are relative to the scan root (not the repo root) and changes outside it are dropped
    const { stdout } = await execFileAsync(
      'git',
      ['diff', '--name-only', '-z', '--diff-filter=ACMRT', '--relative', gitRef, '--'],
      { cwd: resolvedRoot, maxBuffer: 64 * 1024 * 1024 }
    );
    
    if (!stdout.trim()) {
      return [];
    }
    
    const changedFiles = stdout
      .split('\0')
      .filter(Boolean)
      .map((file: string) => resolve(resolvedRoot, file));
    
    return changedFiles;
  } catch (error) {
    throw new Error(`Failed to get changed files: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Check if a directory is a git repository
 * @param rootDir - Directory to check
 * @returns True if directory is a git repository
 */
export async function isGitRepository(rootDir: string): Promise<boolean> {
  try {
    const resolvedRoot = resolve(rootDir);
    await execAsync('git rev-parse --git-dir', { cwd: resolvedRoot });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get the default branch name (main/master)
 * @param rootDir - Root directory of the project
 * @returns Default branch name
 */
export async function getDefaultBranch(rootDir: string): Promise<string> {
  try {
    const resolvedRoot = resolve(rootDir);
    const { stdout } = await execAsync(
      'git symbolic-ref refs/remotes/origin/HEAD',
      { cwd: resolvedRoot }
    );

    return stdout.replace('refs/remotes/origin/', '').trim() || 'main';
  } catch {
    return 'main';
  }
}

/**
 * Return the subset of `files` that git tracks. Returns an empty list outside a
 * git repository, because without git there is no way to tell a committed file
 * from a local, ignored one.
 */
export async function filterGitTracked(files: string[], rootDir: string): Promise<string[]> {
  if (files.length === 0) return [];
  try {
    const resolvedRoot = resolve(rootDir);
    const { stdout } = await execFileAsync('git', ['ls-files', '-z'], {
      cwd: resolvedRoot,
      maxBuffer: 64 * 1024 * 1024,
    });
    const tracked = new Set(
      stdout.split('\0').filter(Boolean).map((f: string) => resolve(resolvedRoot, f))
    );
    return files.filter(f => tracked.has(resolve(f)));
  } catch {
    return [];
  }
}

/**
 * Top-level directory of the git repository containing `dir`, or null outside git.
 */
export async function getGitRoot(dir: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('git', ['rev-parse', '--show-toplevel'], { cwd: resolve(dir) });
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

/**
 * Drop the files git ignores, using a single `git ls-files --cached --others --exclude-standard`
 * from `rootDir`. Tracked files are always kept, even if an ignore pattern matches them.
 * A no-op (returns `files` unchanged) outside a git work tree, when git is missing, or when git
 * lists nothing at all (e.g. the scan root itself sits inside an ignored folder).
 * A file under a submodule or an untracked nested repository is kept (git lists only the directory/gitlink).
 */
export async function filterGitIgnored(files: string[], rootDir: string): Promise<string[]> {
  if (files.length === 0) return files;
  try {
    const resolvedRoot = resolve(rootDir);
    const { stdout } = await execFileAsync(
      'git',
      ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
      { cwd: resolvedRoot, maxBuffer: 256 * 1024 * 1024 }
    );
    const listed = new Set(
      stdout.split('\0').filter(Boolean).map((f: string) => resolve(resolvedRoot, f))
    );
    if (listed.size === 0) return files;
    const kept = (file: string): boolean => {
      for (let p = resolve(file); ; p = dirname(p)) {
        if (listed.has(p)) return true;
        if (p === resolvedRoot || p === dirname(p)) return false;
        // untracked nested repos are listed as `dir/`, which resolve() normalises to `dir`
      }
    };
    return files.filter(kept);
  } catch {
    return files;
  }
}
