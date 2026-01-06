import { exec } from 'child_process';
import { promisify } from 'util';
import { resolve } from 'path';

const execAsync = promisify(exec);

/**
 * Get list of files changed since a specific git reference
 * @param gitRef - Git reference (branch, commit hash, tag)
 * @param rootDir - Root directory of the project
 * @returns Array of changed file paths
 */
export async function getChangedFiles(gitRef: string, rootDir: string): Promise<string[]> {
  try {
    const resolvedRoot = resolve(rootDir);
    
    const { stdout } = await execAsync(
      `git diff --name-only --diff-filter=ACMRT ${gitRef}`,
      { cwd: resolvedRoot }
    );
    
    if (!stdout.trim()) {
      return [];
    }
    
    const changedFiles = stdout
      .split('\n')
      .filter((line: string) => line.trim())
      .map((file: string) => resolve(resolvedRoot, file));
    
    return changedFiles;
  } catch (error) {
    throw new Error(`Failed to get changed files: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Get list of files changed in the current working directory (staged + unstaged)
 * @param rootDir - Root directory of the project
 * @returns Array of changed file paths
 */
export async function getUncommittedFiles(rootDir: string): Promise<string[]> {
  try {
    const resolvedRoot = resolve(rootDir);
    
    const { stdout: unstaged } = await execAsync(
      'git diff --name-only --diff-filter=ACMRT',
      { cwd: resolvedRoot }
    );
    
    const { stdout: staged } = await execAsync(
      'git diff --cached --name-only --diff-filter=ACMRT',
      { cwd: resolvedRoot }
    );
    
    const allChanges = [...unstaged.split('\n'), ...staged.split('\n')]
      .filter((line: string) => line.trim())
      .map((file: string) => resolve(resolvedRoot, file));
    
    return [...new Set(allChanges)];
  } catch (error) {
    throw new Error(`Failed to get uncommitted files: ${error instanceof Error ? error.message : String(error)}`);
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
      'git symbolic-ref refs/remotes/origin/HEAD | sed \'s@^refs/remotes/origin/@@\'',
      { cwd: resolvedRoot }
    );
    
    const branch = stdout.trim();
    return branch || 'main';
  } catch {
    return 'main';
  }
}
