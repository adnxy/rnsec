import type { ProjectInfo, RuleContext } from '../types/ruleTypes.js';
import { Severity, type Finding } from '../types/findings.js';
import { readFileContent } from './fileUtils.js';
import { isGeneratedBundleContent, isGeneratedBundlePath, isNonAppSourcePath, toRelativePath } from './pathFilters.js';
import { isSuppressed, parseSuppressions } from './suppression.js';

/**
 * Helpers for project-level rules: rules that judge the absence of a feature ("no screenshot protection")
 * collect evidence per file in `apply` and emit ONE finding from `finalize`.
 *
 * Behaviour that all of them share:
 * - Evidence only comes from app source: tests, scripts, e2e, storybook and generated bundles neither raise
 *   a finding nor silence one (`finalize` output skips the engine's per-file filters, so this is done here).
 * - The finding is anchored at one evidence file, chosen by (priority, directory depth, path), never by file
 *   content, so the baseline fingerprint (rule + path + text of the anchor line) survives edits elsewhere.
 * - An `rnsec-ignore: RULE` on the anchor line suppresses the finding (the engine does this for every
 *   finalize finding). The same directive in any other evidence file removes that file from the evidence,
 *   so the old per-file ignore keeps working and the anchor moves to the next file.
 * - `--changed-files`: only changed files can be evidence (a finding is never anchored at an unchanged file),
 *   but "no protection anywhere" is still judged on the whole project, through `ProjectInfo.listProjectFiles`.
 *   An unchanged file that has the protection therefore silences the finding in both scan modes.
 * - `ignoredRules` needs nothing here: the engine does not run, begin or finalize an ignored rule.
 */

export interface Evidence {
  filePath: string;
  /** Lower anchors first (e.g. 0 for App.tsx, 1 for other files) */
  priority: number;
}

let lastContent = '';
let lastLower = '';
/** `content.toLowerCase()`, shared by the rules that look at the same file one after another */
export function lowerCased(content: string): string {
  if (content !== lastContent) {
    lastContent = content;
    lastLower = content.toLowerCase();
  }
  return lastLower;
}

/** True for application source that can be evidence: not a script/test/e2e file and not a generated bundle */
export function isAppSource(context: RuleContext): boolean {
  return !context.isNonAppSource && !context.isGeneratedBundle;
}

/** 1-based line of the first non-blank line (1 for an empty file): the anchor line of a project-level finding */
export function firstContentLine(content: string): number {
  const lines = content.split('\n');
  const idx = lines.findIndex(l => l.trim() !== '');
  return idx === -1 ? 1 : idx + 1;
}

/** The file carries `rnsec-ignore: ruleId` on (or directly above) the line a project-level finding would sit on */
export function ignoresAtAnchor(content: string, ruleId: string): boolean {
  if (!content.includes('rnsec-ignore')) return false;
  return isSuppressed(parseSuppressions(content), ruleId, firstContentLine(content));
}

function depth(relPath: string): number {
  return relPath.split('/').length;
}

/** Candidates sorted into anchor order, one entry per file */
export function orderEvidence(candidates: Evidence[], rootDir: string | undefined): Evidence[] {
  const byFile = new Map<string, Evidence>();
  for (const c of candidates) {
    const known = byFile.get(c.filePath);
    if (!known || c.priority < known.priority) byFile.set(c.filePath, c);
  }
  const rel = (c: Evidence) => toRelativePath(c.filePath, rootDir).split('\\').join('/');
  return [...byFile.values()].sort(
    (a, b) => a.priority - b.priority || depth(rel(a)) - depth(rel(b)) || (rel(a) < rel(b) ? -1 : rel(a) > rel(b) ? 1 : 0)
  );
}

/**
 * True when some source file of the whole project satisfies `test`. Full scans never need this (they
 * saw every file in `apply`); in a partial scan it reads the files the scan skipped.
 */
export async function projectHasFile(
  project: ProjectInfo | undefined,
  extensions: RegExp,
  test: (content: string, filePath: string) => boolean
): Promise<boolean> {
  if (!project?.partialScan || !project.listProjectFiles) return false;
  for (const filePath of await project.listProjectFiles()) {
    if (!extensions.test(filePath) || isNonAppSourcePath(filePath, project.rootDir) || isGeneratedBundlePath(filePath)) continue;
    let content: string;
    try {
      content = await readFileContent(filePath);
    } catch {
      continue;
    }
    if (isGeneratedBundleContent(content)) continue;
    if (test(content, filePath)) return true;
  }
  return false;
}

export interface AbsenceFinding {
  ruleId: string;
  severity: Severity;
  headline: string;
  suggestion: string;
  project: ProjectInfo | undefined;
  candidates: Evidence[];
  /** `apply` already saw the protection somewhere */
  protectionSeen: boolean;
  /** Packages whose presence in the root package.json counts as protection */
  protectionPackages?: readonly string[];
  /** Files `projectHasFile` should check in a partial scan, and how */
  protectionFiles: RegExp;
  hasProtection: (content: string, filePath: string) => boolean;
}

/** The single project-level finding of an absence rule, or [] when there is no evidence or protection exists */
export async function finalizeAbsence(spec: AbsenceFinding): Promise<Finding[]> {
  const ordered = orderEvidence(spec.candidates, spec.project?.rootDir);
  if (ordered.length === 0 || spec.protectionSeen) return [];
  if (spec.protectionPackages?.some(name => spec.project?.dependencies.has(name))) return [];
  if (await projectHasFile(spec.project, spec.protectionFiles, spec.hasProtection)) return [];

  const anchor = ordered[0];
  let line = 1;
  try {
    line = firstContentLine(await readFileContent(anchor.filePath));
  } catch {
    // unreadable anchor: line 1
  }
  const rel = (f: string) => toRelativePath(f, spec.project?.rootDir).split('\\').join('/');
  const examples = ordered.slice(0, 3).map(c => rel(c.filePath)).join(', ');
  const more = ordered.length > 3 ? ' ...' : '';
  return [
    {
      ruleId: spec.ruleId,
      confidence: 'low',
      description: `${spec.headline} (${ordered.length} file${ordered.length === 1 ? '' : 's'}, e.g. ${examples}${more})`,
      severity: spec.severity,
      filePath: anchor.filePath,
      line,
      suggestion: spec.suggestion,
    },
  ];
}
