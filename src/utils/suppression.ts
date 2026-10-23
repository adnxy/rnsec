/**
 * Inline suppression: `// rnsec-ignore: RULE_ID[, RULE_ID] optional reason`.
 *
 * - Rule IDs are mandatory; there is no blanket ignore.
 * - Applies to the line carrying the comment, or to the next line when the
 *   comment stands alone on its own line.
 * - Works in `//`, `/* *​/`, `#` and `<!-- -->` comments.
 */
const DIRECTIVE =
  /(?:\/\/|\/\*|#|<!--)\s*rnsec-ignore:\s*([A-Z][A-Z0-9_]*(?:\s*,\s*[A-Z][A-Z0-9_]*)*)/;

const COMMENT_ONLY = /^\s*(?:\/\/|\/\*|\*|#|<!--)/;

export interface SuppressionMap {
  /** line (1-based) -> set of rule IDs suppressed on that line */
  byLine: Map<number, Set<string>>;
}

export function parseSuppressions(content: string): SuppressionMap {
  const byLine = new Map<number, Set<string>>();
  if (!content.includes('rnsec-ignore')) return { byLine };

  const lines = content.split('\n');
  const add = (line: number, ids: string[]) => {
    const set = byLine.get(line) ?? new Set<string>();
    ids.forEach(id => set.add(id));
    byLine.set(line, set);
  };

  lines.forEach((text, idx) => {
    const match = DIRECTIVE.exec(text);
    if (!match) return;
    const ids = match[1].split(',').map(s => s.trim());
    const lineNo = idx + 1;
    add(lineNo, ids);
    if (COMMENT_ONLY.test(text)) add(lineNo + 1, ids);
  });

  return { byLine };
}

/** Findings without a line number (file-level) can be suppressed from line 1. */
export function isSuppressed(map: SuppressionMap, ruleId: string, line: number | undefined): boolean {
  const target = line ?? 1;
  return map.byLine.get(target)?.has(ruleId) ?? false;
}
