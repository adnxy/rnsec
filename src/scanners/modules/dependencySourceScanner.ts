import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { getLineNumber } from '../../utils/stringUtils.js';

const DEP_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

// Specs that resolve to a registry package or a local/workspace path.
const SAFE_PREFIX = /^(workspace|file|link|portal|patch|npm|catalog|jsr):/i;
const GIT_PREFIX = /^(git\+[a-z]+:|git:\/\/|git@|ssh:\/\/|(github|gitlab|bitbucket|gist):)/i;
const SHORTHAND = /^[\w.-]+\/[\w.-]+(#.*)?$/; // owner/repo (scoped names never appear as specs)
const HTTP_TARBALL = /^https?:\/\//i;
const PINNED_FRAGMENT = /#(?:[0-9a-f]{40}|semver:.+|v?\d+(?:\.\d+){1,2}(?:[-+.\w]*)?)$/i;

interface Classified {
  severity: Severity;
  kind: string;
}

function classify(spec: string): Classified | null {
  const s = spec.trim();
  if (SAFE_PREFIX.test(s)) return null;
  if (s === '' || s === '*' || s.toLowerCase() === 'latest' || s.toLowerCase() === 'x') {
    return { severity: Severity.LOW, kind: 'unbounded version range' };
  }
  if (GIT_PREFIX.test(s) || SHORTHAND.test(s)) {
    return {
      severity: PINNED_FRAGMENT.test(s) ? Severity.LOW : Severity.MEDIUM,
      kind: PINNED_FRAGMENT.test(s) ? 'git dependency pinned to a commit or tag' : 'git dependency without a commit pin',
    };
  }
  if (HTTP_TARBALL.test(s)) return { severity: Severity.MEDIUM, kind: 'tarball URL' };
  return null;
}

function findLine(content: string, section: string, name: string): number | undefined {
  const esc = (v: string) => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const secMatch = new RegExp(`"${esc(section)}"\\s*:`).exec(content);
  const from = secMatch ? secMatch.index : 0;
  const m = new RegExp(`"${esc(name)}"\\s*:`).exec(content.slice(from));
  return m ? getLineNumber(content, from + m.index) : undefined;
}

const nonRegistrySourceRule: Rule = {
  id: 'DEPENDENCY_NONREGISTRY_SOURCE',
  description: 'Dependency installed from a non-registry source or an unbounded version',
  severity: Severity.MEDIUM,
  fileTypes: ['.json'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    if (!context.config || !/(^|[\\/])package\.json$/.test(context.filePath)) return [];
    const findings: Finding[] = [];

    for (const section of DEP_SECTIONS) {
      const deps = context.config[section];
      if (!deps || typeof deps !== 'object' || Array.isArray(deps)) continue;

      for (const [name, spec] of Object.entries(deps)) {
        if (typeof spec !== 'string') continue;
        const hit = classify(spec);
        if (!hit) continue;

        const unbounded = hit.kind === 'unbounded version range';
        findings.push({
          ruleId: 'DEPENDENCY_NONREGISTRY_SOURCE',
          description: `"${name}" in ${section} uses ${hit.kind}: "${spec}"`,
          severity: hit.severity,
          filePath: context.filePath,
          line: findLine(context.fileContent, section, name),
          reason: unbounded
            ? 'Any future release, including a compromised one, is installed automatically and builds are not reproducible.'
            : 'Code fetched from git or a URL bypasses registry integrity and provenance checks, and a moving branch or tag can change under you.',
          suggestion: unbounded
            ? `Pin "${name}" to a semver range (e.g. "^1.2.3") and commit a lockfile.`
            : `Publish and install "${name}" from your registry, or pin the git dependency to a full 40-character commit SHA.`,
          category: 'npm',
        });
      }
    }
    return findings;
  },
};

export const dependencySourceRules: RuleGroup = {
  category: RuleCategory.CONFIG,
  rules: [nonRegistrySourceRule],
};
