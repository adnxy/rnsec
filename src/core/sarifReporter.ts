import { writeFile } from 'fs/promises';
import { pathToFileURL } from 'url';
import type { Finding } from '../types/findings.js';
import { Severity } from '../types/findings.js';
import type { Rule } from '../types/ruleTypes.js';
import { VERSION } from '../constants.js';
import { relativeToRoot } from './baseline.js';
import { getRuleStandards, loadOwaspSnapshot, standardsUrl } from '../standards/owasp/index.js';

const SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const INFORMATION_URI = 'https://github.com/adnxy/rnsec';
const MAX_NAME = 255;
const MAX_TEXT = 1024;
const MASVS_TAXONOMY = 'OWASP MASVS';
const MASVS_INFORMATION_URI = 'https://mas.owasp.org/MASVS/';

const LEVEL: Record<Severity, string> = {
  [Severity.CRITICAL]: 'error',
  [Severity.HIGH]: 'error',
  [Severity.MEDIUM]: 'warning',
  [Severity.LOW]: 'note',
};

// GitHub bands: >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low
const SECURITY_SEVERITY: Record<Severity, string> = {
  [Severity.CRITICAL]: '9.5',
  [Severity.HIGH]: '8.0',
  [Severity.MEDIUM]: '5.5',
  [Severity.LOW]: '3.0',
};

export interface SarifOptions {
  /** Directory result URIs are relative to (git root, or the scan root outside git) */
  repoRoot: string;
  /** Applied to rule defaults so they match the (already overridden) findings */
  severityOverrides?: Record<string, Severity>;
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max - 1) + '…';
}

/** INSECURE_HTTP_URL -> InsecureHttpUrl */
function pascalCase(id: string): string {
  return id
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map(w => w[0].toUpperCase() + w.slice(1).toLowerCase())
    .join('');
}

/**
 * Standards metadata of a rule: GitHub-style tags, a help page and the MASVS controls it relates to.
 * Always emitted, with or without --owasp: it is rule metadata and does not change any result.
 */
function standardsOf(ruleId: string): { tags: string[]; helpUri?: string; masvs: string[] } {
  const s = getRuleStandards(ruleId);
  if (!s) return { tags: [], masvs: [] };
  return {
    tags: [...s.masvs, ...s.maswe, ...s.mastg, ...(s.cwe ?? []).map(n => `external/cwe/cwe-${n}`)],
    helpUri: [...s.maswe, ...s.masvs].map(standardsUrl).find(Boolean),
    masvs: s.masvs,
  };
}

export class SarifReporter {
  generate(findings: Finding[], rules: Rule[], options: SarifOptions): object {
    const overrides = options.severityOverrides ?? {};
    const firstFinding = new Map<string, Finding>();
    for (const f of findings) if (!firstFinding.has(f.ruleId)) firstFinding.set(f.ruleId, f);

    // Every registered rule once, in registration order; unknown ids from findings are appended
    const ruleList: Array<{ id: string; description: string; severity: Severity }> = [];
    const ruleIndex = new Map<string, number>();
    const addRule = (id: string, description: string, severity: Severity) => {
      if (ruleIndex.has(id)) return;
      ruleIndex.set(id, ruleList.length);
      ruleList.push({ id, description, severity: overrides[id] ?? severity });
    };
    for (const r of rules) addRule(r.id, r.description, r.severity);
    for (const f of findings) addRule(f.ruleId, f.description, f.severity);

    // Controls the emitted rules relate to, sorted: they become the taxa of the MASVS taxonomy
    const referenced = [...new Set(ruleList.flatMap(r => standardsOf(r.id).masvs))].sort();
    const taxaIndex = (id: string) => referenced.indexOf(id);
    const sarifRules = ruleList.map(r => {
      const standards = standardsOf(r.id);
      const suggestion = firstFinding.get(r.id)?.suggestion;
      const helpText = truncate(suggestion ? `${r.description} ${suggestion}` : r.description, MAX_TEXT);
      return {
        id: r.id,
        name: truncate(pascalCase(r.id), MAX_NAME),
        shortDescription: { text: truncate(r.description, MAX_TEXT) },
        fullDescription: { text: truncate(r.description, MAX_TEXT) },
        help: {
          text: helpText,
          markdown: `**${r.id}**\n\n${helpText}`,
        },
        ...(standards.helpUri ? { helpUri: standards.helpUri } : {}),
        defaultConfiguration: { level: LEVEL[r.severity] },
        ...(standards.masvs.length > 0
          ? {
              relationships: standards.masvs.map(id => ({
                target: { id, index: taxaIndex(id), toolComponent: { name: MASVS_TAXONOMY, index: 0 } },
                kinds: ['relevant'],
              })),
            }
          : {}),
        properties: {
          tags: ['security', ...standards.tags],
          precision: 'medium',
          'security-severity': SECURITY_SEVERITY[r.severity],
        },
      };
    });

    const results = findings.map(f => ({
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId)!,
      level: LEVEL[f.severity],
      message: { text: f.reason ? `${f.description} ${f.reason}` : f.description },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: relativeToRoot(f.filePath, options.repoRoot), uriBaseId: '%SRCROOT%' },
            region: { startLine: f.line ?? 1, startColumn: f.column ?? 1 },
          },
        },
      ],
      ...(f.fingerprint ? { partialFingerprints: { 'rnsec/v1': f.fingerprint } } : {}),
      properties: { confidence: f.confidence ?? 'high' },
    }));

    const snapshot = loadOwaspSnapshot();
    const taxonomies =
      referenced.length > 0
        ? [
            {
              name: MASVS_TAXONOMY,
              version: snapshot.sources.masvs.version,
              organization: 'OWASP',
              shortDescription: { text: 'OWASP Mobile Application Security Verification Standard' },
              informationUri: MASVS_INFORMATION_URI,
              downloadUri: snapshot.sources.masvs.url,
              taxa: referenced.map(id => ({
                id,
                shortDescription: { text: snapshot.masvs.controls[id] },
                helpUri: standardsUrl(id),
              })),
            },
          ]
        : undefined;

    const rootUri = pathToFileURL(options.repoRoot).href;
    return {
      $schema: SCHEMA,
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'rnsec',
              version: VERSION,
              semanticVersion: VERSION,
              informationUri: INFORMATION_URI,
              rules: sarifRules,
            },
          },
          ...(taxonomies ? { taxonomies } : {}),
          originalUriBaseIds: { '%SRCROOT%': { uri: rootUri.endsWith('/') ? rootUri : rootUri + '/' } },
          invocations: [{ executionSuccessful: true }],
          results,
        },
      ],
    };
  }

  /** Pretty-printed SARIF document, newline-terminated; the same text goes to stdout and to files */
  render(findings: Finding[], rules: Rule[], options: SarifOptions): string {
    return JSON.stringify(this.generate(findings, rules, options), null, 2) + '\n';
  }

  async writeReport(file: string, findings: Finding[], rules: Rule[], options: SarifOptions): Promise<void> {
    await writeFile(file, this.render(findings, rules, options));
  }
}
