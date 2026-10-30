/**
 * MASVS coverage of one scan, from the central mapping and what the engine actually ran.
 *
 * Static analysis cannot establish MASVS compliance, so the model only says what was checked:
 * `failed`     >= 1 reported finding maps to the control
 * `checked`    >= 1 enabled, applicable rule maps to it and nothing was reported
 *              (`checked-heuristic` when every such rule is a low-confidence presence/absence heuristic)
 * `not-applicable` every enabled rule that maps to it targets a platform the project does not have
 * `not-assessed`   no enabled rule maps to it: it needs manual or dynamic verification
 */
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import type { ControlCoverage, ControlStatus, Finding, OwaspReport } from "../../types/findings.js";
import { loadOwaspSnapshot } from "./snapshot.js";
import { RULE_STANDARDS } from "./mappings.js";
import type { RulePlatform } from "./mappings.js";

export const OWASP_DISCLAIMER =
  "Static analysis does not establish MASVS compliance. This report lists which controls rnsec checked and where it found issues. " +
  "Controls marked not-assessed need manual or dynamic verification (see the MASTG).";

const CHANGED_FILES_NOTE = " This scan covered only the changed files, so checked controls say nothing about the rest of the project.";

export type ProjectPlatforms = Record<"android" | "ios" | "expo", boolean>;

function readJson(file: string): any {
  try {
    return JSON.parse(readFileSync(file, "utf-8"));
  } catch {
    return undefined;
  }
}

/**
 * Platforms present in the scan root: an `android/` or `ios/` directory, or an Expo config
 * (which targets both, unless app.json `expo.platforms` narrows it). With no signal at all the
 * project is not known to lack anything, so every platform counts as present.
 */
export function detectProjectPlatforms(rootDir: string): ProjectPlatforms {
  const pkg = readJson(join(rootDir, "package.json"));
  const appJson = readJson(join(rootDir, "app.json"));
  const expo =
    Boolean(pkg && ["dependencies", "devDependencies"].some(f => pkg[f] && "expo" in pkg[f])) ||
    Boolean(appJson?.expo) ||
    ["app.config.js", "app.config.ts", "app.config.json"].some(f => existsSync(join(rootDir, f)));
  const android = existsSync(join(rootDir, "android"));
  const ios = existsSync(join(rootDir, "ios"));
  if (!expo && !android && !ios) return { android: true, ios: true, expo: true };

  const listed: unknown = appJson?.expo?.platforms;
  const expoTargets = (p: string) => expo && (!Array.isArray(listed) || listed.includes(p));
  return { android: android || expoTargets("android"), ios: ios || expoTargets("ios"), expo };
}

function appliesTo(platforms: RulePlatform[], project: ProjectPlatforms): boolean {
  return platforms.some(p => (p === "cross-platform" ? true : project[p]));
}

export interface CoverageInput {
  /** Findings as reported (after suppression, baseline and --min-confidence) */
  findings: Finding[];
  /** Ids of rules that ran: registered and not disabled */
  ranRuleIds: string[];
  /**
   * Rule ids that produced a finding before --min-confidence hid it. They did not run clean,
   * so they are no evidence for `checked`.
   */
  hiddenRuleIds?: string[];
  platforms: ProjectPlatforms;
  scope?: OwaspReport["scope"];
}

export function buildCoverage(input: CoverageInput): OwaspReport {
  const snapshot = loadOwaspSnapshot();
  const ran = new Set(input.ranRuleIds);
  const hidden = new Set(input.hiddenRuleIds ?? []);
  const scope = input.scope ?? "project";

  const findingsPerControl = new Map<string, number>();
  for (const f of input.findings) {
    for (const control of RULE_STANDARDS[f.ruleId]?.masvs ?? []) {
      findingsPerControl.set(control, (findingsPerControl.get(control) ?? 0) + 1);
    }
  }

  const applicableRules = new Set<string>();
  const controls: ControlCoverage[] = Object.keys(snapshot.masvs.controls)
    .sort()
    .map(id => {
      const mapped = Object.entries(RULE_STANDARDS)
        .filter(([ruleId, s]) => ran.has(ruleId) && s.masvs.includes(id))
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      const applicable = mapped.filter(([, s]) => appliesTo(s.platform, input.platforms));
      const findings = findingsPerControl.get(id) ?? 0;
      applicable.forEach(([ruleId]) => applicableRules.add(ruleId));

      let status: ControlStatus;
      let reason: string | undefined;
      if (findings > 0) {
        status = "failed";
      } else if (mapped.length === 0) {
        status = "not-assessed";
        reason = "No enabled automated rule maps to this control; verify manually or dynamically.";
      } else if (applicable.length === 0) {
        status = "not-applicable";
        reason = "Every mapped rule targets a platform this project does not have.";
      } else {
        const evidence = applicable.filter(([ruleId]) => !hidden.has(ruleId));
        if (evidence.length === 0) {
          status = "not-assessed";
          reason = "Findings of the mapped rules were hidden by --min-confidence.";
        } else if (evidence.every(([, s]) => s.confidence === "low")) {
          status = "checked-heuristic";
          reason = "Only low-confidence presence/absence heuristics map to this control.";
        } else {
          status = "checked";
        }
      }
      return {
        id,
        statement: snapshot.masvs.controls[id],
        status,
        rules: mapped.map(([ruleId]) => ruleId),
        findings,
        ...(reason ? { reason } : {}),
      };
    });

  const count = (s: ControlStatus) => controls.filter(c => c.status === s).length;
  return {
    standards: {
      masvs: snapshot.sources.masvs.version,
      maswe: snapshot.sources.maswe.version,
      mastg: snapshot.sources.mastg.version,
    },
    scope,
    summary: {
      controls: controls.length,
      failed: count("failed"),
      checked: count("checked"),
      checkedHeuristic: count("checked-heuristic"),
      notApplicable: count("not-applicable"),
      notAssessed: count("not-assessed"),
      automatedRules: applicableRules.size,
    },
    controls,
    disclaimer: OWASP_DISCLAIMER + (scope === "changed-files" ? CHANGED_FILES_NOTE : ""),
  };
}
