import { loadOwaspSnapshot } from "./snapshot.js";
import { RULE_STANDARDS, UNMAPPED_RULES, masvsFromMaswe } from "./mappings.js";
import type { RuleStandards } from "./mappings.js";
import type { Finding } from "../../types/findings.js";

export { RULE_STANDARDS, UNMAPPED_RULES, masvsFromMaswe };
export type { RuleStandards, RulePlatform, MappingConfidence } from "./mappings.js";
export { loadOwaspSnapshot };

const BASE = "https://mas.owasp.org";

/**
 * The OWASP site files MASWE weaknesses and MASTG tests under one MASVS category folder, which is not
 * derivable from the snapshot (a MASWE can list several categories). Verified against mas.owasp.org
 * (HTTP 200) when this table was generated; ids are the numeric suffix.
 */
const MASWE_FOLDER: Record<string, string[]> = {
  AUTH: [
    "0018", "0019", "0020", "0021", "0022", "0023", "0024", "0025",
  ],
  CODE: [
    "0041", "0042", "0043", "0044", "0045", "0046", "0047", "0048", "0049", "0050",
  ],
  CRYPTO: [
    "0007", "0008", "0009", "0010", "0011", "0012", "0013", "0014", "0015", "0016",
    "0017",
  ],
  NETWORK: [
    "0026", "0027", "0028",
  ],
  PLATFORM: [
    "0029", "0030", "0031", "0032", "0033", "0034", "0035", "0036", "0037", "0038",
    "0039", "0040",
  ],
  PRIVACY: [
    "0066", "0067", "0068", "0069", "0070", "0071", "0072", "0073", "0074", "0075",
    "0076", "0077", "0078",
  ],
  RESILIENCE: [
    "0051", "0052", "0053", "0054", "0055", "0056", "0057", "0058", "0059", "0060",
    "0061", "0062", "0063", "0064", "0065",
  ],
  STORAGE: [
    "0001", "0002", "0003", "0004", "0005", "0006",
  ],
};
const MASTG_FOLDER: Record<string, string[]> = {
  AUTH: [
    "0266", "0267", "0268", "0269", "0270", "0271", "0326", "0327", "0328", "0329",
    "0330",
  ],
  CODE: [
    "0222", "0223", "0228", "0229", "0230", "0245", "0272", "0273", "0274", "0275",
    "0337", "0339", "0372", "0374", "0375", "0382", "0383", "0384", "0386", "0392",
    "0398", "0399", "0400",
  ],
  CRYPTO: [
    "0204", "0205", "0208", "0209", "0210", "0211", "0212", "0213", "0214", "0221",
    "0232", "0307", "0308", "0309", "0310", "0311", "0312", "0317", "0349", "0350",
  ],
  NETWORK: [
    "0217", "0218", "0233", "0234", "0235", "0237", "0238", "0239", "0242", "0243",
    "0282", "0283", "0284", "0285", "0286", "0295", "0321", "0322", "0323", "0342",
    "0343", "0344", "0345", "0348", "0385", "0396", "0397",
  ],
  PLATFORM: [
    "0250", "0251", "0252", "0253", "0258", "0276", "0277", "0278", "0279", "0280",
    "0289", "0290", "0291", "0292", "0293", "0294", "0315", "0316", "0320", "0331",
    "0332", "0333", "0334", "0335", "0336", "0340", "0346", "0347", "0355", "0356",
    "0357", "0364", "0365", "0366", "0370", "0371", "0376", "0377", "0378", "0379",
    "0380", "0381", "0389", "0390", "0393", "0394", "0395",
  ],
  PRIVACY: [
    "0206", "0254", "0255", "0256", "0257", "0281", "0318", "0319", "0360", "0361",
    "0362", "0363",
  ],
  RESILIENCE: [
    "0219", "0220", "0224", "0225", "0226", "0227", "0240", "0241", "0246", "0247",
    "0248", "0249", "0261", "0263", "0264", "0265", "0288", "0324", "0325", "0338",
    "0341", "0351", "0352", "0353", "0354", "0358", "0359", "0367", "0368", "0369",
    "0387", "0391", "0401", "0402",
  ],
  STORAGE: [
    "0200", "0201", "0202", "0203", "0207", "0215", "0216", "0231", "0262", "0287",
    "0296", "0297", "0298", "0299", "0300", "0301", "0302", "0303", "0304", "0305",
    "0306", "0313", "0314", "0388",
  ],
};

function invert(table: Record<string, string[]>): Map<string, string> {
  const out = new Map<string, string>();
  for (const [category, ids] of Object.entries(table)) {
    for (const id of ids) out.set(id, `MASVS-${category}`);
  }
  return out;
}
const MASWE_CATEGORY = invert(MASWE_FOLDER);
const MASTG_CATEGORY = invert(MASTG_FOLDER);

/** Mapping for a rule, or undefined when the rule is unmapped (see UNMAPPED_RULES) or unknown. */
export function getRuleStandards(ruleId: string): RuleStandards | undefined {
  return Object.prototype.hasOwnProperty.call(RULE_STANDARDS, ruleId) ? RULE_STANDARDS[ruleId] : undefined;
}

/** "MASVS-STORAGE-1" -> "MASVS-STORAGE" (undefined for anything that is not a MASVS control id). */
export function masvsCategoryOf(controlId: string): string | undefined {
  const match = /^(MASVS-[A-Z]+)-\d+$/.exec(controlId);
  return match ? match[1] : undefined;
}

/**
 * Official page for a MASVS control, MASWE weakness or MASTG test id; undefined when the id is not in the
 * pinned snapshot or has no page (MASTG tests with platform "network" have none under /tests/<platform>/).
 */
export function standardsUrl(id: string): string | undefined {
  const snapshot = loadOwaspSnapshot();
  if (/^MASVS-[A-Z]+-\d+$/.test(id)) {
    return Object.prototype.hasOwnProperty.call(snapshot.masvs.controls, id)
      ? `${BASE}/MASVS/controls/${id}/`
      : undefined;
  }
  const maswe = /^MASWE-(\d{4})$/.exec(id);
  if (maswe) {
    const category = MASWE_CATEGORY.get(maswe[1]);
    return category && Object.prototype.hasOwnProperty.call(snapshot.maswe, id)
      ? `${BASE}/MASWE/${category}/${id}/`
      : undefined;
  }
  const mastg = /^MASTG-TEST-(\d{4})$/.exec(id);
  if (mastg) {
    const category = MASTG_CATEGORY.get(mastg[1]);
    const test = Object.prototype.hasOwnProperty.call(snapshot.mastg, id) ? snapshot.mastg[id] : undefined;
    return category && test ? `${BASE}/MASTG/tests/${test.platform}/${category}/${id}/` : undefined;
  }
  return undefined;
}

/**
 * Adds `title`, `platform` and `standards` to every finding whose rule is mapped (report time only,
 * `--owasp`). Findings of unmapped rules are left as they are.
 */
export function enrichFindings(findings: Finding[]): void {
  for (const f of findings) {
    const s = getRuleStandards(f.ruleId);
    if (!s) continue;
    f.title = s.title;
    f.platform = s.platform;
    f.standards = { masvs: s.masvs, maswe: s.maswe, mastg: s.mastg, cwe: s.cwe ?? [], confidence: s.confidence };
  }
}
