import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { storageRules } from "../dist/scanners/security/storageScanner.js";
import { networkRules } from "../dist/scanners/security/networkScanner.js";
import { loggingRules } from "../dist/scanners/security/loggingScanner.js";
import { configRules } from "../dist/scanners/security/configScanner.js";
import { manifestRules } from "../dist/scanners/android/manifestScanner.js";
import { authenticationRules } from "../dist/scanners/security/authenticationScanner.js";
import { cryptoRules } from "../dist/scanners/security/cryptoScanner.js";
import { reactNativeRules } from "../dist/scanners/react-native/reactNativeScanner.js";
import { webviewRules } from "../dist/scanners/security/webviewScanner.js";
import { secretsRules } from "../dist/scanners/security/secretsScanner.js";
import { debugRules } from "../dist/scanners/security/debugScanner.js";
import { androidRules } from "../dist/scanners/android/androidScanner.js";
import { iosRules } from "../dist/scanners/ios/iosScanner.js";
import { npmVulnerabilityRules } from "../dist/scanners/modules/npmScanner.js";
import { rnSecurityRules } from "../dist/scanners/security/rnSecurityScanner.js";
import { dependencySourceRules } from "../dist/scanners/modules/dependencySourceScanner.js";
import { networkSecurityConfigRules } from "../dist/scanners/android/networkSecurityConfigScanner.js";
import { iosPlistExtraRules } from "../dist/scanners/ios/iosPlistExtraScanner.js";
import { rnExtraRules } from "../dist/scanners/security/rnExtraScanner.js";
import { expoConfigRules } from "../dist/scanners/security/expoConfigScanner.js";
import { gradleRules } from "../dist/scanners/android/gradleScanner.js";
import { registryConfigRules } from "../dist/scanners/modules/registryConfigScanner.js";
import { credentialFileRules } from "../dist/scanners/security/credentialFilesScanner.js";

import {
  RULE_STANDARDS,
  UNMAPPED_RULES,
  getRuleStandards,
  masvsCategoryOf,
  masvsFromMaswe,
  standardsUrl,
} from "../dist/standards/owasp/index.js";
import { loadOwaspSnapshot } from "../dist/standards/owasp/snapshot.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const snapshot = loadOwaspSnapshot();

// Same groups as registerAllRules() in src/cli/index.ts (not exported); the CLI cross-check below catches drift.
const groups = [
  storageRules, networkRules, loggingRules, configRules, manifestRules, authenticationRules,
  cryptoRules, reactNativeRules, webviewRules, secretsRules, debugRules, androidRules, iosRules,
  npmVulnerabilityRules, rnSecurityRules, dependencySourceRules, networkSecurityConfigRules,
  iosPlistExtraRules, rnExtraRules, expoConfigRules, gradleRules, registryConfigRules,
  credentialFileRules,
];
const registeredIds = groups.flatMap((g) => g.rules.map((r) => r.id));

test("registry helper lists the same rules as `rnsec rules`", () => {
  const out = execFileSync("node", [resolve(root, "dist/index.js"), "rules"], { encoding: "utf8" });
  const cliIds = [...out.matchAll(/▸ ([A-Z0-9_]+)/g)].map((m) => m[1]);
  assert.deepEqual([...cliIds].sort(), [...registeredIds].sort());
  assert.equal(new Set(registeredIds).size, registeredIds.length, "duplicate rule ids");
});

test("every registered rule is mapped xor unmapped, and no table has stale ids", () => {
  const registered = new Set(registeredIds);
  for (const id of registered) {
    const inMapped = id in RULE_STANDARDS;
    const inUnmapped = id in UNMAPPED_RULES;
    assert.ok(inMapped !== inUnmapped, `${id} must be in exactly one of RULE_STANDARDS / UNMAPPED_RULES`);
  }
  for (const id of Object.keys(RULE_STANDARDS)) assert.ok(registered.has(id), `stale RULE_STANDARDS id ${id}`);
  for (const id of Object.keys(UNMAPPED_RULES)) assert.ok(registered.has(id), `stale UNMAPPED_RULES id ${id}`);
  for (const [id, reason] of Object.entries(UNMAPPED_RULES)) {
    assert.ok(reason.trim().length > 0, `${id} needs a reason`);
  }
});

test("every referenced MASVS, MASWE and MASTG id exists in the snapshot", () => {
  for (const [rule, s] of Object.entries(RULE_STANDARDS)) {
    for (const id of s.masvs) assert.ok(id in snapshot.masvs.controls, `${rule}: unknown MASVS ${id}`);
    for (const id of s.maswe) assert.ok(id in snapshot.maswe, `${rule}: unknown MASWE ${id}`);
    for (const id of s.mastg) assert.ok(id in snapshot.mastg, `${rule}: unknown MASTG ${id}`);
    assert.ok(s.masvs.length > 0, `${rule}: needs at least one MASVS control`);
    for (const cwe of s.cwe ?? []) assert.ok(Number.isInteger(cwe) && cwe > 0, `${rule}: bad CWE ${cwe}`);
  }
});

test("masvs is derived from maswe unless narrower; mastg platforms fit the rule", () => {
  for (const [rule, s] of Object.entries(RULE_STANDARDS)) {
    if (s.maswe.length > 0) {
      const union = new Set(masvsFromMaswe(s.maswe));
      for (const id of s.masvs) assert.ok(union.has(id), `${rule}: ${id} is not in its MASWE union`);
    }
    for (const id of s.mastg) {
      const platform = snapshot.mastg[id].platform;
      const ok =
        s.platform.includes("cross-platform") || s.platform.includes("expo") || s.platform.includes(platform);
      assert.ok(ok, `${rule}: ${id} is a ${platform} test but the rule targets ${s.platform.join(",")}`);
    }
  }
});

// Upstream links a MASTG test to its own MASWE entries; a rule may only list the test when it shares one.
test("a mapped MASTG test's own maswe links overlap the rule's maswe (when the rule lists any)", () => {
  for (const [rule, s] of Object.entries(RULE_STANDARDS)) {
    if (s.maswe.length === 0) continue;
    for (const id of s.mastg) {
      const linked = snapshot.mastg[id].maswe;
      assert.ok(
        linked.some((w) => s.maswe.includes(w)),
        `${rule}: ${id} links to ${linked.join(",")}, none of which is in the rule's maswe ${s.maswe.join(",")}`
      );
    }
  }
});

test("snapshot has 8 MASVS categories including PRIVACY and 24 controls", () => {
  const ids = snapshot.masvs.categories.map((c) => c.id);
  assert.equal(ids.length, 8);
  assert.ok(ids.includes("MASVS-PRIVACY"));
  assert.equal(Object.keys(snapshot.masvs.controls).length, 24);
  for (const control of Object.keys(snapshot.masvs.controls)) {
    assert.ok(ids.includes(masvsCategoryOf(control)), `${control} has no category`);
  }
});

test("every mapped rule has a title, confidence and platform", () => {
  for (const [rule, s] of Object.entries(RULE_STANDARDS)) {
    assert.ok(s.title.trim().length > 0, `${rule}: empty title`);
    assert.ok(["high", "medium", "low"].includes(s.confidence), `${rule}: bad confidence`);
    assert.ok(s.platform.length > 0, `${rule}: no platform`);
    for (const p of s.platform) assert.ok(["android", "ios", "cross-platform", "expo"].includes(p), `${rule}: ${p}`);
  }
});

test("presence/absence heuristics are low confidence", () => {
  for (const id of [
    "ROOT_JAILBREAK_DETECTION_ABSENT",
    "MISSING_RUNTIME_INTEGRITY_CHECKS",
    "THIRD_PARTY_SDK_RISK",
    "SCREENSHOT_PROTECTION_MISSING",
  ]) {
    assert.equal(RULE_STANDARDS[id].confidence, "low", id);
  }
});

test("helpers: getRuleStandards, masvsCategoryOf, standardsUrl", () => {
  assert.equal(getRuleStandards("HARDCODED_SECRETS"), RULE_STANDARDS.HARDCODED_SECRETS);
  assert.equal(getRuleStandards("NO_REQUEST_TIMEOUT"), undefined);
  assert.equal(getRuleStandards("toString"), undefined);
  assert.equal(masvsCategoryOf("MASVS-STORAGE-1"), "MASVS-STORAGE");
  assert.equal(masvsCategoryOf("MASWE-0001"), undefined);
  assert.equal(standardsUrl("MASVS-STORAGE-1"), "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/");
  assert.equal(standardsUrl("MASWE-0001"), "https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/");
  assert.equal(
    standardsUrl("MASTG-TEST-0231"),
    "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0231/"
  );
  assert.equal(standardsUrl("MASWE-9999"), undefined);
  assert.equal(standardsUrl("MASVS-STORAGE-9"), undefined);
});

test("every mapped id has an official URL (network-platform MASTG tests have no page)", () => {
  for (const [rule, s] of Object.entries(RULE_STANDARDS)) {
    for (const id of [...s.masvs, ...s.maswe, ...s.mastg]) {
      assert.ok(standardsUrl(id), `${rule}: no URL for ${id}`);
    }
  }
});
