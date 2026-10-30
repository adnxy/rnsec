#!/usr/bin/env node
/**
 * Regenerates src/standards/owasp/snapshot.json from pinned official OWASP releases:
 *   - MASVS v2.1.0  (release asset OWASP_MASVS.yaml)
 *   - MASWE v1.0.0  (release asset OWASP_MASWE.yaml)
 *   - MASTG v2.0.0 + master@2eb0f70  (source tarball at a pinned master commit, front matter of
 *     MASTG-TEST-*.md). The v2.0.0 tag still uses stale MASWE beta numbering in its `weakness`
 *     field; master uses a `maswe:` list that matches MASWE v1.0.0 titles, so master is pinned.
 *
 * Usage: node scripts/update-owasp-snapshot.mjs
 *
 * Requirements: node >= 20, and curl, tar and git on PATH (network access needed).
 * No npm dependencies. PyYAML is not used; MASVS/MASWE YAML is read by a tiny
 * purpose-built parser (block maps/sequences, plain and quoted scalars, which is all
 * these two files use). MASTG front matter is read line by line (flat key/value pairs).
 *
 * Safety: every pinned commit is verified (git ls-remote, and the MASTG tarball's
 * top-level directory prefix) and every cross reference is checked, so the script
 * fails instead of emitting an ID that does not exist in the official data.
 * Output is deterministic (fixed key order, sorted IDs, no timestamps).
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_FILE = resolve(__dirname, "../src/standards/owasp/snapshot.json");

const PINS = {
  masvs: {
    version: "2.1.0",
    tag: "v2.1.0",
    commit: "8e133d09f4140518ed04cc254b18be9ff4990ffc",
    repo: "https://github.com/OWASP/masvs",
    url: "https://github.com/OWASP/masvs/releases/download/v2.1.0/OWASP_MASVS.yaml",
  },
  maswe: {
    version: "1.0.0",
    tag: "v1.0.0",
    commit: "308b82b4bbe29166934fb5a621b40471cfea61db",
    repo: "https://github.com/OWASP/maswe",
    url: "https://github.com/OWASP/maswe/releases/download/v1.0.0/OWASP_MASWE.yaml",
  },
  mastg: {
    version: "v2.0.0 + master@2eb0f70",
    tag: null, // no release tag: pinned to a master commit (verified via tarball top-level dir)
    commit: "2eb0f7097e5fc702df2f043fb34079fa42956548",
    repo: "https://github.com/OWASP/mastg",
    url: "https://api.github.com/repos/OWASP/mastg/tarball/2eb0f7097e5fc702df2f043fb34079fa42956548",
  },
};

const MASVS_CONTROL_RE = /^MASVS-[A-Z]+-\d+$/;
const MASWE_RE = /^MASWE-\d{4}$/;
const MASTG_TEST_RE = /^MASTG-TEST-\d{4}$/;

function run(cmd, args) {
  return execFileSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

function curl(url, dest) {
  run("curl", ["-sSfL", "-o", dest, url]);
}

/** Resolve the commit a tag points at (peeled for annotated tags). */
function remoteCommit(repo, tag) {
  const out = run("git", ["ls-remote", repo, `${tag}^{}`, tag]);
  const refs = new Map();
  for (const line of out.split("\n").filter(Boolean)) {
    const [sha, ref] = line.split("\t");
    refs.set(ref, sha);
  }
  const sha = refs.get(`refs/tags/${tag}^{}`) ?? refs.get(`refs/tags/${tag}`);
  if (!sha) throw new Error(`tag ${tag} not found in ${repo}`);
  return sha;
}

// ---------------------------------------------------------------------------
// Minimal YAML subset parser
// ---------------------------------------------------------------------------

/** Split source into logical lines, joining multi-line quoted scalars. */
function logicalLines(src) {
  const raw = src.replace(/\r\n/g, "\n").split("\n");
  const out = [];
  for (let i = 0; i < raw.length; i++) {
    let line = raw[i];
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    let text = line.trim();
    const m = text.match(/^(?:-\s+)?(?:[^'":\s][^:]*:\s+)?(['"])/);
    // A quoted scalar that is a value (after "key: " or "- " or alone) may span lines.
    const q = m ? m[1] : null;
    if (q && !quoteClosed(text, q)) {
      while (i + 1 < raw.length) {
        const next = raw[++i].trim();
        text += next === "" ? "\n" : (text.endsWith("\n") ? "" : " ") + next;
        if (quoteClosed(text, q)) break;
      }
    }
    out.push({ indent, text });
  }
  return out;
}

/** True when the first quote in `text` has a matching closing quote. */
function quoteClosed(text, q) {
  const start = text.indexOf(q);
  for (let i = start + 1; i < text.length; i++) {
    if (q === "'" && text[i] === "'") {
      if (text[i + 1] === "'") { i++; continue; }
      return true;
    }
    if (q === '"' && text[i] === "\\") { i++; continue; }
    if (q === '"' && text[i] === '"') return true;
  }
  return false;
}

function scalar(s) {
  s = s.trim();
  if (s.startsWith("'")) return s.slice(1, s.lastIndexOf("'")).replace(/''/g, "'");
  if (s.startsWith('"')) return JSON.parse(s.replace(/\n/g, "\\n"));
  if (s === "[]") return [];
  if (/^-?\d+$/.test(s)) return Number(s);
  if (s === "true") return true;
  if (s === "false") return false;
  if (s === "null" || s === "~") return null;
  if (/^[|>]/.test(s) || /^[[{&*!]/.test(s)) throw new Error(`unsupported YAML value: ${s}`);
  return s;
}

function splitKey(text) {
  const m = text.match(/^([^'":\s][^:]*?):(?:\s+(.*))?$/s);
  if (!m) throw new Error(`cannot parse YAML line: ${text.slice(0, 80)}`);
  return [m[1], m[2]];
}

function parseYaml(src) {
  const lines = logicalLines(src);
  let pos = 0;

  function parseNode(indent) {
    return lines[pos].text.startsWith("- ") || lines[pos].text === "-"
      ? parseSeq(indent)
      : parseMap(indent);
  }

  function parseSeq(indent) {
    const arr = [];
    while (pos < lines.length && lines[pos].indent === indent && /^-(\s|$)/.test(lines[pos].text)) {
      const rest = lines[pos].text.slice(1).trim();
      if (rest === "") {
        pos++;
        arr.push(parseNode(lines[pos].indent));
      } else if (/^[^'":\s][^:]*:(\s|$)/.test(rest)) {
        // "- key: value" starts a nested map whose keys sit at indent + 2.
        lines[pos] = { indent: indent + 2, text: rest };
        arr.push(parseMap(indent + 2));
      } else {
        arr.push(scalar(rest));
        pos++;
      }
    }
    return arr;
  }

  function parseMap(indent) {
    const obj = {};
    while (pos < lines.length && lines[pos].indent === indent && !lines[pos].text.startsWith("- ")) {
      const [key, value] = splitKey(lines[pos].text);
      pos++;
      if (value !== undefined) {
        obj[key] = scalar(value);
      } else if (pos < lines.length && (lines[pos].indent > indent ||
          (lines[pos].indent === indent && lines[pos].text.startsWith("- ")))) {
        obj[key] = parseNode(lines[pos].indent);
      } else {
        obj[key] = null;
      }
    }
    return obj;
  }

  const root = parseNode(lines[0].indent);
  if (pos !== lines.length) throw new Error(`YAML parse stopped early at logical line ${pos}`);
  return root;
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

const sortedUnique = (arr) => [...new Set(arr)].sort();
const sortedKeys = (obj) => Object.keys(obj).sort();

function buildMasvs(yamlPath) {
  const doc = parseYaml(readFileSync(yamlPath, "utf8"));
  if (doc.metadata?.version !== `v${PINS.masvs.version}`) {
    throw new Error(`unexpected MASVS version ${doc.metadata?.version}`);
  }
  const categories = [];
  const controls = {};
  for (const group of doc.groups) {
    categories.push({ id: group.id, title: group.title });
    for (const c of group.controls) {
      if (!MASVS_CONTROL_RE.test(c.id)) throw new Error(`bad MASVS control id ${c.id}`);
      controls[c.id] = c.statement;
    }
  }
  categories.sort((a, b) => a.id.localeCompare(b.id));
  const sortedControls = {};
  for (const id of sortedKeys(controls)) sortedControls[id] = controls[id];
  return { categories, controls: sortedControls };
}

function buildMaswe(yamlPath, controls) {
  const doc = parseYaml(readFileSync(yamlPath, "utf8"));
  if (doc.metadata?.version !== `v${PINS.maswe.version}`) {
    throw new Error(`unexpected MASWE version ${doc.metadata?.version}`);
  }
  const out = {};
  for (const key of sortedKeys(doc.weaknesses)) {
    const w = doc.weaknesses[key];
    if (!MASWE_RE.test(key) || w.id !== key) throw new Error(`bad MASWE id ${key}`);
    // Source already uses full control IDs (mappings.masvs-v2); no short-form expansion needed.
    const masvs = sortedUnique(w.mappings?.["masvs-v2"] ?? []);
    for (const id of masvs) {
      if (!controls[id]) throw new Error(`${key} maps to unknown MASVS control ${id}`);
    }
    const entry = { title: w.title, masvs, platform: [...(w.platform ?? [])] };
    const cwe = w.mappings?.cwe;
    if (Array.isArray(cwe) && cwe.length > 0) entry.cwe = [...new Set(cwe)].sort((a, b) => a - b);
    out[key] = entry;
  }
  return out;
}

function frontMatter(file) {
  const lines = readFileSync(file, "utf8").split("\n");
  if (lines[0] !== "---") return {};
  const fm = {};
  for (let i = 1; i < lines.length && lines[i] !== "---"; i++) {
    const m = lines[i].match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (m) fm[m[1]] = m[2].trim();
  }
  return fm;
}

function unquote(s) {
  if (s.length >= 2 && ((s[0] === "'" && s.at(-1) === "'") || (s[0] === '"' && s.at(-1) === '"'))) {
    return s[0] === "'" ? s.slice(1, -1).replace(/''/g, "'") : JSON.parse(s);
  }
  return s;
}

function idList(raw) {
  if (!raw) return [];
  const inner = raw.startsWith("[") ? raw.slice(1, raw.lastIndexOf("]")) : raw;
  return inner.split(",").map((s) => unquote(s.trim())).filter(Boolean);
}

function walk(dir) {
  const files = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) files.push(...walk(p));
    else files.push(p);
  }
  return files;
}

function buildMastg(extractDir, maswe) {
  const out = {};
  const files = walk(extractDir).filter((f) => /MASTG-TEST-\d+\.md$/.test(f)).sort();
  for (const file of files) {
    const fm = frontMatter(file);
    // Legacy v1-style tests have no id; only real MASTG-TEST-#### ids are kept.
    if (!fm.id || !MASTG_TEST_RE.test(unquote(fm.id))) continue;
    const id = unquote(fm.id);
    if (out[id]) throw new Error(`duplicate ${id}`);
    const ids = sortedUnique([...idList(fm.weakness), ...idList(fm.maswe)]);
    for (const w of ids) {
      if (!MASWE_RE.test(w)) throw new Error(`${id} has malformed weakness id ${w}`);
    }
    for (const w of ids) {
      if (!MASWE_RE.test(w) || !maswe[w]) throw new Error(`${id} references unknown weakness ${w}`);
    }
    const entry = {
      title: unquote(fm.title ?? ""),
      platform: unquote(fm.platform ?? ""),
      maswe: ids,
    };
    out[id] = entry;
  }
  const sorted = {};
  for (const id of sortedKeys(out)) sorted[id] = out[id];
  return sorted;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const work = mkdtempSync(join(tmpdir(), "rnsec-owasp-"));
  try {
    for (const [name, pin] of Object.entries(PINS)) {
      if (!pin.tag) continue;
      const remote = remoteCommit(pin.repo, pin.tag);
      if (remote !== pin.commit) {
        throw new Error(`${name} ${pin.tag}: ls-remote gives ${remote}, pinned ${pin.commit}`);
      }
    }

    const masvsYaml = join(work, "OWASP_MASVS.yaml");
    const msweYaml = join(work, "OWASP_MASWE.yaml");
    const tarball = join(work, "mastg.tgz");
    curl(PINS.masvs.url, masvsYaml);
    curl(PINS.maswe.url, msweYaml);
    curl(PINS.mastg.url, tarball);

    const names = run("tar", ["tzf", tarball]).split("\n").filter(Boolean);
    const top = names[0].split("/")[0];
    if (!top.endsWith(`-${PINS.mastg.commit.slice(0, 7)}`)) {
      throw new Error(`MASTG tarball top-level dir ${top} does not match pinned commit`);
    }
    const wanted = names.filter((n) => /\/tests(-beta)?\/.*MASTG-TEST-\d+\.md$/.test(n));
    const extractDir = join(work, "mastg");
    mkdirSync(extractDir);
    run("tar", ["xzf", tarball, "-C", extractDir, ...wanted]);

    const masvs = buildMasvs(masvsYaml);
    const maswe = buildMaswe(msweYaml, masvs.controls);
    const mastg = buildMastg(extractDir, maswe);

    const sources = {};
    for (const [name, pin] of Object.entries(PINS)) {
      sources[name] = { version: pin.version, tag: pin.tag, commit: pin.commit, url: pin.url };
    }
    const snapshot = { sources, masvs, maswe, mastg };
    mkdirSync(dirname(OUT_FILE), { recursive: true });
    writeFileSync(OUT_FILE, JSON.stringify(snapshot, null, 2) + "\n");
    console.log(
      `wrote ${OUT_FILE}: ${masvs.categories.length} categories, ` +
        `${Object.keys(masvs.controls).length} controls, ${Object.keys(maswe).length} MASWE, ` +
        `${Object.keys(mastg).length} MASTG tests`
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

main();
