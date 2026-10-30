#!/usr/bin/env node
// Aggregate bench/run.mjs results.
// Usage: node bench/report.mjs --out <results dir> [--save <aggregate.json>] [--compare <baseline.json>] [--top 20]
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(`--${n}`); return i === -1 ? undefined : args[i + 1]; };
const out = opt('out');
if (!out) {
  console.error('usage: node bench/report.mjs --out <results dir> [--save file] [--compare baseline.json] [--top N]');
  process.exit(2);
}
const top = Number(opt('top') || 20);
const median = (xs) => {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

const apps = {};
const rules = {}; // ruleId -> { total, perApp }
const sev = {};
const exceptions = {}; // ruleId -> count (from stderr when run with RNSEC_VERBOSE=1)
let unreadable = 0;
for (const f of readdirSync(out).filter((f) => f.endsWith('.meta.json')).sort()) {
  const meta = JSON.parse(readFileSync(join(out, f), 'utf8'));
  const a = { ...meta, rules: {}, severity: {} };
  const jp = join(out, `${meta.name}.json`);
  if (!meta.error && existsSync(jp)) {
    const j = JSON.parse(readFileSync(jp, 'utf8'));
    for (const x of j.findings) {
      a.rules[x.ruleId] = (a.rules[x.ruleId] || 0) + 1;
      a.severity[x.severity] = (a.severity[x.severity] || 0) + 1;
      rules[x.ruleId] ??= { total: 0, perApp: {} };
      rules[x.ruleId].total++;
      rules[x.ruleId].perApp[meta.name] = (rules[x.ruleId].perApp[meta.name] || 0) + 1;
      sev[x.severity] = (sev[x.severity] || 0) + 1;
    }
  }
  const ep = join(out, `${meta.name}.stderr.txt`);
  if (existsSync(ep)) {
    for (const line of readFileSync(ep, 'utf8').split('\n')) {
      const m = line.match(/Rule (\S+) failed/);
      if (m) exceptions[m[1]] = (exceptions[m[1]] || 0) + 1;
      else if (/Could not scan/.test(line)) { unreadable++; }
    }
  }
  apps[meta.name] = a;
}

const names = Object.keys(apps);
const total = Object.values(apps).reduce((n, a) => n + (a.findings || 0), 0);
const agg = {
  rnsecVersion: names.length ? apps[names[0]].rnsecVersion : null,
  rnsecHead: names.length ? apps[names[0]].rnsecHead : null,
  total,
  severity: sev,
  medianFindingsPerApp: median(names.map((n) => apps[n].findings || 0)),
  medianSecondsPerApp: median(names.map((n) => apps[n].seconds || 0)),
  nonZeroExit: names.filter((n) => apps[n].exitCode !== 0).length,
  ruleExceptions: exceptions,
  unreadableFiles: unreadable,
  apps: Object.fromEntries(names.map((n) => {
    const { name, findings, scannedFiles, seconds, exitCode, npmCalls, headSha, pinnedSha, shaExact, severity, rules: r, error, note } = apps[n];
    return [n, { findings, scannedFiles, seconds, exitCode, npmCalls, headSha, pinnedSha, shaExact, severity, rules: r, error, note }];
  })),
  rules: Object.fromEntries(Object.entries(rules).map(([k, v]) => [k, v.total])),
};

const pad = (s, w) => String(s).padEnd(w);
const num = (s, w) => String(s).padStart(w);
console.log(`rnsec ${agg.rnsecVersion} (${agg.rnsecHead}), ${names.length} apps`);
console.log('\nPer app');
console.log(`${pad('app', 26)}${num('files', 7)}${num('findings', 10)}${num('HIGH+', 7)}${num('secs', 8)}${num('exit', 6)}${num('npm', 5)}  sha`);
for (const n of names) {
  const a = apps[n];
  const hi = (a.severity.HIGH || 0) + (a.severity.CRITICAL || 0);
  console.log(`${pad(n, 26)}${num(a.scannedFiles ?? '-', 7)}${num(a.findings ?? 'ERR', 10)}${num(hi, 7)}${num(a.seconds?.toFixed(1) ?? '-', 8)}${num(a.exitCode ?? '-', 6)}${num(a.npmCalls ?? '-', 5)}  ${(a.headSha || '').slice(0, 7)}${a.shaExact === false ? ' (NOT pinned)' : ''}${a.error ? ' ERROR: ' + a.error : ''}`);
}
console.log(`\nTotal ${total}; severity ${JSON.stringify(sev)}; median findings/app ${agg.medianFindingsPerApp}; median secs/app ${agg.medianSecondsPerApp.toFixed(1)}; non-zero exits ${agg.nonZeroExit}`);
const ex = Object.entries(exceptions);
console.log(`Rule exceptions (needs run.mjs --verbose): ${ex.length ? ex.map(([k, v]) => `${k}=${v}`).join(', ') : 'none seen'}; unreadable files: ${unreadable}`);

console.log(`\nTop ${top} rules by volume`);
const sorted = Object.entries(agg.rules).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
for (const [id, c] of sorted.slice(0, top)) {
  const per = names.filter((n) => rules[id].perApp[n]).map((n) => `${n}:${rules[id].perApp[n]}`).join(' ');
  console.log(`${num(c, 6)}  ${pad(id, 42)}${per}`);
}
console.log(`\n${sorted.length} distinct rules fired`);

const cmp = opt('compare');
if (cmp) {
  const base = JSON.parse(readFileSync(cmp, 'utf8'));
  console.log(`\nDelta vs ${cmp} (${base.rnsecVersion} ${base.rnsecHead})`);
  const ids = new Set([...Object.keys(base.rules), ...Object.keys(agg.rules)]);
  const rows = [...ids].map((id) => [id, base.rules[id] || 0, agg.rules[id] || 0]).filter(([, b, c]) => b !== c).sort((a, b) => Math.abs(b[2] - b[1]) - Math.abs(a[2] - a[1]));
  for (const [id, b, c] of rows) console.log(`${pad(id, 42)}${num(b, 6)} -> ${num(c, 6)}  ${c - b > 0 ? '+' : ''}${c - b}`);
  if (!rows.length) console.log('no per-rule changes');
  for (const n of names) {
    const b = base.apps?.[n]?.findings;
    if (b !== undefined && b !== apps[n].findings) console.log(`app ${pad(n, 24)}${num(b, 6)} -> ${num(apps[n].findings, 6)}`);
  }
  console.log(`Total ${base.total} -> ${agg.total}  (${agg.total - base.total >= 0 ? '+' : ''}${agg.total - base.total})`);
}

const save = opt('save');
if (save) {
  writeFileSync(save, JSON.stringify(agg, null, 2));
  console.log(`\nsaved ${save}`);
}
