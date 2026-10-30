#!/usr/bin/env node
// Must-still-fire gate: checks that every known true positive is still reported.
// Usage: node bench/check-tps.mjs <known-tps.json> <scan output dir>
// The scan output dir holds <repo>.json files written by bench/run.mjs.
// A TP matches on rule + file (path ends with /<repo>/<file>) and, when the TP has a line, a line within +-3.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const [tpsPath, outDir] = process.argv.slice(2);
if (!tpsPath || !outDir) {
  console.error('usage: node bench/check-tps.mjs <known-tps.json> <scan output dir>');
  process.exit(2);
}

const { tps } = JSON.parse(readFileSync(tpsPath, 'utf8'));
const cache = new Map();
const findingsFor = (repo) => {
  if (!cache.has(repo)) {
    const p = join(outDir, `${repo}.json`);
    cache.set(repo, existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')).findings ?? [] : null);
  }
  return cache.get(repo);
};

let lost = 0;
for (const tp of tps) {
  const findings = findingsFor(tp.repo);
  const suffix = `/${tp.repo}/${tp.file}`;
  const hit = findings?.find(
    (f) =>
      f.ruleId === tp.rule &&
      f.filePath.endsWith(suffix) &&
      (tp.line == null || (typeof f.line === 'number' && Math.abs(f.line - tp.line) <= 3)),
  );
  if (hit) console.log(`OK    ${tp.rule} ${tp.repo}/${tp.file}:${hit.line ?? '-'} [${hit.severity}]`);
  else {
    lost++;
    console.log(`LOST  ${tp.rule} ${tp.repo}/${tp.file}:${tp.line ?? '-'}${findings ? '' : ' (no scan output for repo)'}`);
  }
}
console.log(`\n${tps.length - lost}/${tps.length} known TPs still reported`);
process.exit(lost ? 1 : 0);
