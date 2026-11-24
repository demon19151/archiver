import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { compress, decompress } from '../src/codec.js';
import { compressionFixtures } from '../fixtures/compression.js';

const ref = process.argv[2] || '8e18ef0';
const source = execFileSync('git', ['show', `${ref}:src/codec.js`], { encoding: 'utf8' });
const before = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const fixtures = compressionFixtures().map(([name, input]) => [name, input, 'synthetic']);
// Optional files and directories can be supplied; no filename-based codec rules.
async function addInput(path) {
  const info = await stat(path).catch(() => null);
  if (!info) throw new Error(`Input path not found: ${path}`);
  if (!info.isDirectory()) {
    fixtures.push([path, await readFile(path), 'supplied']);
    return;
  }
  const entries = await readdir(path, { withFileTypes: true });
  for (const entry of entries) {
    const child = join(path, entry.name);
    if (entry.isDirectory()) await addInput(child);
    else fixtures.push([child, await readFile(child), 'supplied']);
  }
}
for (const path of process.argv.slice(3)) await addInput(path);
let totalInput = 0;
let totalBefore = 0;
let totalAfter = 0;
let totalBeforeMs = 0;
let totalAfterMs = 0;
const groupTotals = new Map();
console.log('Fixture\tInput\tBefore\tAfter\tBefore ms\tAfter ms');
for (const [name, input, group] of fixtures) {
  const start = performance.now();
  const old = before.compress(input);
  const middle = performance.now();
  const archive = compress(input);
  const end = performance.now();
  assert.deepEqual(decompress(archive), input, name);
  assert.deepEqual(decompress(old), input, `legacy ${name}`);
  assert.ok(archive.length <= old.length, `size regression: ${name}`);
  totalInput += input.length;
  totalBefore += old.length;
  totalAfter += archive.length;
  totalBeforeMs += middle - start;
  totalAfterMs += end - middle;
  const totals = groupTotals.get(group) || { input: 0, before: 0, after: 0, beforeMs: 0, afterMs: 0, count: 0 };
  totals.input += input.length;
  totals.before += old.length;
  totals.after += archive.length;
  totals.beforeMs += middle - start;
  totals.afterMs += end - middle;
  totals.count++;
  groupTotals.set(group, totals);
  console.log(`${name}\t${input.length}\t${old.length}\t${archive.length}\t${(middle-start).toFixed(1)}\t${(end-middle).toFixed(1)}`);
}
console.log(`TOTAL\t${totalInput}\t${totalBefore}\t${totalAfter}`);
console.log(`TOTAL ms\t${totalBeforeMs.toFixed(1)}\t${totalAfterMs.toFixed(1)}\t${(totalAfterMs-totalBeforeMs).toFixed(1)} additional`);
for (const [group, totals] of groupTotals) {
  console.log(`${group}\t${totals.count} files\t${totals.input}\t${totals.before}\t${totals.after}\t${(totals.input/totals.before).toFixed(3)} -> ${(totals.input/totals.after).toFixed(3)}\t${(totals.afterMs-totals.beforeMs).toFixed(1)} additional ms`);
}
console.log(`Combined ratio: ${(totalInput/totalBefore).toFixed(3)} -> ${(totalInput/totalAfter).toFixed(3)} (not an arena score)`);
