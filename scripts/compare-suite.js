import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { readFile } from 'node:fs/promises';
import { compress, decompress } from '../src/codec.js';
import { compressionFixtures } from '../fixtures/compression.js';

const ref = process.argv[2] || '8e18ef0';
const source = execFileSync('git', ['show', `${ref}:src/codec.js`], { encoding: 'utf8' });
const before = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const fixtures = compressionFixtures();
// Optional real input files supplied by the user; no filename heuristics.
for (const path of process.argv.slice(3)) fixtures.push([path, await readFile(path)]);
let totalInput = 0;
let totalBefore = 0;
let totalAfter = 0;
console.log('Fixture\tInput\tBefore\tAfter\tBefore ms\tAfter ms');
for (const [name, input] of fixtures) {
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
  console.log(`${name}\t${input.length}\t${old.length}\t${archive.length}\t${(middle-start).toFixed(1)}\t${(end-middle).toFixed(1)}`);
}
console.log(`TOTAL\t${totalInput}\t${totalBefore}\t${totalAfter}`);
console.log(`Synthetic ratios: ${(totalInput/totalBefore).toFixed(3)} -> ${(totalInput/totalAfter).toFixed(3)} (not arena scores)`);
