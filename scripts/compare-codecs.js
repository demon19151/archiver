import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';
import { compress, decompress } from '../src/codec.js';

// Specify a saved commit to reproduce the before/after comparison.
const reference = process.argv[2] || '4ee9c97';
const source = execFileSync('git', ['show', `${reference}:src/codec.js`], { encoding: 'utf8' });
const baseline = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
let state = 0x12345678;
function random(size) {
  const data = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    data[i] = state & 255;
  }
  return data;
}
const shortText = Buffer.from('Архиватор сохраняет данные без потерь. Выберите файлы, нажмите кнопку сжатия и скачайте результат. Повторяющиеся фрагменты заменяются ссылками. Проверка целостности защищает данные.\n');
const noisyZeros = Buffer.alloc(262144);
random(2048).copy(noisyZeros);
const sparse = Buffer.alloc(16384);
for (let i = 80; i < sparse.length; i += 211) sparse[i] = i & 255;
const cases = [
  ['short-ru', shortText],
  ['short-en', Buffer.from('A lossless archive preserves every byte. Select your files, compress them, and download the result. The decoder restores the original bytes using the dictionary stored in the archive. No external data is required.')],
  ['text-ru', Buffer.concat(Array.from({ length: 300 }, (_, i) => Buffer.concat([shortText, Buffer.from(`${i}\n`)])))],
  ['csv', Buffer.from(Array.from({ length: 5000 }, (_, i) => `${i},Москва,${i % 100},active\n`).join(''))],
  ['json', Buffer.from(JSON.stringify(Array.from({ length: 4000 }, (_, id) => ({ id, name: 'item', active: true }))))],
  ['noise+zeros', noisyZeros], ['sparse-zeros', sparse],
  ['random-64k', random(65536)], ['random-1m', random(1024 * 1024)],
  ['byte', Buffer.from([127])], ['empty', Buffer.alloc(0)]
];
for (const [, data] of cases) { baseline.compress(data); compress(data); }
console.log('Fixture\tInput\tBefore\tAfter\tBefore ms\tAfter ms');
for (const [name, input] of cases) {
  const time = fn => {
    const samples = [];
    let output;
    for (let i = 0; i < 5; i++) { const start = performance.now(); output = fn(input); samples.push(performance.now() - start); }
    return { output, ms: samples.sort((a,b) => a-b)[2].toFixed(2) };
  };
  const before = time(baseline.compress);
  const after = time(compress);
  assert.ok(after.output.length <= before.output.length, name);
  assert.deepEqual(decompress(before.output), input, `legacy: ${name}`);
  assert.deepEqual(decompress(after.output), input, name);
  console.log(`${name}\t${input.length}\t${before.output.length}\t${after.output.length}\t${before.ms}\t${after.ms}`);
}
