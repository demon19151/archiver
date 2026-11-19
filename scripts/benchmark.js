import { readFile } from 'node:fs/promises';
import { basename, extname } from 'node:path';
import { performance } from 'node:perf_hooks';
import { compress } from '../src/codec.js';

const files = process.argv.slice(2);
if (!files.length) {
  console.error('Использование: node scripts/benchmark.js file1 file2 ...');
  process.exit(1);
}

console.log('Файл\tФормат\tИсходный\tАрхив\t%\tКоэффициент\tмс');
for (const file of files) {
  const input = await readFile(file);
  const started = performance.now();
  const archive = compress(input);
  const elapsed = (performance.now() - started).toFixed(1);
  const percent = input.length ? (archive.length / input.length * 100).toFixed(2) : '—';
  const coefficient = archive.length ? (input.length / archive.length).toFixed(3) : '—';
  console.log(`${basename(file)}\t${extname(file) || 'без расширения'}\t${input.length}\t${archive.length}\t${percent}\t${coefficient}x\t${elapsed}`);
}
