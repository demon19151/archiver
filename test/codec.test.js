import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { compress, decompress, ArchiveError } from '../src/codec.js';

const sha = data => createHash('sha256').update(data).digest('hex');
const roundTrip = (name, input) => test(name, () => {
  const archive = compress(input);
  const restored = decompress(archive);
  assert.deepEqual(restored, input);
  assert.equal(sha(restored), sha(input));
});

roundTrip('empty file', Buffer.alloc(0));
roundTrip('one byte', Buffer.from([0x7f]));
roundTrip('zero bytes', Buffer.alloc(200_000));
roundTrip('repeated text', Buffer.from('The quick brown fox jumps over the lazy dog. '.repeat(10_000)));
roundTrip('Russian and English text', Buffer.from('Привет, мир! Hello, world! Это проверка UTF-8.\n'.repeat(3000)));
roundTrip('JSON', Buffer.from(JSON.stringify({ rows: Array.from({ length: 2000 }, (_, i) => ({ id: i, name: 'value', active: i % 2 === 0 })) })));
roundTrip('CSV', Buffer.from(Array.from({ length: 10000 }, (_, i) => `${i},Москва,100.25,ok\n`).join('')));
roundTrip('binary data', Buffer.from(Array.from({ length: 100_000 }, (_, i) => (i * 73) & 255)));
roundTrip('random bytes', Buffer.from(Array.from({ length: 32_000 }, () => Math.floor(Math.random() * 256))));
roundTrip('already compressed-like data', Buffer.from(Array.from({ length: 80_000 }, () => Math.floor(Math.random() * 256))));
roundTrip('small image-like data', Buffer.concat([Buffer.from([137, 80, 78, 71]), Buffer.alloc(30_000, 33), Buffer.from([0, 0, 0, 0])]));
roundTrip('PCM-like audio', Buffer.from(Array.from({ length: 100_000 }, (_, i) => Math.round(127 + 80 * Math.sin(i / 20)) & 255)));

test('empty archive has compact representation', () => {
  assert.equal(compress(Buffer.alloc(0)).length, 1);
  assert.deepEqual(decompress(compress(Buffer.alloc(0))), Buffer.alloc(0));
});

test('100 KB zero file uses a compact repeat representation', () => {
  const archive = compress(Buffer.alloc(100_000));
  assert.ok(archive.length <= 16, `archive was ${archive.length} bytes`);
  assert.deepEqual(decompress(archive), Buffer.alloc(100_000));
});

test('repeated text is smaller than the previous header-heavy encoding', () => {
  const input = Buffer.from('hello world '.repeat(567));
  const archive = compress(input);
  assert.ok(archive.length <= 32, `archive was ${archive.length} bytes`);
  assert.deepEqual(decompress(archive), input);
});

test('delta transform compresses structured 32-bit binary values', () => {
  const input = Buffer.alloc(50_000 * 4);
  for (let i = 0; i < 50_000; i++) input.writeUInt32LE(i, i * 4);
  const archive = compress(input);
  assert.ok(archive.length < input.length / 5, `archive was ${archive.length} bytes`);
  assert.deepEqual(decompress(archive), input);
});

test('fast profile round-trips chunk-sized mixed data', () => {
  const input = Buffer.alloc(256 * 1024);
  for (let i = 0; i < input.length; i++) input[i] = (i * 37 + (i >>> 8)) & 255;
  const archive = compress(input, { fast: true });
  assert.deepEqual(decompress(archive), input);
});

test('incompressible binary has only small overhead', () => {
  const input = Buffer.from(Array.from({ length: 4096 }, () => Math.floor(Math.random() * 256)));
  const archive = compress(input);
  assert.ok(archive.length <= input.length + 20);
  assert.deepEqual(decompress(archive), input);
});

test('truncated archive is rejected', () => {
  const archive = compress(Buffer.from('hello'));
  assert.throws(() => decompress(archive.subarray(0, archive.length - 1)), error => error instanceof ArchiveError && ['invalid_archive', 'checksum_mismatch'].includes(error.code));
});

test('unknown version is rejected', () => {
  const archive = Buffer.alloc(64);
  archive.write('SARC', 0);
  archive.writeUInt16LE(99, 4);
  assert.throws(() => decompress(archive), error => error.code === 'unsupported_version');
});

test('wrong checksum is rejected', () => {
  const archive = compress(Buffer.from('hello'));
  archive[1] ^= 1;
  assert.throws(() => decompress(archive), error => error.code === 'checksum_mismatch');
});

test('unknown method is rejected', () => {
  const archive = compress(Buffer.from('hello'));
  archive[0] = 0xf9;
  assert.throws(() => decompress(archive), error => error.code === 'unsupported_method');
});
