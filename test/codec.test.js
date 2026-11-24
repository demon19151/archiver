import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { compress, decompress, ArchiveError, _testInternals } from '../src/codec.js';

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

test('incompressible binary has only small overhead', () => {
  const input = Buffer.from(Array.from({ length: 4096 }, () => Math.floor(Math.random() * 256)));
  const archive = compress(input);
  assert.ok(archive.length <= input.length + 20);
  assert.deepEqual(decompress(archive), input);
});

test('single-byte files use compact records and all byte values round-trip', () => {
  for (let value = 0; value < 256; value++) {
    const input = Buffer.from([value]);
    const archive = compress(input);
    assert.ok(archive.length <= 2, `byte ${value} used ${archive.length} bytes`);
    assert.deepEqual(decompress(archive), input);
    if (value > 0 && value < 0xf0) assert.equal(archive.length, 1, `byte ${value} should fit in one byte`);
  }
});

test('high-entropy multi-megabyte input takes the store path', () => {
  const input = Buffer.alloc(2 * 1024 * 1024);
  let state = 0x12345678;
  for (let i = 0; i < input.length; i++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    input[i] = state & 0xff;
  }
  const archive = compress(input);
  assert.ok(archive.length <= input.length + 5);
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

test('malformed method stream is rejected', () => {
  const archive = compress(Buffer.from('hello'));
  archive[0] = 0xf9;
  assert.throws(() => decompress(archive), ArchiveError);
});

// Build tiny independently specified new-method records to exercise decoder
// boundaries even when the adaptive encoder selects another method.
function record(method, original, payload) {
  assert.ok(original.length < 128);
  return Buffer.concat([
    Buffer.from([0xf0 + method, original.length]),
    createHash('sha256').update(original).digest().subarray(0, 4), payload
  ]);
}

test('raw LZSS decoder accepts references and rejects truncated tokens', () => {
  const input = Buffer.from('abcabcabcabc!');
  const payload = _testInternals.lzssEncode(input);
  const archive = record(9, input, payload);
  assert.deepEqual(decompress(archive), input);
  assert.throws(() => decompress(archive.subarray(0, -2)), ArchiveError);
  assert.throws(() => decompress(Buffer.concat([archive, Buffer.from([0])])), ArchiveError);
});

test('small-file bit-packed LZSS round-trips and rejects truncated streams', () => {
  const input = Buffer.from('short text: repeat this phrase. '.repeat(3));
  const payload = _testInternals.smallLzEncode(input);
  const archive = record(12, input, payload);
  assert.deepEqual(decompress(archive), input);
  assert.ok(payload.length < input.length);
  assert.throws(() => decompress(archive.subarray(0, -1)), ArchiveError);
});

test('English prose dictionary improves repeated-word text without changing bytes', () => {
  const paragraphs = [
    'The report describes how the archive is built and how the restored file can be checked. Each section uses familiar words, punctuation, and short examples to explain the result. The program looks for repeated sequences, then stores the dictionary needed to rebuild the original bytes. ',
    'A reader can follow the steps, compare the source with the output, and verify that no information has changed. Repeated phrases are common in ordinary writing, although their positions and lengths vary from one paragraph to another. This gives a compressor useful patterns to find. '
  ];
  const input = Buffer.from(Array.from({ length: 100 }, (_, i) => `${paragraphs[i % 2]}Section ${i}: the compression result must preserve every original byte.\n`).join(''));
  const archive = compress(input);
  assert.ok([0xf8, 0xfb, 0xfd, 0xfe].includes(archive[0]), 'a text compression method should be selected');
  assert.ok(archive.length < input.length * 0.04, `archive was ${archive.length} bytes for ${input.length} bytes`);
  assert.deepEqual(decompress(archive), input);
  assert.throws(() => decompress(archive.subarray(0, -1)), ArchiveError);
});

test('word-dictionary decoder validates malformed tokens and indexes', () => {
  const input = Buffer.from(('The archive stores the original bytes. Each repeated phrase can use a compact word dictionary.\n').repeat(300));
  const archive = compress(input);
  assert.notEqual(archive[0], 0xf0);
  const brokenIndex = Buffer.from(archive);
  brokenIndex[brokenIndex.length - 1] ^= 0x40;
  assert.throws(() => decompress(brokenIndex), ArchiveError);
});

test('mixed RLE preserves literal spans and runs with strict bounds', () => {
  const input = Buffer.from('abzzzzzz!');
  const payload = Buffer.from([4, 97, 98, 13, 122, 2, 33]);
  assert.deepEqual(decompress(record(10, input, payload)), input);
  for (const bad of [Buffer.from([0]), Buffer.from([255,255,255,255,255,1]), Buffer.from([40,97]), Buffer.from([19,122]), Buffer.from([13])]) {
    assert.throws(() => decompress(record(10, input, bad)), ArchiveError);
  }
});

test('compact Huffman table validates symbol count, codes and padding', () => {
  // Direct Huffman: one symbol A, code 0 of length 1, eight output symbols.
  const input = Buffer.alloc(8, 65);
  const params = Buffer.from([2, 8,0,0,0, 1,0, 65, 0x10]);
  const archive = record(11, input, Buffer.concat([params, Buffer.from([0])]));
  assert.deepEqual(decompress(archive), input);
  for (const [offset, value] of [[6, 9], [11, 255], [14, 0], [14, 0x11]]) {
    const corrupt = Buffer.from(archive);
    corrupt[offset] = value;
    assert.throws(() => decompress(corrupt), ArchiveError);
  }
});

test('random prefix followed by zeros uses mixed RLE efficiently', () => {
  const input = Buffer.alloc(262144);
  let state = 0x12345678;
  for (let i = 0; i < 2048; i++) {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    input[i] = state & 255;
  }
  const archive = compress(input);
  assert.equal(archive[0], 0xfa);
  assert.ok(archive.length < 2080);
  assert.deepEqual(decompress(archive), input);
  for (const cut of [1, 4, 6, 7, 8, archive.length - 1]) {
    assert.throws(() => decompress(archive.subarray(0, cut)), ArchiveError);
  }
});
