import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { compress, decompress, ArchiveError, _testInternals as internals } from '../src/codec.js';
import { compressionFixtures, randomBytes } from '../fixtures/compression.js';

function varUint(value) {
  const bytes = [];
  while (value >= 128) {
    bytes.push((value & 127) | 128);
    value = Math.floor(value / 128);
  }
  return Buffer.from([...bytes, value]);
}

function record(method, input, payload) {
  return Buffer.concat([
    Buffer.from([0xf0 + method]), varUint(input.length),
    createHash('sha256').update(input).digest().subarray(0, 4), payload
  ]);
}

test('BWT sorts and restores non-power-of-two, periodic and binary blocks', () => {
  for (const size of [1, 2, 3, 7, 31, 255, 256, 257, 4093, 8192]) {
    for (const input of [randomBytes(size), Buffer.alloc(size, 123), Buffer.from('banana'.repeat(size)).subarray(0, size)]) {
      const encoded = internals.bwtEncode(input);
      assert.deepEqual(internals.bwtDecode(encoded.data, encoded.primary), input);
    }
  }
  assert.throws(() => internals.bwtDecode(Buffer.alloc(0), 0), ArchiveError);
  assert.throws(() => internals.bwtDecode(Buffer.from('abc'), 3), ArchiveError);
});

test('MTF run coding preserves all ranks and validates lengths', () => {
  for (const input of [Buffer.alloc(262144), randomBytes(10000), Buffer.from(Array.from({ length: 256 }, (_, i) => i))]) {
    const encoded = internals.mtfRunsEncode(input);
    assert.deepEqual(internals.mtfRunsDecode(encoded, input.length), input);
  }
  for (const bad of [[], [0], [0, 0], [0, 100], [1, 2, 3, 4]]) {
    assert.throws(() => internals.mtfRunsDecode(Buffer.from(bad), 3), ArchiveError);
  }
});

test('context blocks preserve mixed raw and compressed blocks across boundaries', () => {
  const input = Buffer.concat([
    randomBytes(128 * 1024),
    Buffer.from('Contexts and repeated words. '.repeat(6000)).subarray(0, 128 * 1024),
    randomBytes(113, 9876)
  ]);
  const payload = internals.contextBlocksEncode(input, 128 * 1024);
  // block size=128 KiB (LE varint), then count=3, first block is stored because its bytes are high entropy.
  assert.equal(payload[0], 128);
  assert.equal(payload[1], 128);
  assert.equal(payload[2], 8);
  assert.equal(payload[3], 3);
  assert.equal(payload[4], 0);
  assert.deepEqual(internals.contextBlocksDecode(payload, input.length), input);
  const archive = record(13, input, payload);
  assert.deepEqual(decompress(archive), input);
  assert.throws(() => decompress(Buffer.concat([archive, Buffer.from([0])])), ArchiveError);
  for (const cut of [0, 1, 4, 6, 10, archive.length - 1]) {
    assert.throws(() => decompress(archive.subarray(0, cut)), ArchiveError);
  }
});

test('BWT header corruption fails with ArchiveError instead of unchecked reads', () => {
  const input = Buffer.from('context transform: banana bandana. '.repeat(60));
  const payload = internals.contextBlocksEncode(input, 128 * 1024);
  assert.ok([1, 2].includes(payload[3]), 'fixture must use a compressed block');
  for (let i = 0; i < payload.length; i++) {
    const corrupt = Buffer.from(payload);
    corrupt[i] ^= 0x80;
    try {
      // Some changed parameters can describe another valid stream, but the
      // outer SHA checksum must still prevent returning different file bytes.
      assert.deepEqual(decompress(record(13, input, corrupt)), input);
    } catch (error) {
      assert.ok(error instanceof ArchiveError, `${i}: ${error.stack}`);
    }
  }
});

test('numeric filters are bit-exact with wraparound, odd sizes and short tails', () => {
  for (const id of [8, 9, 10, 11]) {
    for (const size of [0, 1, 2, 3, 4, 5, 17, 4099]) {
      for (const input of [randomBytes(size), Buffer.alloc(size, 255)]) {
        const encoded = internals.numericTransform(input, id);
        assert.deepEqual(internals.numericTransform(encoded, id, true), input);
      }
    }
  }
});

test('16-bit numeric signal uses filtered compression and rejects invalid filters', () => {
  const input = compressionFixtures().find(([name]) => name === 'pcm16-signal')[1];
  const archive = compress(input);
  assert.equal(archive[0], 0xff);
  assert.ok(archive.length < input.length / 2);
  assert.deepEqual(decompress(archive), input);
  const corrupt = Buffer.from(archive);
  let position = 1;
  while (corrupt[position++] & 128) { /* Skip original-size varint. */ }
  corrupt[position + 4] = 255;
  assert.throws(() => decompress(corrupt), ArchiveError);
  assert.throws(() => decompress(archive.subarray(0, -1)), ArchiveError);
});

test('deterministic context fuzz round-trips through the public archive API', () => {
  for (let seed = 1; seed <= 40; seed++) {
    const input = randomBytes(seed * 67 + 256, seed * 12345);
    const alphabetSize = seed % 3 === 0 ? 256 : seed % 13 + 2;
    for (let i = 0; i < input.length; i++) input[i] %= alphabetSize;
    const archive = record(13, input, internals.contextBlocksEncode(input));
    assert.deepEqual(decompress(archive), input, `seed ${seed}`);
  }
});
