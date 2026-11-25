import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createContext, runInContext } from 'node:vm';
import { performance } from 'node:perf_hooks';
import { buildBrowser } from '../scripts/build-browser.js';
import { compress, decompress } from '../src/codec.js';
import { compressionFixtures } from '../fixtures/compression.js';

test('browser worker produces server-compatible archives, including large files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'opencode', 'browser-codec-'));
  try {
    const filename = join(directory, 'worker.js');
    await buildBrowser(filename);
    let reply;
    const self = { postMessage: value => { reply = value; } };
    const context = createContext({ self, performance, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView });
    runInContext(await readFile(filename, 'utf8'), context);
    const callWorker = (operation, input) => {
      reply = null;
      self.onmessage({ data: { id: 1, operation, buffer: Uint8Array.from(input).buffer } });
      assert.ok(reply, 'worker must return a result');
      assert.equal(reply.error, undefined, JSON.stringify(reply.error));
      return Buffer.from(reply.buffer);
    };

    const cases = [
      Buffer.alloc(0),
      Buffer.from([255]),
      Buffer.from('Привет! Hello! '.repeat(1000)),
      Buffer.from(JSON.stringify(Array.from({ length: 5000 }, (_, id) => ({ id, city: 'Москва', active: true })))),
      Buffer.concat([randomBytes(2048), Buffer.alloc(262144)]),
      Buffer.from('abcabcabcabc!'),
      Buffer.from('token Huffman compression has repeated phrases. '.repeat(500)),
      Buffer.concat([Buffer.from('long-distance repeated data. '.repeat(4096)), randomBytes(80 * 1024), Buffer.from('long-distance repeated data. '.repeat(4096))]),
      randomBytes(1024 * 1024),
      Buffer.concat([Buffer.from('II*\0'), Buffer.alloc(8 * 1024 * 1024, 37)])
    ];
    // Exercise new block methods and multi-block decoding in the bundled code,
    // not only the Node implementation.
    for (const [name, input] of compressionFixtures()) {
      if (['english-varied-240k', 'russian-numbered', 'csv-varied', 'json-varied', 'pcm16-signal'].includes(name)) cases.push(input);
    }
    for (const input of cases) {
      const browserArchive = callWorker('compress', input);
      assert.deepEqual(browserArchive, compress(input), 'browser and server archives must match');
      assert.deepEqual(decompress(browserArchive), input);
      assert.deepEqual(callWorker('decompress', compress(input)), input);
    }

    const corrupt = compress(Buffer.from('checksum verification'));
    corrupt[1] ^= 1;
    self.onmessage({ data: { id: 2, operation: 'decompress', buffer: Uint8Array.from(corrupt).buffer } });
    assert.equal(reply.error.code, 'checksum_mismatch');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
