import { compress, decompress } from '../codec.js';

self.onmessage = ({ data: { id, operation, buffer } }) => {
  try {
    if (operation !== 'compress' && operation !== 'decompress') throw new Error('Неизвестная операция');
    const started = performance.now();
    const output = operation === 'compress' ? compress(new Uint8Array(buffer)) : decompress(new Uint8Array(buffer));
    // Node's Buffer may share a larger pool ArrayBuffer. Transfer directly
    // only when it owns the exact range; otherwise make one safe copy.
    const ownsExactBuffer = output.byteOffset === 0 && output.byteLength === output.buffer.byteLength;
    const result = ownsExactBuffer ? new Uint8Array(output.buffer) : Uint8Array.from(output);
    self.postMessage({ id, buffer: result.buffer, codecMs: performance.now() - started }, [result.buffer]);
  } catch (error) {
    self.postMessage({ id, error: { code: error.code || 'codec_error', message: error.message } });
  }
};
