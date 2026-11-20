import { compress, decompress } from '../codec.js';

self.onmessage = ({ data: { id, operation, buffer } }) => {
  try {
    if (operation !== 'compress' && operation !== 'decompress') throw new Error('Неизвестная операция');
    const started = performance.now();
    const output = operation === 'compress' ? compress(new Uint8Array(buffer)) : decompress(new Uint8Array(buffer));
    // Buffer may be a slice of a pool. Transfer only its own bytes.
    const result = Uint8Array.from(output);
    self.postMessage({ id, buffer: result.buffer, codecMs: performance.now() - started }, [result.buffer]);
  } catch (error) {
    self.postMessage({ id, error: { code: error.code || 'codec_error', message: error.message } });
  }
};
