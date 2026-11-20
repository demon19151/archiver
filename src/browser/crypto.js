import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer/';

// Synchronous equivalent of the small node:crypto API used by the shared
// codec. No compression logic is duplicated in this browser adapter.
export function createHash(algorithm) {
  if (algorithm !== 'sha256') throw new Error('Unsupported checksum');
  const hash = sha256.create();
  return {
    update(bytes) { hash.update(bytes); return this; },
    digest() { return Buffer.from(hash.digest()); }
  };
}

export function timingSafeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}
