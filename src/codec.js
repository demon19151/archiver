import { createHash, timingSafeEqual } from 'node:crypto';

export const MAX_ORIGINAL_SIZE = 128 * 1024 * 1024;
const MAGIC = Buffer.from('SARC');
const VERSION = 4;
const V3_VERSION = 3;
const V2_VERSION = 2;
const LEGACY_VERSION = 1;
const HEADER_SIZE = 28;
const STORE_HEADER_SIZE = 18;
const V3_HEADER_SIZE = 14;
const LEGACY_HEADER_SIZE = 64;
const WINDOW_SIZE = 65536;
const MAX_MATCH = 258;

export class ArchiveError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = 'ArchiveError';
    this.code = code;
    this.status = status;
  }
}

function fail(code, message, status = 400) {
  throw new ArchiveError(code, message, status);
}

function sha256(data) {
  return createHash('sha256').update(data).digest();
}

function hash3(data, i) {
  return (((data[i] * 251 + data[i + 1]) * 251 + data[i + 2]) & 0xffff);
}

// LZSS stream: a flag byte followed by up to eight tokens. A literal is one
// byte; a match is distance (uint16 LE, minus one) and length (uint8, minus 3).
function lzssEncode(input, searchLimit = 48) {
  const n = input.length;
  const head = new Int32Array(65536);
  head.fill(-1);
  const previous = new Int32Array(WINDOW_SIZE);
  previous.fill(-1);
  const result = new Uint8Array(n + Math.ceil(n / 8) + 16);
  let resultLength = 0;
  let position = 0;

  const insert = (at) => {
    if (at + 2 >= n) return;
    const h = hash3(input, at);
    const slot = at & (WINDOW_SIZE - 1);
    previous[slot] = head[h];
    head[h] = at;
  };

  while (position < n) {
    const flagPosition = resultLength++;
    let flags = 0;
    for (let bit = 0; bit < 8 && position < n; bit++) {
      let bestLength = 0;
      let bestDistance = 0;
      if (position + 2 < n) {
        const h = hash3(input, position);
        let candidate = head[h];
        let examined = 0;
        const limit = Math.min(MAX_MATCH, n - position);
        while (candidate >= 0 && position - candidate <= WINDOW_SIZE && examined < searchLimit) {
          const max = Math.min(limit, n - candidate);
          let length = 0;
          while (length < max && input[candidate + length] === input[position + length]) length++;
          if (length >= 3 && length > bestLength) {
            bestLength = length;
            bestDistance = position - candidate;
            if (length === limit) break;
          }
          const older = previous[candidate & (WINDOW_SIZE - 1)];
          // A ring slot may already belong to a newer position. Stop rather
          // than following a stale forward link or cycling the chain.
          if (older >= candidate) break;
          candidate = older;
          examined++;
        }
      }

      if (bestLength >= 3) {
        const encodedDistance = bestDistance - 1;
        result[resultLength++] = encodedDistance & 0xff;
        result[resultLength++] = encodedDistance >>> 8;
        result[resultLength++] = bestLength - 3;
        for (let j = 0; j < bestLength; j++) insert(position + j);
        position += bestLength;
      } else {
        flags |= 1 << bit;
        result[resultLength++] = input[position];
        insert(position);
        position++;
      }
    }
    result[flagPosition] = flags;
  }
  return Buffer.from(result.subarray(0, resultLength));
}

function lzssDecode(stream, outputSize) {
  const output = Buffer.alloc(outputSize);
  let inputPosition = 0;
  let outputPosition = 0;
  while (outputPosition < outputSize) {
    if (inputPosition >= stream.length) fail('invalid_archive', 'Обрезан поток LZSS');
    const flags = stream[inputPosition++];
    for (let bit = 0; bit < 8 && outputPosition < outputSize; bit++) {
      if (flags & (1 << bit)) {
        if (inputPosition >= stream.length) fail('invalid_archive', 'Обрезан литеральный токен');
        output[outputPosition++] = stream[inputPosition++];
      } else {
        if (inputPosition + 3 > stream.length) fail('invalid_archive', 'Обрезанный токен LZSS');
        const distance = stream[inputPosition] | (stream[inputPosition + 1] << 8);
        const length = stream[inputPosition + 2] + 3;
        inputPosition += 3;
        if (distance >= outputPosition || distance >= WINDOW_SIZE) {
          fail('invalid_archive', 'Некорректное расстояние LZSS');
        }
        if (outputPosition + length > outputSize) {
          fail('invalid_archive', 'Токен LZSS выходит за размер файла');
        }
        for (let j = 0; j < length; j++) {
          output[outputPosition] = output[outputPosition - distance - 1];
          outputPosition++;
        }
      }
    }
  }
  if (inputPosition !== stream.length) fail('invalid_archive', 'Лишние данные в потоке LZSS');
  return output;
}

function buildHuffman(input) {
  const frequencies = new Uint32Array(256);
  for (const byte of input) frequencies[byte]++;
  const symbols = [];
  for (let symbol = 0; symbol < 256; symbol++) {
    if (frequencies[symbol]) symbols.push({ frequency: frequencies[symbol], symbol, left: -1, right: -1 });
  }
  if (symbols.length === 0) return { lengths: new Uint8Array(256), data: Buffer.alloc(0), decodedSize: 0 };

  const nodes = symbols.slice();
  const queue = nodes.map((_, index) => index);
  while (queue.length > 1) {
    queue.sort((a, b) => nodes[a].frequency - nodes[b].frequency || a - b);
    const left = queue.shift();
    const right = queue.shift();
    nodes.push({ frequency: nodes[left].frequency + nodes[right].frequency, symbol: -1, left, right });
    queue.push(nodes.length - 1);
  }
  const root = queue[0];
  const lengths = new Uint8Array(256);
  const walk = (node, depth) => {
    const current = nodes[node];
    if (current.symbol >= 0) {
      lengths[current.symbol] = depth || 1;
    } else {
      walk(current.left, depth + 1);
      walk(current.right, depth + 1);
    }
  };
  walk(root, 0);

  let maxLength = 0;
  const counts = new Uint32Array(32);
  for (const length of lengths) {
    if (length > 31) return null;
    if (length) {
      counts[length]++;
      maxLength = Math.max(maxLength, length);
    }
  }

  // Canonical code assignment. A pathological frequency distribution can
  // create codes longer than the compact implementation supports; storing is
  // safer than spending unbounded time or emitting an invalid archive.
  const nextCode = new Uint32Array(32);
  let code = 0;
  for (let length = 1; length <= maxLength; length++) {
    code = (code + counts[length - 1]) * 2;
    if (code + counts[length] > 2 ** length) return null;
    nextCode[length] = code;
  }
  const codes = new Uint32Array(256);
  for (let symbol = 0; symbol < 256; symbol++) {
    const length = lengths[symbol];
    if (length) codes[symbol] = nextCode[length]++;
  }

  let totalBits = 0;
  for (let symbol = 0; symbol < 256; symbol++) totalBits += frequencies[symbol] * lengths[symbol];
  const encoded = new Uint8Array(Math.ceil(totalBits / 8) + 1);
  let outPosition = 0;
  let pending = 0;
  let pendingBits = 0;
  for (const symbol of input) {
    let remaining = lengths[symbol];
    const symbolCode = codes[symbol];
    while (remaining) {
      const take = Math.min(8 - pendingBits, remaining);
      const shift = remaining - take;
      const divisor = 2 ** shift;
      const part = Math.floor(symbolCode / divisor) % (2 ** take);
      pending = pending * (2 ** take) + part;
      pendingBits += take;
      remaining -= take;
      if (pendingBits === 8) {
        encoded[outPosition++] = pending;
        pending = 0;
        pendingBits = 0;
      }
    }
  }
  if (pendingBits) encoded[outPosition++] = pending * (2 ** (8 - pendingBits));
  return { lengths, data: Buffer.from(encoded.subarray(0, outPosition)), decodedSize: input.length };
}

function decodeHuffman(data, lengths, outputSize) {
  const counts = new Uint32Array(32);
  let maxLength = 0;
  for (const length of lengths) {
    if (length > 31) fail('invalid_archive', 'Недопустимая длина кода Хаффмана');
    if (length) {
      counts[length]++;
      maxLength = Math.max(maxLength, length);
    }
  }
  if (outputSize === 0) {
    if (data.length !== 0) fail('invalid_archive', 'Данные для пустого потока Хаффмана');
    return Buffer.alloc(0);
  }
  if (maxLength === 0) fail('invalid_archive', 'Пустая таблица Хаффмана');
  const firstCode = new Uint32Array(32);
  const nextCode = new Uint32Array(32);
  let code = 0;
  for (let length = 1; length <= maxLength; length++) {
    code = (code + counts[length - 1]) * 2;
    if (code + counts[length] > 2 ** length) fail('invalid_archive', 'Повреждена таблица Хаффмана');
    firstCode[length] = code;
    nextCode[length] = code;
  }
  const byLength = Array.from({ length: maxLength + 1 }, () => new Map());
  for (let symbol = 0; symbol < 256; symbol++) {
    const length = lengths[symbol];
    if (length) byLength[length].set(nextCode[length]++, symbol);
  }

  const output = Buffer.alloc(outputSize);
  let inputPosition = 0;
  let currentByte = 0;
  let bitsLeft = 0;
  const readBit = () => {
    if (!bitsLeft) {
      if (inputPosition >= data.length) fail('invalid_archive', 'Обрезан поток Хаффмана');
      currentByte = data[inputPosition++];
      bitsLeft = 8;
    }
    const bit = (currentByte & 0x80) ? 1 : 0;
    currentByte = (currentByte << 1) & 0xff;
    bitsLeft--;
    return bit;
  };
  for (let out = 0; out < outputSize; out++) {
    let value = 0;
    let found = false;
    for (let length = 1; length <= maxLength; length++) {
      value = value * 2 + readBit();
      const symbol = byLength[length].get(value);
      if (symbol !== undefined) {
        output[out] = symbol;
        found = true;
        break;
      }
    }
    if (!found) fail('invalid_archive', 'Некорректный код Хаффмана');
  }
  if (inputPosition < data.length) {
    // The only permissible remaining bits are zero padding in the last byte.
    if (bitsLeft && currentByte !== 0) fail('invalid_archive', 'Некорректное заполнение Хаффмана');
    if (inputPosition !== data.length - (bitsLeft ? 1 : 0)) fail('invalid_archive', 'Лишние данные Хаффмана');
  }
  return output;
}

function huffmanParams(huffman) {
  let symbolCount = 0;
  for (const length of huffman.lengths) if (length) symbolCount++;
  const params = Buffer.alloc(6 + symbolCount * 2);
  params.writeUInt32LE(huffman.decodedSize, 0);
  params.writeUInt16LE(symbolCount, 4);
  let position = 6;
  for (let symbol = 0; symbol < 256; symbol++) {
    if (huffman.lengths[symbol]) {
      params[position++] = symbol;
      params[position++] = huffman.lengths[symbol];
    }
  }
  return params;
}

function createArchive(method, original, params, payload, checksum) {
  // SARC v4 uses a method-specific one-byte signature. For stored data the
  // payload length is implicit; compressed methods carry an original-size
  // varint and a four-byte SHA-256 check before method parameters.
  if (method === 0) return Buffer.concat([Buffer.from([0xf0]), checksum.subarray(0, 4), payload]);
  const prefix = Buffer.from([0xf0 + method, ...writeVarUint(original.length)]);
  return Buffer.concat([prefix, checksum.subarray(0, 4), params, payload]);
}

function deltaEncode(input) {
  const output = Buffer.allocUnsafe(input.length);
  let previous = 0;
  for (let i = 0; i < input.length; i++) {
    const current = input[i];
    output[i] = (current - previous) & 0xff;
    previous = current;
  }
  return output;
}

function deltaStride(input, stride) {
  const output = Buffer.allocUnsafe(input.length);
  const initial = Math.min(stride, input.length);
  input.copy(output, 0, 0, initial);
  for (let i = stride; i < input.length; i++) output[i] = (input[i] - input[i - stride]) & 0xff;
  return output;
}

function restoreDeltaStride(output, stride) {
  for (let i = stride; i < output.length; i++) output[i] = (output[i] + output[i - stride]) & 0xff;
  return output;
}

function byteShuffle(input, stride) {
  const output = Buffer.allocUnsafe(input.length);
  let out = 0;
  for (let lane = 0; lane < stride; lane++) {
    for (let i = lane; i < input.length; i += stride) output[out++] = input[i];
  }
  return output;
}

function byteUnshuffle(input, stride, outputSize) {
  const output = Buffer.allocUnsafe(outputSize);
  let source = 0;
  for (let lane = 0; lane < stride; lane++) {
    for (let i = lane; i < outputSize; i += stride) output[i] = input[source++];
  }
  if (source !== input.length) fail('invalid_archive', 'Некорректный byte-shuffle поток');
  return output;
}

function deltaDecode(input) {
  const output = Buffer.from(input);
  let previous = 0;
  for (let i = 0; i < output.length; i++) {
    output[i] = (output[i] + previous) & 0xff;
    previous = output[i];
  }
  return output;
}

// Transform IDs are deliberately generic: no filename extension is needed.
// 1/2 are lane-wise delta filters, 5/6 are byte-shuffle followed by delta,
// and 7 compares adjacent fixed-size pages (useful for database-like data).
function applyTransform(input, id) {
  if (id === 1) return deltaStride(input, 2);
  if (id === 2) return deltaStride(input, 4);
  if (id === 5) return deltaEncode(byteShuffle(input, 2));
  if (id === 6) return deltaEncode(byteShuffle(input, 4));
  if (id === 7) return deltaStride(input, 4096);
  fail('invalid_archive', 'Неизвестное преобразование данных');
}

function reverseTransform(input, id) {
  if (id === 1) return restoreDeltaStride(Buffer.from(input), 2);
  if (id === 2) return restoreDeltaStride(Buffer.from(input), 4);
  if (id === 5) return byteUnshuffle(deltaDecode(input), 2, input.length);
  if (id === 6) return byteUnshuffle(deltaDecode(input), 4, input.length);
  if (id === 7) return restoreDeltaStride(Buffer.from(input), 4096);
  fail('invalid_archive', 'Неизвестное преобразование данных');
}

function chooseTransform(input) {
  if (input.length < 8192 || input.length > 2 * 1024 * 1024) return 0;
  const sampleSize = Math.min(input.length, 16 * 1024);
  const sample = input.subarray(0, sampleSize);
  const originalEntropy = entropy(sample);
  let best = { id: 0, gain: 0 };
  const candidates = [1, 2, 5, 6];
  if (input.length >= 8192) candidates.push(7);
  for (const id of candidates) {
    const transformed = applyTransform(sample, id);
    const gain = originalEntropy - entropy(transformed);
    if (gain > best.gain) best = { id, gain };
  }
  const minimumGain = input.length >= 8 * 1024 * 1024 ? 0.25 : 0.08;
  return best.gain >= minimumGain ? best.id : 0;
}

function writeVarUint(value) {
  const bytes = [];
  while (value >= 128) {
    bytes.push((value & 127) | 128);
    value = Math.floor(value / 128);
  }
  bytes.push(value);
  return bytes;
}

function readVarUint(buffer, state) {
  let value = 0;
  let shift = 0;
  while (true) {
    if (state.position >= buffer.length || shift > 28) fail('invalid_archive', 'Некорректный размер в архиве');
    const byte = buffer[state.position++];
    value += (byte & 127) * (2 ** shift);
    if (!(byte & 128)) return value;
    shift += 7;
  }
}

function rleEncode(input) {
  const probeSize = Math.min(4096, input.length);
  let probeRuns = 0;
  let probes = 0;
  for (const start of [0, Math.max(0, Math.floor(input.length / 2) - Math.floor(probeSize / 2)), Math.max(0, input.length - probeSize)]) {
    let previous = -1;
    for (let i = start; i < Math.min(input.length, start + probeSize); i++) {
      if (input[i] !== previous) probeRuns++;
      previous = input[i];
      probes++;
    }
  }
  if (input.length > 64 && probeRuns > probes * 0.98) return null;

  let encodedSize = 0;
  let position = 0;
  while (position < input.length) {
    const value = input[position];
    let end = position + 1;
    while (end < input.length && input[end] === value) end++;
    encodedSize += writeVarUint(end - position).length + 1;
    if (encodedSize >= input.length - 16) return null;
    position = end;
  }
  const output = Buffer.allocUnsafe(encodedSize);
  position = 0;
  let outPosition = 0;
  while (position < input.length) {
    const value = input[position];
    let end = position + 1;
    while (end < input.length && input[end] === value) end++;
    for (const byte of writeVarUint(end - position)) output[outPosition++] = byte;
    output[outPosition++] = value;
    position = end;
  }
  return output;
}

function rleDecode(payload, outputSize) {
  const output = Buffer.alloc(outputSize);
  let inputPosition = 0;
  let outputPosition = 0;
  while (inputPosition < payload.length) {
    let count = 0;
    let shift = 0;
    let byte;
    do {
      if (inputPosition >= payload.length || shift > 28) fail('invalid_archive', 'Некорректная длина RLE');
      byte = payload[inputPosition++];
      count += (byte & 127) * (2 ** shift);
      shift += 7;
    } while (byte & 128);
    if (!count || inputPosition >= payload.length || outputPosition + count > outputSize) {
      fail('invalid_archive', 'Некорректный диапазон RLE');
    }
    output.fill(payload[inputPosition++], outputPosition, outputPosition + count);
    outputPosition += count;
  }
  if (outputPosition !== outputSize) fail('invalid_archive', 'RLE не совпадает с размером файла');
  return output;
}

function repeatedPeriod(input) {
  if (input.length < 2) return 0;
  // Find a candidate period in a bounded prefix instead of allocating a
  // prefix table proportional to a multi-megabyte file.
  const sampleSize = Math.min(input.length, 64 * 1024);
  const prefix = new Uint16Array(sampleSize);
  for (let i = 1; i < sampleSize; i++) {
    let j = prefix[i - 1];
    while (j > 0 && input[i] !== input[j]) j = prefix[j - 1];
    if (input[i] === input[j]) j++;
    prefix[i] = j;
  }
  const period = sampleSize - prefix[sampleSize - 1];
  if (period >= sampleSize || input.length % period !== 0) return 0;
  for (let i = sampleSize; i < input.length; i++) {
    if (input[i] !== input[i % period]) return 0;
  }
  return period;
}

function entropy(data) {
  const counts = new Uint32Array(256);
  for (const byte of data) counts[byte]++;
  let result = 0;
  for (const count of counts) {
    if (count) {
      const probability = count / data.length;
      result -= probability * Math.log2(probability);
    }
  }
  return result;
}

function looksIncompressible(input) {
  if (input.length < 8192) return false;
  // Sample several regions: multimedia containers often start with a simple
  // header while their payload is already compressed. Avoid expensive full
  // LZ/Huffman passes when most sampled payload regions have high entropy and
  // almost no repeated quadgrams. Never use filename extensions for this.
  const windowSize = Math.min(4096, input.length);
  const starts = [...new Set([
    0,
    Math.max(0, Math.floor(input.length / 4) - Math.floor(windowSize / 2)),
    Math.max(0, Math.floor(input.length / 2) - Math.floor(windowSize / 2)),
    Math.max(0, Math.floor((input.length * 3) / 4) - Math.floor(windowSize / 2)),
    Math.max(0, input.length - windowSize)
  ])];
  let incompressibleWindows = 0;
  for (const start of starts) {
    const sample = input.subarray(start, Math.min(input.length, start + windowSize));
    // Encoded media often lands around 7.5–7.8 bits/byte: it is already
    // compressed enough that a deep LZ search usually cannot repay its cost.
    if (sample.length < 1024 || entropy(sample) < 7.5) continue;
    const seen = new Set();
    let repeatedQuadgrams = 0;
    for (let i = 0; i + 3 < sample.length; i++) {
      const key = ((sample[i] * 0x1000000) + (sample[i + 1] << 16) + (sample[i + 2] << 8) + sample[i + 3]) >>> 0;
      if (seen.has(key)) {
        if (++repeatedQuadgrams > 4) break;
      } else {
        seen.add(key);
      }
    }
    if (repeatedQuadgrams <= 4) incompressibleWindows++;
  }
  return incompressibleWindows >= Math.min(3, starts.length);
}

function shouldTryDelta(input) {
  if (input.length < 4096) return false;
  const sample = input.subarray(0, Math.min(input.length, 32 * 1024));
  const delta = deltaEncode(sample);
  return entropy(delta) + 0.12 < entropy(sample);
}

export function compress(inputData) {
  const input = Buffer.isBuffer(inputData) ? inputData : Buffer.from(inputData);
  if (input.length > MAX_ORIGINAL_SIZE) fail('input_too_large', 'Файл превышает допустимый размер', 413);
  // The empty archive has a dedicated one-byte representation. Zero bytes
  // cannot be a valid archive: the decompressor would have no way to tell an
  // empty file from a missing/truncated request.
  if (input.length === 0) return Buffer.from([0]);
  const checksum = sha256(input);
  let best = { method: 0, params: Buffer.alloc(0), payload: input, total: input.length + 5 };

  const encodedSize = (method, params, payload) => {
    if (method === 0) return 5 + payload.length;
    return 1 + writeVarUint(input.length).length + 4 + params.length + payload.length;
  };

  const period = repeatedPeriod(input);
  if (period) {
    const params = Buffer.alloc(2);
    params.writeUInt16LE(period, 0);
    const payload = input.subarray(0, period);
    const total = encodedSize(5, params, payload);
    if (total < best.total) best = { method: 5, params, payload, total };
  }

  // If an exact repeat descriptor is already excellent, don't run multiple
  // linear encoders over the whole file just to shave a couple more bytes.
  if (best.total <= 32 || best.total < input.length * 0.05) {
    return createArchive(best.method, input, best.params, best.payload, checksum);
  }

  if (looksIncompressible(input)) {
    return createArchive(0, input, Buffer.alloc(0), input, checksum);
  }

  const rle = rleEncode(input);
  if (rle) {
    const rleTotal = encodedSize(4, Buffer.alloc(0), rle);
    if (rleTotal < best.total) best = { method: 4, params: Buffer.alloc(0), payload: rle, total: rleTotal };
  }

  // Keep the hash-chain effort proportional to file size. Deep matching is
  // useful for small text; on multi-megabyte files it disproportionately costs
  // CPU while bringing only marginal compression gains.
  const searchLimit = input.length < 64 * 1024 ? 48 : input.length < 1024 * 1024 ? 24 : input.length < 8 * 1024 * 1024 ? 12 : 6;
  const lz = lzssEncode(input, searchLimit);
  const lzHuffman = buildHuffman(lz);
  if (lzHuffman) {
    const params = huffmanParams(lzHuffman);
    const total = encodedSize(1, params, lzHuffman.data);
    if (total < best.total) best = { method: 1, params, payload: lzHuffman.data, total };
  }

  const directHuffman = buildHuffman(input);
  if (directHuffman) {
    const params = huffmanParams(directHuffman);
    const total = encodedSize(2, params, directHuffman.data);
    if (total < best.total) best = { method: 2, params, payload: directHuffman.data, total };
  }

  const transformId = chooseTransform(input);
  if (!transformId && shouldTryDelta(input)) {
    const delta = deltaEncode(input);
    const deltaLz = lzssEncode(delta, searchLimit);
    const deltaHuffman = buildHuffman(deltaLz);
    if (deltaHuffman) {
      const params = huffmanParams(deltaHuffman);
      const total = encodedSize(3, params, deltaHuffman.data);
      if (total < best.total) best = { method: 3, params, payload: deltaHuffman.data, total };
    }
  }

  if (transformId) {
    const transformed = applyTransform(input, transformId);
    const transformedLz = lzssEncode(transformed, searchLimit);
    const transformedHuffman = buildHuffman(transformedLz);
    if (transformedHuffman) {
      const params = Buffer.concat([Buffer.from([transformId]), huffmanParams(transformedHuffman)]);
      const total = encodedSize(6, params, transformedHuffman.data);
      if (total < best.total) best = { method: 6, params, payload: transformedHuffman.data, total };
    }
  }
  return createArchive(best.method, input, best.params, best.payload, checksum);
}

function readLegacyHeader(archive) {
  if (archive.length < LEGACY_HEADER_SIZE) fail('invalid_archive', 'Архив короче заголовка');
  if (!archive.subarray(0, 4).equals(MAGIC)) fail('invalid_archive', 'Неверная сигнатура архива');
  const version = archive.readUInt16LE(4);
  if (version !== LEGACY_VERSION) fail('unsupported_version', `Неподдерживаемая версия архива: ${version}`);
  const method = archive[6];
  if (![0, 1, 2, 3].includes(method)) fail('unsupported_method', `Неподдерживаемый метод: ${method}`);
  if (archive.readUInt32LE(60) !== LEGACY_HEADER_SIZE) fail('invalid_archive', 'Некорректный размер заголовка');
  const originalSizeBig = archive.readBigUInt64LE(8);
  const payloadSizeBig = archive.readBigUInt64LE(16);
  if (originalSizeBig > BigInt(MAX_ORIGINAL_SIZE)) fail('invalid_archive', 'Заявленный размер распаковки слишком велик');
  const paramsSize = archive.readUInt32LE(56);
  if (paramsSize > 4096) fail('invalid_archive', 'Слишком большая таблица параметров');
  const totalExpected = BigInt(LEGACY_HEADER_SIZE) + BigInt(paramsSize) + payloadSizeBig;
  if (totalExpected !== BigInt(archive.length)) fail('invalid_archive', 'Размер архива не совпадает с заголовком');
  return {
    legacy: true,
    method,
    originalSize: Number(originalSizeBig),
    payloadSize: Number(payloadSizeBig),
    params: archive.subarray(LEGACY_HEADER_SIZE, LEGACY_HEADER_SIZE + paramsSize),
    payload: archive.subarray(LEGACY_HEADER_SIZE + paramsSize),
    checksum: archive.subarray(24, 56)
  };
}

function readHeader(archive) {
  if (archive.length >= 1 && archive[0] >= 0xf0) {
    return readV3Header(archive);
  }
  if (archive.length < 6) fail('invalid_archive', 'Архив короче заголовка');
  if (!archive.subarray(0, 4).equals(MAGIC)) fail('invalid_archive', 'Неверная сигнатура архива');
  const version = archive[4];
  if (version === LEGACY_VERSION && archive[5] === 0) return readLegacyHeader(archive);
  if (version === V2_VERSION) return readV2Header(archive);
  if (version === V3_VERSION) return readOldV3Header(archive);
  if (version !== VERSION) fail('unsupported_version', `Неподдерживаемая версия архива: ${version}`);
  const method = archive[5];
  if (![0, 1, 2, 3, 4, 5].includes(method)) fail('unsupported_method', `Неподдерживаемый метод: ${method}`);
  if (archive.length < V3_HEADER_SIZE) fail('invalid_archive', 'Архив короче заголовка v3');
  const originalSize = archive.readUInt32LE(6);
  if (originalSize > MAX_ORIGINAL_SIZE) fail('invalid_archive', 'Заявленный размер распаковки слишком велик');
  let paramsSize = method === 5 ? 2 : 0;
  if ([1, 2, 3].includes(method)) {
    if (archive.length < V3_HEADER_SIZE + 6) fail('invalid_archive', 'Обрезана таблица Хаффмана');
    const symbolCount = archive.readUInt16LE(V3_HEADER_SIZE + 4);
    if (symbolCount > 256) fail('invalid_archive', 'Некорректная таблица Хаффмана');
    paramsSize = 6 + symbolCount * 2;
  }
  if (archive.length < V3_HEADER_SIZE + paramsSize) fail('invalid_archive', 'Архив короче параметров');
  const params = archive.subarray(V3_HEADER_SIZE, V3_HEADER_SIZE + paramsSize);
  const payload = archive.subarray(V3_HEADER_SIZE + paramsSize);
  return {
    legacy: false,
    method,
    originalSize,
    payloadSize: payload.length,
    params,
    payload,
    checksum: archive.subarray(10, 14)
  };
}

function readV3Header(archive) {
  if (archive.length < 5) fail('invalid_archive', 'Обрезан компактный заголовок');
  const method = archive[0] - 0xf0;
  if (method < 0 || method > 6) fail('unsupported_method', `Неподдерживаемый метод: ${method}`);
  if (method === 0) {
    const originalSize = archive.length - 5;
    return { legacy: false, v2: false, compact: true, method, originalSize, params: Buffer.alloc(0), payload: archive.subarray(5), checksum: archive.subarray(1, 5) };
  }
  const state = { position: 1 };
  const originalSize = readVarUint(archive, state);
  if (originalSize > MAX_ORIGINAL_SIZE) fail('invalid_archive', 'Заявленный размер распаковки слишком велик');
  if (state.position + 4 > archive.length) fail('invalid_archive', 'Обрезана контрольная сумма');
  const checksum = archive.subarray(state.position, state.position + 4);
  state.position += 4;
  let params = Buffer.alloc(0);
  if (method === 5) {
    if (state.position + 2 > archive.length) fail('invalid_archive', 'Обрезан период повторения');
    params = archive.subarray(state.position, state.position + 2);
    state.position += 2;
  } else if ([1, 2, 3, 6].includes(method)) {
    if (state.position + 6 > archive.length) fail('invalid_archive', 'Обрезана таблица Хаффмана');
    const parameterOffset = method === 6 ? 1 : 0;
    if (method === 6 && state.position + 1 > archive.length) fail('invalid_archive', 'Обрезан идентификатор преобразования');
    const symbolsPosition = state.position + parameterOffset + 4;
    if (symbolsPosition + 2 > archive.length) fail('invalid_archive', 'Обрезана таблица Хаффмана');
    const symbols = archive.readUInt16LE(symbolsPosition);
    if (symbols > 256) fail('invalid_archive', 'Некорректная таблица Хаффмана');
    const size = parameterOffset + 6 + symbols * 2;
    if (state.position + size > archive.length) fail('invalid_archive', 'Обрезана таблица Хаффмана');
    params = archive.subarray(state.position, state.position + size);
    state.position += size;
  }
  return { legacy: false, v2: false, compact: true, method, originalSize, params, payload: archive.subarray(state.position), checksum };
}

function readOldV3Header(archive) {
  const method = archive[5];
  if (![0, 1, 2, 3, 4, 5].includes(method)) fail('unsupported_method', `Неподдерживаемый метод: ${method}`);
  if (archive.length < V3_HEADER_SIZE) fail('invalid_archive', 'Архив короче заголовка v3');
  const originalSize = archive.readUInt32LE(6);
  if (originalSize > MAX_ORIGINAL_SIZE) fail('invalid_archive', 'Заявленный размер распаковки слишком велик');
  let paramsSize = method === 5 ? 2 : 0;
  if ([1, 2, 3].includes(method)) {
    if (archive.length < V3_HEADER_SIZE + 6) fail('invalid_archive', 'Обрезана таблица Хаффмана');
    const symbolCount = archive.readUInt16LE(V3_HEADER_SIZE + 4);
    if (symbolCount > 256) fail('invalid_archive', 'Некорректная таблица Хаффмана');
    paramsSize = 6 + symbolCount * 2;
  }
  if (archive.length < V3_HEADER_SIZE + paramsSize) fail('invalid_archive', 'Архив короче параметров');
  return { legacy: false, v2: false, compact: false, method, originalSize, params: archive.subarray(V3_HEADER_SIZE, V3_HEADER_SIZE + paramsSize), payload: archive.subarray(V3_HEADER_SIZE + paramsSize), checksum: archive.subarray(10, 14) };
}

function readV2Header(archive) {
  const method = archive[5];
  if (![0, 1, 2, 3].includes(method)) fail('unsupported_method', `Неподдерживаемый метод: ${method}`);
  if (method === 0) {
    if (archive.length < STORE_HEADER_SIZE) fail('invalid_archive', 'Архив короче заголовка store');
    const originalSize = archive.readUInt32LE(6);
    if (archive.length - STORE_HEADER_SIZE !== originalSize) fail('invalid_archive', 'Размер store-архива не совпадает');
    return { legacy: false, v2: true, method, originalSize, payloadSize: originalSize, params: Buffer.alloc(0), payload: archive.subarray(STORE_HEADER_SIZE), checksum: archive.subarray(10, 18) };
  }
  if (archive.length < HEADER_SIZE || archive[7] !== HEADER_SIZE) fail('invalid_archive', 'Некорректный заголовок v2');
  const originalSize = archive.readUInt32LE(8);
  const payloadSize = archive.readUInt32LE(12);
  const paramsSize = archive.readUInt16LE(16);
  if (paramsSize > 4096 || HEADER_SIZE + paramsSize + payloadSize !== archive.length) fail('invalid_archive', 'Размер архива v2 не совпадает');
  return { legacy: false, v2: true, method, originalSize, payloadSize, params: archive.subarray(HEADER_SIZE, HEADER_SIZE + paramsSize), payload: archive.subarray(HEADER_SIZE + paramsSize), checksum: archive.subarray(20, 28) };
}

function parseHuffman(header) {
  if (header.method === 6 && !header.v2 && !header.legacy) {
    if (header.params.length < 1) fail('invalid_archive', 'Отсутствует идентификатор преобразования');
    const transformId = header.params[0];
    if (![1, 2, 5, 6, 7].includes(transformId)) fail('invalid_archive', 'Неизвестное преобразование данных');
    return { ...parseHuffman({ ...header, method: 1, params: header.params.subarray(1) }), transformId };
  }
  if (header.legacy) {
    if (header.params.length !== 260) fail('invalid_archive', 'Некорректный размер таблицы Хаффмана');
    return { decodedSize: header.params.readUInt32LE(0), lengths: header.params.subarray(4) };
  }
  if (header.params.length < 6) fail('invalid_archive', 'Некорректная таблица Хаффмана');
  const decodedSize = header.params.readUInt32LE(0);
  const symbolCount = header.params.readUInt16LE(4);
  if (symbolCount > 256 || header.params.length !== 6 + symbolCount * 2) {
    fail('invalid_archive', 'Некорректный список символов Хаффмана');
  }
  const lengths = new Uint8Array(256);
  for (let i = 0, position = 6; i < symbolCount; i++, position += 2) {
    const symbol = header.params[position];
    const length = header.params[position + 1];
    if (length === 0 || lengths[symbol]) fail('invalid_archive', 'Повторный символ в таблице Хаффмана');
    lengths[symbol] = length;
  }
  if (decodedSize > MAX_ORIGINAL_SIZE + Math.ceil(MAX_ORIGINAL_SIZE / 8) + 16) {
    fail('invalid_archive', 'Слишком большой промежуточный поток');
  }
  return { decodedSize, lengths };
}

export function decompress(archiveData) {
  const archive = Buffer.isBuffer(archiveData) ? archiveData : Buffer.from(archiveData);
  if (archive.length === 1 && archive[0] === 0) return Buffer.alloc(0);
  if (archive.length === 1 && archive[0] >= 0xf0 && archive[0] <= 0xf5) {
    fail('invalid_archive', 'Обрезан компактный архив');
  }
  const header = readHeader(archive);
  let output;
  if (header.method === 0) {
    if (header.params.length !== 0 || header.payload.length !== header.originalSize) {
      fail('invalid_archive', 'Некорректные параметры режима хранения');
    }
    output = Buffer.from(header.payload);
  } else if (header.method === 4) {
    output = rleDecode(header.payload, header.originalSize);
  } else if (header.method === 5) {
    if (header.params.length !== 2) fail('invalid_archive', 'Некорректный период повторяющегося блока');
    const period = header.params.readUInt16LE(0);
    if (!period || header.payload.length !== period) fail('invalid_archive', 'Некорректный повторяющийся блок');
    output = Buffer.alloc(header.originalSize);
    for (let position = 0; position < output.length; position++) output[position] = header.payload[position % period];
  } else if (header.method === 2) {
    const huffman = parseHuffman(header);
    if (huffman.decodedSize !== header.originalSize) fail('invalid_archive', 'Размер Хаффмана не совпадает с исходным');
    output = decodeHuffman(header.payload, huffman.lengths, huffman.decodedSize);
  } else {
    const huffman = parseHuffman(header);
    const lzStream = decodeHuffman(header.payload, huffman.lengths, huffman.decodedSize);
    output = lzssDecode(lzStream, header.originalSize);
    if (header.method === 3) {
      let previous = 0;
      for (let i = 0; i < output.length; i++) {
        output[i] = (output[i] + previous) & 0xff;
        previous = output[i];
      }
    } else if (header.method === 6) {
      output = reverseTransform(output, huffman.transformId);
    }
  }
  const actualChecksum = sha256(output).subarray(0, header.legacy ? 32 : header.v2 ? 8 : 4);
  if (!timingSafeEqual(actualChecksum, header.checksum)) fail('checksum_mismatch', 'Контрольная сумма распакованных данных не совпадает');
  return output;
}

export const formatInfo = {
  magic: 'SARC',
  version: VERSION,
  headerSize: 5,
  storeHeaderSize: 5,
  methods: { 0: 'store', 1: 'lzss+huffman', 2: 'huffman', 3: 'delta+lzss+huffman', 4: 'rle', 5: 'repeat', 6: 'transform+lzss+huffman' }
};

export const _testInternals = { lzssEncode, lzssDecode, buildHuffman, decodeHuffman };
