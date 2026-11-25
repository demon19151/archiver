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
const COMPACT_ONE_BYTE_MARKER = 0xfe;
const WINDOW_SIZE = 65536;
const TOKEN_WINDOW_SIZE = 256 * 1024;
const MAX_DISTANCE_SLOT = 18;
const MAX_MATCH = 258;
const CONTEXT_BLOCK_SIZE = 128 * 1024;
const RECORD_TRANSPOSE_MARKER = 0;
const RECORD_STRIDES = [...new Set([
  ...Array.from({ length: 63 }, (_, index) => 4 + index * 4),
  ...Array.from({ length: 16 }, (_, index) => 256 + (index + 1) * 16),
  256, 640, 768, 1024, 2048, 4096
])].sort((a, b) => a - b);

function recordStrideFromTransform(id) {
  if (!Number.isInteger(id) || id < 16 || id >= 16 + RECORD_STRIDES.length) return 0;
  return RECORD_STRIDES[id - 16];
}

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
function lzssEncode(input, searchLimit = 48, windowSize = WINDOW_SIZE) {
  if (windowSize < WINDOW_SIZE || (windowSize & (windowSize - 1)) !== 0) fail('invalid_archive', 'Некорректный размер окна LZSS');
  const wideDistance = windowSize > WINDOW_SIZE;
  const n = input.length;
  const head = new Int32Array(65536);
  head.fill(-1);
  const previous = new Int32Array(windowSize);
  previous.fill(-1);
  const result = new Uint8Array((wideDistance ? n * 2 : n) + Math.ceil(n / 8) + 16);
  let resultLength = 0;
  let position = 0;

  const insert = (at) => {
    if (at + 2 >= n) return;
    const h = hash3(input, at);
    const slot = at & (windowSize - 1);
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
        while (candidate >= 0 && position - candidate <= windowSize && examined < searchLimit) {
          const max = Math.min(limit, n - candidate);
          let length = 0;
          while (length < max && input[candidate + length] === input[position + length]) length++;
          if (length >= 3 && length > bestLength) {
            bestLength = length;
            bestDistance = position - candidate;
            if (length === limit) break;
          }
          const older = previous[candidate & (windowSize - 1)];
          // A ring slot may already belong to a newer position. Stop rather
          // than following a stale forward link or cycling the chain.
          if (older >= candidate) break;
          candidate = older;
          examined++;
        }
      }

      const minimumMatch = wideDistance ? writeVarUint(bestDistance).length + 2 : 3;
      if (bestLength >= minimumMatch) {
        const encodedDistance = bestDistance - 1;
        if (wideDistance) {
          for (const byte of writeVarUint(bestDistance)) result[resultLength++] = byte;
        } else {
          result[resultLength++] = encodedDistance & 0xff;
          result[resultLength++] = encodedDistance >>> 8;
        }
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
    if (outputSize - outputPosition > 8 && inputPosition >= stream.length) fail('invalid_archive', 'Обрезан поток LZSS');
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

// An additional representation of the SAME Huffman stream: separate symbols
// from code lengths, packing two lengths into one byte (only lengths <= 15).
function compactHuffmanParams(method, params) {
  const offset = method === 6 ? 1 : 0;
  const count = params.readUInt16LE(offset + 4);
  for (let i = 0; i < count; i++) if (params[offset + 7 + i * 2] > 15) return null;
  const compact = Buffer.alloc(1 + offset + 6 + count + Math.ceil(count / 2));
  compact[0] = method;
  if (offset) compact[1] = params[0];
  params.copy(compact, 1 + offset, offset, offset + 6);
  const symbolsStart = 7 + offset;
  const lengthsStart = symbolsStart + count;
  for (let i = 0; i < count; i++) {
    compact[symbolsStart + i] = params[offset + 6 + i * 2];
    compact[lengthsStart + (i >>> 1)] |= params[offset + 7 + i * 2] << (i % 2 ? 0 : 4);
  }
  return compact;
}

function expandCompactHeader(header) {
  const params = header.params;
  const method = params[0];
  if (![1, 2, 3, 6].includes(method)) fail('invalid_archive', 'Некорректный метод компактной таблицы');
  const offset = method === 6 ? 1 : 0;
  const count = params.readUInt16LE(5 + offset);
  const expanded = Buffer.alloc(offset + 6 + count * 2);
  if (offset) expanded[0] = params[1];
  params.copy(expanded, offset, 1 + offset, 7 + offset);
  const symbolsStart = 7 + offset;
  const lengthsStart = symbolsStart + count;
  for (let i = 0; i < count; i++) {
    expanded[offset + 6 + i * 2] = params[symbolsStart + i];
    expanded[offset + 7 + i * 2] = (params[lengthsStart + (i >>> 1)] >>> (i % 2 ? 0 : 4)) & 15;
  }
  if (count % 2 && (params[params.length - 1] & 15)) fail('invalid_archive', 'Некорректное заполнение таблицы');
  return { ...header, method, params: expanded };
}

function createArchive(method, original, params, payload, checksum) {
  // SARC v4 uses a method-specific one-byte signature. For stored data the
  // payload length is implicit; compressed methods carry an original-size
  // varint and a four-byte SHA-256 check before method parameters.
  if (method === 0) return Buffer.concat([Buffer.from([0xf0]), checksum.subarray(0, 4), payload]);
  const prefix = Buffer.from([0xf0 + method, ...writeVarUint(original.length)]);
  return Buffer.concat([prefix, checksum.subarray(0, 4), params, payload]);
}

// Modular word deltas preserve every bit, including headers and odd tails.
function wordDelta(input, stride, order, inverse = false) {
  const output = Buffer.from(input);
  for (let pass = 0; pass < order; pass++) {
    let previous = 0;
    for (let at = 0; at + stride <= output.length; at += stride) {
      const value = stride === 2 ? output.readUInt16LE(at) : output.readUInt32LE(at);
      const encoded = inverse ? (value + previous) >>> 0 : (value - previous) >>> 0;
      if (stride === 2) output.writeUInt16LE(encoded & 0xffff, at);
      else output.writeUInt32LE(encoded, at);
      previous = inverse ? encoded : value;
    }
  }
  return output;
}

function huffmanCodesFromFrequencies(frequencies) {
  const nodes = [];
  const queue = [];
  for (let symbol = 0; symbol < frequencies.length; symbol++) {
    if (frequencies[symbol]) {
      queue.push(nodes.length);
      nodes.push({ frequency: frequencies[symbol], symbol, left: -1, right: -1 });
    }
  }
  if (!queue.length) return null;
  while (queue.length > 1) {
    queue.sort((a, b) => nodes[a].frequency - nodes[b].frequency || a - b);
    const left = queue.shift();
    const right = queue.shift();
    queue.push(nodes.length);
    nodes.push({ frequency: nodes[left].frequency + nodes[right].frequency, symbol: -1, left, right });
  }

  const lengths = new Uint8Array(frequencies.length);
  const walk = (index, depth) => {
    const node = nodes[index];
    if (node.symbol >= 0) {
      lengths[node.symbol] = depth || 1;
      return;
    }
    walk(node.left, depth + 1);
    walk(node.right, depth + 1);
  };
  walk(queue[0], 0);

  const counts = new Uint32Array(32);
  let maxLength = 0;
  for (const length of lengths) {
    if (length > 31) return null;
    if (length) {
      counts[length]++;
      maxLength = Math.max(maxLength, length);
    }
  }
  const codes = new Uint32Array(frequencies.length);
  const nextCode = new Uint32Array(32);
  let code = 0;
  for (let length = 1; length <= maxLength; length++) {
    code = (code + counts[length - 1]) * 2;
    if (code + counts[length] > 2 ** length) return null;
    nextCode[length] = code;
  }
  for (let symbol = 0; symbol < lengths.length; symbol++) {
    const length = lengths[symbol];
    if (length) codes[symbol] = nextCode[length]++;
  }
  return { lengths, codes, maxLength };
}

function walkLzssTokens(input, stream, visit, wideDistance = false) {
  let streamPosition = 0;
  let outputPosition = 0;
  while (outputPosition < input.length) {
    if (streamPosition >= stream.length) return false;
    const flags = stream[streamPosition++];
    for (let bit = 0; bit < 8 && outputPosition < input.length; bit++) {
      if (flags & (1 << bit)) {
        if (streamPosition >= stream.length) return false;
        visit(input[outputPosition], 0, 0);
        streamPosition++;
        outputPosition++;
      } else {
        let distance;
        let length;
        if (wideDistance) {
          const state = { position: streamPosition };
          try {
            distance = readVarUint(stream, state);
          } catch {
            return false;
          }
          streamPosition = state.position;
          if (streamPosition >= stream.length) return false;
          length = stream[streamPosition++] + 3;
        } else {
          if (streamPosition + 3 > stream.length) return false;
          distance = (stream[streamPosition] | (stream[streamPosition + 1] << 8)) + 1;
          length = stream[streamPosition + 2] + 3;
          streamPosition += 3;
        }
        if (distance > outputPosition || outputPosition + length > input.length) return false;
        visit(256 + length - 3, distance, length);
        outputPosition += length;
      }
    }
  }
  return streamPosition === stream.length;
}

// A DEFLATE-like token stream written from scratch: literals and match lengths
// have separate canonical Huffman codes, while distances use logarithmic
// slots plus low-order extra bits. The legacy LZSS format remains supported.
function lzTokenHuffmanEncode(input, lzStream, wideDistance = false) {
  const tokenFrequencies = new Uint32Array(512);
  const distanceFrequencies = new Uint32Array(MAX_DISTANCE_SLOT + 1);
  let extraBits = 0;
  let tokenCount = 0;
  const countToken = (symbol, distance, length) => {
    tokenFrequencies[symbol]++;
    tokenCount++;
    if (distance) {
      const slot = 31 - Math.clz32(distance);
      distanceFrequencies[slot]++;
      extraBits += slot;
    }
  };
  if (!walkLzssTokens(input, lzStream, countToken, wideDistance) || !tokenCount) return null;
  const tokenCodes = huffmanCodesFromFrequencies(tokenFrequencies);
  const distanceCodes = huffmanCodesFromFrequencies(distanceFrequencies);
  if (!tokenCodes || (distanceFrequencies.some(Boolean) && !distanceCodes)) return null;

  let totalBits = extraBits;
  for (let symbol = 0; symbol < tokenFrequencies.length; symbol++) {
    totalBits += tokenFrequencies[symbol] * tokenCodes.lengths[symbol];
  }
  for (let symbol = 0; symbol < distanceFrequencies.length; symbol++) {
    if (distanceFrequencies[symbol]) totalBits += distanceFrequencies[symbol] * distanceCodes.lengths[symbol];
  }
  const paramsBytes = 3 + tokenFrequencies.reduce((count, frequency) => count + (frequency ? 3 : 0), 0)
    + distanceFrequencies.reduce((count, frequency) => count + (frequency ? 2 : 0), 0);
  const estimatedPayloadSize = writeVarUint(paramsBytes).length + paramsBytes + Math.ceil(totalBits / 8);
  const estimatedArchiveSize = 1 + writeVarUint(input.length).length + 4
    + writeVarUint(estimatedPayloadSize).length + estimatedPayloadSize;
  if (estimatedArchiveSize >= input.length + 5) return null;
  const bitstream = Buffer.alloc(Math.ceil(totalBits / 8));
  let bitPosition = 0;
  const writeBits = (value, count) => {
    while (count) {
      const offset = bitPosition & 7;
      const take = Math.min(8 - offset, count);
      const shift = count - take;
      const part = Math.floor(value / (2 ** shift)) % (2 ** take);
      bitstream[bitPosition >>> 3] |= part << (8 - offset - take);
      bitPosition += take;
      count -= take;
    }
  };
  const writeSymbol = (symbol, table) => writeBits(table.codes[symbol], table.lengths[symbol]);
  const encodeToken = (symbol, distance) => {
    writeSymbol(symbol, tokenCodes);
    if (distance) {
      const slot = 31 - Math.clz32(distance);
      writeSymbol(slot, distanceCodes);
      if (slot) writeBits(distance - 2 ** slot, slot);
    }
  };
  if (!walkLzssTokens(input, lzStream, encodeToken, wideDistance) || bitPosition !== totalBits) return null;

  const tokenCountUsed = tokenFrequencies.reduce((count, frequency) => count + (frequency ? 1 : 0), 0);
  const distanceCountUsed = distanceFrequencies.reduce((count, frequency) => count + (frequency ? 1 : 0), 0);
  const params = Buffer.alloc(3 + tokenCountUsed * 3 + distanceCountUsed * 2);
  params.writeUInt16LE(tokenCountUsed, 0);
  let position = 2;
  for (let symbol = 0; symbol < tokenFrequencies.length; symbol++) {
    if (!tokenFrequencies[symbol]) continue;
    params.writeUInt16LE(symbol, position);
    params[position + 2] = tokenCodes.lengths[symbol];
    position += 3;
  }
  params[position++] = distanceCountUsed;
  for (let symbol = 0; symbol < distanceFrequencies.length; symbol++) {
    if (!distanceFrequencies[symbol]) continue;
    params[position++] = symbol;
    params[position++] = distanceCodes.lengths[symbol];
  }
  return { params, payload: bitstream };
}

function readLzTokenHuffmanParams(params) {
  if (params.length < 3) fail('invalid_archive', 'Обрезаны параметры токенного LZ');
  const tokenCount = params.readUInt16LE(0);
  if (!tokenCount || tokenCount > 512 || params.length < 3 + tokenCount * 3) fail('invalid_archive', 'Некорректная таблица токенов LZ');
  const tokenLengths = new Uint8Array(512);
  const tokenFrequencies = new Uint32Array(512);
  let position = 2;
  for (let i = 0; i < tokenCount; i++) {
    const symbol = params.readUInt16LE(position);
    const length = params[position + 2];
    if (symbol >= tokenLengths.length || !length || length > 31 || tokenLengths[symbol]) fail('invalid_archive', 'Некорректный код токена LZ');
    tokenLengths[symbol] = length;
    tokenFrequencies[symbol] = 1;
    position += 3;
  }
  const distanceCount = params[position++];
  if (distanceCount > MAX_DISTANCE_SLOT + 1 || params.length !== position + distanceCount * 2) fail('invalid_archive', 'Некорректная таблица расстояний LZ');
  const distanceLengths = new Uint8Array(MAX_DISTANCE_SLOT + 1);
  const distanceFrequencies = new Uint32Array(MAX_DISTANCE_SLOT + 1);
  for (let i = 0; i < distanceCount; i++) {
    const symbol = params[position++];
    const length = params[position++];
    if (symbol > MAX_DISTANCE_SLOT || !length || length > 31 || distanceLengths[symbol]) fail('invalid_archive', 'Некорректный код расстояния LZ');
    distanceLengths[symbol] = length;
    distanceFrequencies[symbol] = 1;
  }
  if (!distanceCount) fail('invalid_archive', 'Нет таблицы расстояний для LZ');
  const tokenTable = canonicalDecodeTable(tokenLengths);
  const distanceTable = distanceCount ? canonicalDecodeTable(distanceLengths) : null;
  return { tokenTable, distanceTable };
}

function canonicalDecodeTable(lengths) {
  const counts = new Uint32Array(32);
  let maxLength = 0;
  for (const length of lengths) {
    if (length) {
      counts[length]++;
      maxLength = Math.max(maxLength, length);
    }
  }
  if (!maxLength) fail('invalid_archive', 'Пустая таблица токенного LZ');
  const byLength = Array.from({ length: maxLength + 1 }, () => new Map());
  const nextCode = new Uint32Array(32);
  let code = 0;
  for (let length = 1; length <= maxLength; length++) {
    code = (code + counts[length - 1]) * 2;
    if (code + counts[length] > 2 ** length) fail('invalid_archive', 'Повреждена таблица токенного LZ');
    nextCode[length] = code;
  }
  for (let symbol = 0; symbol < lengths.length; symbol++) {
    const length = lengths[symbol];
    if (length) byLength[length].set(nextCode[length]++, symbol);
  }
  return { byLength, maxLength };
}

function lzTokenHuffmanDecode(payload, params, outputSize, maxDistance = WINDOW_SIZE) {
  const { tokenTable, distanceTable } = readLzTokenHuffmanParams(params);
  let bitPosition = 0;
  const totalBits = payload.length * 8;
  const readBits = count => {
    if (bitPosition + count > totalBits) fail('invalid_archive', 'Обрезан токенный поток LZ');
    let value = 0;
    for (let i = 0; i < count; i++) {
      value = value * 2 + ((payload[bitPosition >>> 3] >>> (7 - (bitPosition & 7))) & 1);
      bitPosition++;
    }
    return value;
  };
  const readSymbol = table => {
    if (!table) fail('invalid_archive', 'Отсутствует таблица расстояний LZ');
    let code = 0;
    for (let length = 1; length <= table.maxLength; length++) {
      code = code * 2 + readBits(1);
      const symbol = table.byLength[length].get(code);
      if (symbol !== undefined) return symbol;
    }
    fail('invalid_archive', 'Некорректный код токенного LZ');
  };

  const output = Buffer.alloc(outputSize);
  let written = 0;
  while (written < outputSize) {
    const symbol = readSymbol(tokenTable);
    if (symbol < 256) {
      output[written++] = symbol;
      continue;
    }
    const length = symbol - 256 + 3;
    const slot = readSymbol(distanceTable);
    const distance = 2 ** slot + (slot ? readBits(slot) : 0);
    if (length > MAX_MATCH || distance > written || distance > maxDistance || written + length > outputSize) fail('invalid_archive', 'Некорректная ссылка токенного LZ');
    for (let i = 0; i < length; i++) {
      output[written] = output[written - distance];
      written++;
    }
  }
  const padding = totalBits - bitPosition;
  if (padding > 7 || (padding && readBits(padding) !== 0)) fail('invalid_archive', 'Некорректное заполнение токенного LZ');
  return output;
}

function numericTransform(input, id, inverse = false) {
  const recordStride = recordStrideFromTransform(id);
  if (![8, 9, 10, 11].includes(id) && !recordStride) fail('invalid_archive', 'Неизвестный числовой фильтр');
  if (recordStride) return inverse ? restoreDeltaStride(Buffer.from(input), recordStride) : deltaStride(input, recordStride);
  const stride = id <= 9 ? 2 : 4;
  const order = id % 2 === 0 ? 1 : 2;
  return inverse
    ? wordDelta(byteUnshuffle(input, stride, input.length), stride, order, true)
    : byteShuffle(wordDelta(input, stride, order), stride);
}

function chooseWordTransform(input) {
  if (input.length < 8192 || input.length > 2 * 1024 * 1024) return 0;
  const size = Math.min(8192, input.length);
  const starts = [0, Math.floor((input.length - size) / 2 / 4) * 4, Math.floor((input.length - size) / 4) * 4];
  let best = { id: 0, gain: 0.35 };
  for (const id of [8, 9, 10, 11]) {
    let gain = 0;
    for (const start of starts) {
      const sample = input.subarray(start, start + size);
      gain += entropy(sample) - entropy(numericTransform(sample, id));
    }
    gain /= starts.length;
    if (gain > best.gain) best = { id, gain };
  }
  return best.id;
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
  const recordStride = recordStrideFromTransform(id);
  if (recordStride) return deltaStride(input, recordStride);
  fail('invalid_archive', 'Неизвестное преобразование данных');
}

function reverseTransform(input, id) {
  if (id === 1) return restoreDeltaStride(Buffer.from(input), 2);
  if (id === 2) return restoreDeltaStride(Buffer.from(input), 4);
  if (id === 5) return byteUnshuffle(deltaDecode(input), 2, input.length);
  if (id === 6) return byteUnshuffle(deltaDecode(input), 4, input.length);
  if (id === 7) return restoreDeltaStride(Buffer.from(input), 4096);
  const recordStride = recordStrideFromTransform(id);
  if (recordStride) return restoreDeltaStride(Buffer.from(input), recordStride);
  fail('invalid_archive', 'Неизвестное преобразование данных');
}

function chooseTransform(input) {
  if (input.length < 8192 || input.length > 2 * 1024 * 1024) return 0;
  const sampleSize = Math.min(input.length, 16 * 1024);
  const sample = input.subarray(0, sampleSize);
  const originalEntropy = entropy(sample);
  let best = { id: 0, gain: 0 };
  const candidates = [1, 2, 5, 6, 7];
  for (const id of candidates) {
    const gain = originalEntropy - entropy(applyTransform(sample, id));
    if (gain > best.gain) best = { id, gain };
  }
  const minimumGain = input.length >= 8 * 1024 * 1024 ? 0.25 : 0.08;
  return best.gain >= minimumGain ? best.id : 0;
}

function chooseRecordStride(input) {
  if (input.length < 8 * 1024 || input.length > 2 * 1024 * 1024) return 0;
  const sampleSize = Math.min(input.length, 8192);
  const center = Math.floor((input.length - sampleSize) / 2);
  let bestStride = 0;
  let bestGain = 0.35;
  const strideGains = new Map();
  for (const stride of RECORD_STRIDES) {
    if (stride > sampleSize / 2) continue;
    const alignedSamples = [
      input.subarray(0, sampleSize),
      input.subarray(Math.floor(center / stride) * stride, Math.floor(center / stride) * stride + sampleSize),
      input.subarray(Math.floor((input.length - sampleSize) / stride) * stride, Math.floor((input.length - sampleSize) / stride) * stride + sampleSize)
    ];
    const gains = alignedSamples.map(sample => entropy(sample) - entropy(deltaStride(sample, stride)));
    gains.sort((a, b) => a - b);
    const stableGain = gains[0];
    strideGains.set(stride, stableGain);
    if (stableGain > bestGain) {
      bestGain = stableGain;
      bestStride = stride;
    }
  }
  if (!bestStride) return 0;
  // Prefer the smallest plausible row period when a larger multiple produces
  // a nearly equal score; the unscaled delta is usually more compact then.
  for (const stride of RECORD_STRIDES) {
    if (stride <= bestStride && strideGains.has(stride) && strideGains.get(stride) >= bestGain - 0.25) return stride;
  }
  return bestStride;
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

// Bit-packed LZSS for short inputs. Literals cost 9 bits; back-references use
// a 12-bit distance (1..4096) and an 8-bit length delta (3..258), so the token
// costs 21 bits instead of the regular stream's 24-bit reference plus flag.
function smallLzEncode(input) {
  const output = [];
  const positionsByKey = new Map();
  let pendingByte = 0;
  let pendingBits = 0;
  const writeBits = (value, count) => {
    for (let bit = count - 1; bit >= 0; bit--) {
      pendingByte = (pendingByte << 1) | ((value >>> bit) & 1);
      if (++pendingBits === 8) {
        output.push(pendingByte);
        pendingByte = 0;
        pendingBits = 0;
      }
    }
  };
  const keyAt = position => (input[position] << 16) | (input[position + 1] << 8) | input[position + 2];
  const insert = position => {
    if (position + 2 >= input.length) return;
    const key = keyAt(position);
    const positions = positionsByKey.get(key) || [];
    positions.push(position);
    positionsByKey.set(key, positions);
  };

  let position = 0;
  while (position < input.length) {
    let bestLength = 0;
    let bestDistance = 0;
    if (position + 2 < input.length) {
      const candidates = positionsByKey.get(keyAt(position)) || [];
      let examined = 0;
      for (let i = candidates.length - 1; i >= 0 && examined < 64; i--, examined++) {
        const candidate = candidates[i];
        const distance = position - candidate;
        if (distance > 4096) break;
        const limit = Math.min(258, input.length - position);
        let length = 3;
        while (length < limit && input[candidate + length] === input[position + length]) length++;
        if (length > bestLength) {
          bestLength = length;
          bestDistance = distance;
          if (length === limit) break;
        }
      }
    }

    if (bestLength >= 3) {
      writeBits(1, 1);
      writeBits(bestDistance - 1, 12);
      writeBits(bestLength - 3, 8);
      for (let i = 0; i < bestLength; i++) insert(position + i);
      position += bestLength;
    } else {
      writeBits(0, 1);
      writeBits(input[position], 8);
      insert(position++);
    }
  }
  if (pendingBits) output.push(pendingByte << (8 - pendingBits));
  return Buffer.from(output);
}

function smallLzDecode(payload, outputSize) {
  const output = Buffer.alloc(outputSize);
  const totalBits = payload.length * 8;
  let bitPosition = 0;
  const readBits = count => {
    if (bitPosition + count > totalBits) fail('invalid_archive', 'Обрезан короткий поток LZSS');
    let value = 0;
    for (let i = 0; i < count; i++) {
      value = value * 2 + ((payload[bitPosition >>> 3] >>> (7 - (bitPosition & 7))) & 1);
      bitPosition++;
    }
    return value;
  };

  let written = 0;
  while (written < outputSize) {
    if (readBits(1) === 0) {
      output[written++] = readBits(8);
      continue;
    }
    const distance = readBits(12) + 1;
    const length = readBits(8) + 3;
    if (distance > written || written + length > outputSize) fail('invalid_archive', 'Некорректная ссылка короткого LZSS');
    for (let i = 0; i < length; i++) {
      output[written] = output[written - distance];
      written++;
    }
  }

  const paddingBits = totalBits - bitPosition;
  if (paddingBits > 7) fail('invalid_archive', 'Лишние данные короткого LZSS');
  if (paddingBits && readBits(paddingBits) !== 0) fail('invalid_archive', 'Некорректное заполнение короткого LZSS');
  return output;
}

function isAsciiLetter(byte) {
  return (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122);
}

function wordDictionary(input) {
  const counts = new Map();
  let position = 0;
  while (position < input.length) {
    if (!isAsciiLetter(input[position])) {
      position++;
      continue;
    }
    const start = position++;
    while (position < input.length && isAsciiLetter(input[position])) position++;
    const length = position - start;
    if (length < 3) continue;
    const word = input.subarray(start, position).toString('ascii');
    counts.set(word, (counts.get(word) || 0) + 1);
  }

  return [...counts.entries()]
    .filter(([word, count]) => count >= 2)
    .map(([word, count]) => ({
      word: Buffer.from(word, 'ascii'),
      count,
      gain: (word.length - 2) * count - word.length - writeVarUint(word.length).length
    }))
    .filter(entry => entry.gain > 0)
    .sort((a, b) => b.gain - a.gain || b.count - a.count || b.word.length - a.word.length)
    .slice(0, 255)
    .map(entry => entry.word);
}

function wordDictionaryEncode(input, searchLimit) {
  const dictionary = wordDictionary(input);
  if (!dictionary.length) return null;
  const indexes = new Map(dictionary.map((word, index) => [word.toString('ascii'), index]));
  const tokens = [];
  let literalStart = 0;
  let position = 0;
  while (position < input.length) {
    if (!isAsciiLetter(input[position])) {
      position++;
      continue;
    }
    const start = position++;
    while (position < input.length && isAsciiLetter(input[position])) position++;
    const index = indexes.get(input.subarray(start, position).toString('ascii'));
    if (index === undefined) continue;
    tokens.push(Buffer.from([0]), Buffer.from(writeVarUint(start - literalStart)), input.subarray(literalStart, start), Buffer.from([1]), Buffer.from(writeVarUint(index)));
    literalStart = position;
  }
  tokens.push(Buffer.from([0]), Buffer.from(writeVarUint(input.length - literalStart)), input.subarray(literalStart));
  const tokenStream = Buffer.concat(tokens);

  const lz = lzssEncode(tokenStream, Math.max(searchLimit, 96));
  let type = 0;
  let params = Buffer.alloc(0);
  let data = lz;
  const huffman = buildHuffman(lz);
  if (huffman) {
    const full = huffmanParams(huffman);
    const compact = compactHuffmanParams(1, full);
    const choose = (candidateType, candidateParams) => {
      const candidate = 1 + writeVarUint(candidateParams.length).length + candidateParams.length + huffman.data.length;
      const current = 1 + writeVarUint(params.length).length + params.length + data.length;
      if (candidate < current) {
        type = candidateType;
        params = candidateParams;
        data = huffman.data;
      }
    };
    choose(1, full);
    if (compact && compact.length < full.length) choose(2, compact);
  }

  const header = [Buffer.from(writeVarUint(dictionary.length))];
  for (const word of dictionary) header.push(Buffer.from(writeVarUint(word.length)), word);
  header.push(Buffer.from(writeVarUint(tokenStream.length)), Buffer.from([type]), Buffer.from(writeVarUint(params.length)), params);
  return Buffer.concat([...header, data]);
}

function wordDictionaryDecode(payload, outputSize) {
  const state = { position: 0 };
  const count = readVarUint(payload, state);
  if (!count || count > 255) fail('invalid_archive', 'Некорректный словарь текста');
  const dictionary = [];
  for (let i = 0; i < count; i++) {
    const length = readVarUint(payload, state);
    if (length < 3 || length > payload.length - state.position) fail('invalid_archive', 'Некорректное слово в словаре');
    dictionary.push(payload.subarray(state.position, state.position + length));
    state.position += length;
  }
  const tokenSize = readVarUint(payload, state);
  if (tokenSize > MAX_ORIGINAL_SIZE + Math.ceil(MAX_ORIGINAL_SIZE / 8) + 16 || state.position >= payload.length) {
    fail('invalid_archive', 'Некорректный размер словарного потока');
  }
  const type = payload[state.position++];
  const paramsLength = readVarUint(payload, state);
  if (paramsLength > payload.length - state.position) fail('invalid_archive', 'Обрезаны параметры словарного потока');
  let params = payload.subarray(state.position, state.position + paramsLength);
  state.position += paramsLength;
  let tokenStream;
  if (type === 0) {
    tokenStream = lzssDecode(payload.subarray(state.position), tokenSize);
  } else if (type === 1 || type === 2) {
    let header = { method: 1, params };
    if (type === 2) header = expandCompactHeader(header);
    const huffman = parseHuffman(header);
    const lzStream = decodeHuffman(payload.subarray(state.position), huffman.lengths, huffman.decodedSize);
    tokenStream = lzssDecode(lzStream, tokenSize);
  } else {
    fail('invalid_archive', 'Неизвестное кодирование словарного потока');
  }

  const output = Buffer.alloc(outputSize);
  const tokenState = { position: 0 };
  let written = 0;
  while (tokenState.position < tokenStream.length) {
    const kind = tokenStream[tokenState.position++];
    if (kind === 0) {
      const length = readVarUint(tokenStream, tokenState);
      if (length > tokenStream.length - tokenState.position || length > outputSize - written) fail('invalid_archive', 'Обрезан литеральный текстовый блок');
      tokenStream.copy(output, written, tokenState.position, tokenState.position + length);
      tokenState.position += length;
      written += length;
    } else if (kind === 1) {
      const index = readVarUint(tokenStream, tokenState);
      if (index >= dictionary.length || dictionary[index].length > outputSize - written) fail('invalid_archive', 'Некорректная ссылка на слово');
      dictionary[index].copy(output, written);
      written += dictionary[index].length;
    } else {
      fail('invalid_archive', 'Неизвестный токен словарного текста');
    }
  }
  if (written !== outputSize) fail('invalid_archive', 'Словарный поток не совпадает с размером файла');
  return output;
}

// Cyclic suffix sorting with counting-sort doubling. Workspace is bounded by
// one block, not the whole file; no platform compression library is used.
function bwtEncode(input) {
  const size = input.length;
  if (!size) return { primary: 0, data: Buffer.alloc(0) };
  const order = new Uint32Array(size);
  const shifted = new Uint32Array(size);
  let classes = new Uint32Array(size);
  let nextClasses = new Uint32Array(size);
  const counts = new Uint32Array(Math.max(256, size));
  for (const byte of input) counts[byte]++;
  let sum = 0;
  for (let i = 0; i < 256; i++) {
    const count = counts[i];
    counts[i] = sum;
    sum += count;
  }
  for (let i = 0; i < size; i++) order[counts[input[i]]++] = i;
  let classCount = 1;
  for (let i = 1; i < size; i++) {
    if (input[order[i]] !== input[order[i - 1]]) classCount++;
    classes[order[i]] = classCount - 1;
  }
  for (let width = 1; width < size && classCount < size; width *= 2) {
    counts.fill(0, 0, classCount);
    for (let i = 0; i < size; i++) {
      const start = order[i] - width;
      shifted[i] = start < 0 ? start + size : start;
      counts[classes[shifted[i]]]++;
    }
    sum = 0;
    for (let i = 0; i < classCount; i++) {
      const count = counts[i];
      counts[i] = sum;
      sum += count;
    }
    for (let i = 0; i < size; i++) {
      const start = shifted[i];
      order[counts[classes[start]]++] = start;
    }
    let nextCount = 1;
    nextClasses[order[0]] = 0;
    for (let i = 1; i < size; i++) {
      const current = order[i];
      const previous = order[i - 1];
      const currentEnd = current + width < size ? current + width : current + width - size;
      const previousEnd = previous + width < size ? previous + width : previous + width - size;
      if (classes[current] !== classes[previous] || classes[currentEnd] !== classes[previousEnd]) nextCount++;
      nextClasses[current] = nextCount - 1;
    }
    [classes, nextClasses] = [nextClasses, classes];
    classCount = nextCount;
  }
  const data = Buffer.allocUnsafe(size);
  let primary = 0;
  for (let i = 0; i < size; i++) {
    const start = order[i];
    if (start === 0) primary = i;
    data[i] = input[start === 0 ? size - 1 : start - 1];
  }
  return { primary, data };
}

function bwtDecode(data, primary) {
  if (!data.length || primary >= data.length) fail('invalid_archive', 'Некорректная позиция BWT');
  const counts = new Uint32Array(256);
  for (const byte of data) counts[byte]++;
  let sum = 0;
  for (let i = 0; i < 256; i++) {
    const count = counts[i];
    counts[i] = sum;
    sum += count;
  }
  const next = new Uint32Array(data.length);
  for (let i = 0; i < data.length; i++) next[counts[data[i]]++] = i;
  const output = Buffer.allocUnsafe(data.length);
  let row = primary;
  for (let i = 0; i < output.length; i++) {
    row = next[row];
    output[i] = data[row];
  }
  return output;
}

// Move-to-front ranks, with zero runs stored as 0 followed by a varint.
function mtfRunsEncode(input) {
  const alphabet = Uint8Array.from({ length: 256 }, (_, i) => i);
  const output = [];
  let zeros = 0;
  const flush = () => {
    if (zeros) output.push(0, ...writeVarUint(zeros));
    zeros = 0;
  };
  for (const byte of input) {
    let rank = 0;
    while (alphabet[rank] !== byte) rank++;
    if (!rank) {
      zeros++;
      continue;
    }
    flush();
    output.push(rank);
    for (let i = rank; i > 0; i--) alphabet[i] = alphabet[i - 1];
    alphabet[0] = byte;
  }
  flush();
  return Buffer.from(output);
}

function mtfRunsDecode(input, outputSize) {
  const alphabet = Uint8Array.from({ length: 256 }, (_, i) => i);
  const output = Buffer.allocUnsafe(outputSize);
  const state = { position: 0 };
  let written = 0;
  while (state.position < input.length) {
    const rank = input[state.position++];
    if (rank === 0) {
      const length = readVarUint(input, state);
      if (!length || length > outputSize - written) fail('invalid_archive', 'Некорректная серия MTF');
      output.fill(alphabet[0], written, written + length);
      written += length;
    } else {
      if (written >= outputSize) fail('invalid_archive', 'Лишние данные MTF');
      const byte = alphabet[rank];
      output[written++] = byte;
      for (let i = rank; i > 0; i--) alphabet[i] = alphabet[i - 1];
      alphabet[0] = byte;
    }
  }
  if (written !== outputSize) fail('invalid_archive', 'Обрезан поток MTF');
  return output;
}

// Bijective binary zero-run digits (0/1); nonzero MTF ranks are shifted by 1.
// Unlike byte-varint runs this keeps the run alphabet separate from literals.
function mtfBinaryEncode(input) {
  const alphabet = Uint8Array.from({ length: 256 }, (_, i) => i);
  const symbols = [];
  let zeros = 0;
  const flush = () => {
    while (zeros) {
      zeros--;
      symbols.push(zeros & 1);
      zeros = Math.floor(zeros / 2);
    }
  };
  for (const byte of input) {
    let rank = 0;
    while (alphabet[rank] !== byte) rank++;
    if (!rank) { zeros++; continue; }
    flush();
    symbols.push(rank + 1);
    for (let i = rank; i > 0; i--) alphabet[i] = alphabet[i - 1];
    alphabet[0] = byte;
  }
  flush();
  return Uint16Array.from(symbols);
}

function mtfBinaryDecode(symbols, outputSize) {
  const alphabet = Uint8Array.from({ length: 256 }, (_, i) => i);
  const output = Buffer.allocUnsafe(outputSize);
  let written = 0, zeros = 0, weight = 1;
  const flush = () => {
    if (zeros) output.fill(alphabet[0], written, written + zeros);
    written += zeros;
    zeros = 0; weight = 1;
  };
  for (const symbol of symbols) {
    if (symbol < 2) {
      zeros += (symbol + 1) * weight;
      if (zeros > outputSize - written) fail('invalid_archive', 'Слишком длинная бинарная серия MTF');
      weight *= 2;
    } else {
      flush();
      if (symbol > 256 || written >= outputSize) fail('invalid_archive', 'Некорректный бинарный ранг MTF');
      const rank = symbol - 1;
      const byte = alphabet[rank];
      output[written++] = byte;
      for (let i = rank; i > 0; i--) alphabet[i] = alphabet[i - 1];
      alphabet[0] = byte;
    }
  }
  flush();
  if (written !== outputSize) fail('invalid_archive', 'Обрезан бинарный поток MTF');
  return output;
}

function arithmeticContext(symbol, contextual) {
  return contextual ? Math.min(9, symbol < 2 ? symbol : 2 + Math.floor(Math.log2(symbol))) : 0;
}

// Integer 32-bit arithmetic intervals, 12-bit adaptive binary probabilities.
// Products stay below 2^44 and are exact JavaScript integers. No platform codec.
function arithmeticEncode(symbols, width, contextual) {
  const probabilities = new Uint16Array(10 * 1024);
  probabilities.fill(2048);
  const output = [];
  let low = 0, high = 0xffffffff, pending = 0, context = 0;
  let byte = 0, bits = 0;
  const put = bit => {
    byte = (byte << 1) | bit;
    if (++bits === 8) { output.push(byte); byte = 0; bits = 0; }
  };
  const emit = bit => { put(bit); while (pending) { put(bit ^ 1); pending--; } };
  for (const symbol of symbols) {
    let node = 1;
    for (let shift = width - 1; shift >= 0; shift--) {
      const index = context * 1024 + node;
      const probability = probabilities[index];
      const bit = (symbol >>> shift) & 1;
      const split = low + Math.floor((high - low + 1) * probability / 4096);
      if (bit) low = split; else high = split - 1;
      probabilities[index] = bit ? probability - (probability >>> 4) : probability + ((4096 - probability) >>> 4);
      for (;;) {
        if (high < 0x80000000) emit(0);
        else if (low >= 0x80000000) { emit(1); low -= 0x80000000; high -= 0x80000000; }
        else if (low >= 0x40000000 && high < 0xc0000000) { pending++; low -= 0x40000000; high -= 0x40000000; }
        else break;
        low *= 2; high = high * 2 + 1;
      }
      node = node * 2 + bit;
    }
    context = arithmeticContext(symbol, contextual);
  }
  pending++; emit(low < 0x40000000 ? 0 : 1);
  if (bits) output.push(byte << (8 - bits));
  // Explicit lookahead, never silently synthesize missing input bits.
  output.push(0, 0, 0, 0);
  return Buffer.from(output);
}

function arithmeticDecode(data, count, width, contextual) {
  const probabilities = new Uint16Array(10 * 1024);
  probabilities.fill(2048);
  const output = new Uint16Array(count);
  let low = 0, high = 0xffffffff, code = 0, position = 0, context = 0;
  const get = () => {
    if (position >= data.length * 8) fail('invalid_archive', 'Обрезан арифметический поток');
    const bit = (data[position >>> 3] >>> (7 - (position & 7))) & 1;
    position++;
    return bit;
  };
  for (let i = 0; i < 32; i++) code = code * 2 + get();
  for (let i = 0; i < count; i++) {
    let node = 1, symbol = 0;
    for (let shift = width - 1; shift >= 0; shift--) {
      const index = context * 1024 + node;
      const probability = probabilities[index];
      const split = low + Math.floor((high - low + 1) * probability / 4096);
      const bit = code >= split ? 1 : 0;
      if (bit) low = split; else high = split - 1;
      probabilities[index] = bit ? probability - (probability >>> 4) : probability + ((4096 - probability) >>> 4);
      for (;;) {
        if (high < 0x80000000) { /* lower half */ }
        else if (low >= 0x80000000) { code -= 0x80000000; low -= 0x80000000; high -= 0x80000000; }
        else if (low >= 0x40000000 && high < 0xc0000000) { code -= 0x40000000; low -= 0x40000000; high -= 0x40000000; }
        else break;
        low *= 2; high = high * 2 + 1; code = code * 2 + get();
      }
      node = node * 2 + bit;
      symbol = symbol * 2 + bit;
    }
    if (symbol > 256) fail('invalid_archive', 'Некорректный арифметический символ');
    output[i] = symbol;
    context = arithmeticContext(symbol, contextual);
  }
  // Canonical termination also rejects trailing bytes and altered lookahead.
  if (!arithmeticEncode(output, width, contextual).equals(data)) fail('invalid_archive', 'Некорректное завершение арифметического потока');
  return output;
}

function contextBlocksEncode(input, blockSize = CONTEXT_BLOCK_SIZE, adaptive = false) {
  const count = Math.ceil(input.length / blockSize);
  const parts = [Buffer.from(writeVarUint(blockSize)), Buffer.from(writeVarUint(count))];
  for (let start = 0; start < input.length; start += blockSize) {
    const block = input.subarray(start, Math.min(input.length, start + blockSize));
    const bwt = bwtEncode(block);
    const runs = mtfRunsEncode(bwt.data);
    const huffman = buildHuffman(runs);
    const raw = Buffer.concat([Buffer.from([0]), Buffer.from(writeVarUint(block.length)), block]);
    let chosen = raw;
    if (huffman) {
      const full = huffmanParams(huffman);
      const compact = compactHuffmanParams(2, full);
      const params = compact && compact.length < full.length ? compact : full;
      const mode = params === full ? 2 : 1;
      const compressed = Buffer.concat([
        Buffer.from([mode]), Buffer.from(writeVarUint(block.length)),
        Buffer.from(writeVarUint(bwt.primary)), Buffer.from(writeVarUint(params.length)), params,
        Buffer.from(writeVarUint(huffman.data.length)), huffman.data
      ]);
      if (compressed.length < raw.length) chosen = compressed;
    }
    if (adaptive) {
      const binary = mtfBinaryEncode(bwt.data);
      for (const mode of [3, 4, 5]) {
        const symbols = mode === 3 ? runs : binary;
        const data = arithmeticEncode(symbols, mode === 3 ? 8 : 9, mode !== 5);
        const compressed = Buffer.concat([
          Buffer.from([mode]), Buffer.from(writeVarUint(block.length)),
          Buffer.from(writeVarUint(bwt.primary)), Buffer.from(writeVarUint(symbols.length)),
          Buffer.from(writeVarUint(data.length)), data
        ]);
        if (compressed.length < chosen.length) chosen = compressed;
      }
    }
    parts.push(chosen);
  }
  return Buffer.concat(parts);
}

function contextBlocksDecode(payload, outputSize) {
  const state = { position: 0 };
  const blockSize = readVarUint(payload, state);
  if (![16, 20, 24, 28, 32, 40, 64, 128, 256, 512].some(size => size * 1024 === blockSize)) fail('invalid_archive', 'Недопустимый размер блока BWT');
  const count = readVarUint(payload, state);
  if (count !== Math.ceil(outputSize / blockSize) || !count) fail('invalid_archive', 'Некорректное число блоков BWT');
  const output = Buffer.allocUnsafe(outputSize);
  let written = 0;
  for (let i = 0; i < count; i++) {
    if (state.position >= payload.length) fail('invalid_archive', 'Обрезан заголовок блока BWT');
    const mode = payload[state.position++];
    const length = readVarUint(payload, state);
    if (length !== Math.min(blockSize, outputSize - written)) fail('invalid_archive', 'Некорректный размер блока BWT');
    if (mode === 0) {
      if (length > payload.length - state.position) fail('invalid_archive', 'Обрезан блок хранения BWT');
      payload.copy(output, written, state.position, state.position + length);
      state.position += length;
    } else if (mode === 1 || mode === 2) {
      const primary = readVarUint(payload, state);
      const paramsLength = readVarUint(payload, state);
      if (primary >= length || paramsLength > 1024 || paramsLength > payload.length - state.position) fail('invalid_archive', 'Некорректный заголовок BWT');
      const params = payload.subarray(state.position, state.position + paramsLength);
      state.position += paramsLength;
      // Validate the compact header before expanding it: the generic helper
      // assumes that its caller already checked the size and symbol count.
      if (mode === 1) {
        if (params.length < 7 || params[0] !== 2) fail('invalid_archive', 'Некорректная таблица блока BWT');
        const symbols = params.readUInt16LE(5);
        if (!symbols || symbols > 256 || params.length !== 7 + symbols + Math.ceil(symbols / 2)) fail('invalid_archive', 'Обрезана таблица блока BWT');
      }
      const header = mode === 1 ? expandCompactHeader({ params }) : { params, method: 2 };
      const huffman = parseHuffman(header);
      if (!huffman.decodedSize || huffman.decodedSize > length * 2 + 8) fail('invalid_archive', 'Слишком большой поток MTF');
      const dataLength = readVarUint(payload, state);
      if (dataLength > payload.length - state.position) fail('invalid_archive', 'Обрезаны данные блока BWT');
      const runs = decodeHuffman(payload.subarray(state.position, state.position + dataLength), huffman.lengths, huffman.decodedSize);
      state.position += dataLength;
      bwtDecode(mtfRunsDecode(runs, length), primary).copy(output, written);
    } else if (mode >= 3 && mode <= 5) {
      const primary = readVarUint(payload, state);
      const symbols = readVarUint(payload, state);
      const dataLength = readVarUint(payload, state);
      if (primary >= length || !symbols || symbols > length * 2 + 8 || dataLength < 5 || dataLength > payload.length - state.position) fail('invalid_archive', 'Некорректный арифметический блок BWT');
      const data = payload.subarray(state.position, state.position + dataLength);
      state.position += dataLength;
      const ranks = arithmeticDecode(data, symbols, mode === 3 ? 8 : 9, mode !== 5);
      const sorted = mode === 3 ? mtfRunsDecode(ranks, length) : mtfBinaryDecode(ranks, length);
      bwtDecode(sorted, primary).copy(output, written);
    } else {
      fail('invalid_archive', 'Неизвестный режим блока BWT');
    }
    written += length;
  }
  if (state.position !== payload.length) fail('invalid_archive', 'Лишние данные блоков BWT');
  return output;
}

function transposeBytes(input, stride, phase = 0) {
  if (!Number.isInteger(stride) || stride < 1 || stride > 4096 || !Number.isInteger(phase) || phase < 0 || phase >= stride) fail('invalid_archive', 'Некорректные параметры транспонирования');
  const prefix = Math.min(phase, input.length);
  const tail = (input.length - prefix) % stride;
  const rows = Math.floor((input.length - prefix) / stride);
  const output = Buffer.allocUnsafe(input.length);
  input.copy(output, 0, 0, prefix);
  let destination = prefix;
  for (let column = 0; column < stride; column++) {
    for (let row = 0; row < rows; row++) output[destination++] = input[prefix + row * stride + column];
  }
  input.copy(output, destination, input.length - tail);
  return output;
}

function chooseTransposeParameters(input, stride) {
  const sampleSize = Math.min(input.length, 8192);
  const phases = [];
  for (let phase = 0; phase < stride; phase++) {
    const counts = Array.from({ length: stride }, () => new Uint32Array(256));
    const totals = new Uint32Array(stride);
    for (let index = phase; index < sampleSize; index++) {
      const column = (index - phase) % stride;
      counts[column][input[index]]++;
      totals[column]++;
    }
    let sumEntropy = 0;
    for (let column = 0; column < stride; column++) sumEntropy += entropyFromCounts(counts[column], totals[column]);
    phases.push({ phase, score: sumEntropy / stride });
  }
  phases.sort((a, b) => a.score - b.score || a.phase - b.phase);
  return phases.slice(0, Math.min(1, phases.length)).map(({ phase }) => phase);
}

function untransposeBytes(input, stride, phase = 0) {
  if (!Number.isInteger(stride) || stride < 1 || stride > 4096 || !Number.isInteger(phase) || phase < 0 || phase >= stride) fail('invalid_archive', 'Некорректные параметры транспонирования');
  const prefix = Math.min(phase, input.length);
  const tail = (input.length - prefix) % stride;
  const rows = Math.floor((input.length - prefix) / stride);
  const output = Buffer.allocUnsafe(input.length);
  input.copy(output, 0, 0, prefix);
  let source = prefix;
  for (let column = 0; column < stride; column++) {
    for (let row = 0; row < rows; row++) output[prefix + row * stride + column] = input[source++];
  }
  input.copy(output, input.length - tail, source, source + tail);
  if (source + tail !== input.length) fail('invalid_archive', 'Некорректный транспонированный поток записей');
  return output;
}

// Mixed RLE: a varint stores length*2 + kind. Kind 0 is a literal span;
// kind 1 is a repeated byte. Random prefixes and isolated noise bytes don't
// cost two bytes per input byte. Never exceed the current winner's budget.
function mixedRleEncode(input, budget) {
  if (budget < 3) return null;
  const output = Buffer.allocUnsafe(Math.min(input.length, budget));
  let written = 0;
  let literalStart = 0;
  const emit = (start, length, run) => {
    const code = writeVarUint(length * 2 + (run ? 1 : 0));
    const size = code.length + (run ? 1 : length);
    if (written + size >= output.length) return false;
    for (const byte of code) output[written++] = byte;
    if (run) output[written++] = input[start];
    else {
      input.copy(output, written, start, start + length);
      written += length;
    }
    return true;
  };
  let position = 0;
  while (position < input.length) {
    let end = position + 1;
    while (end < input.length && input[end] === input[position]) end++;
    if (end - position >= 4) {
      if (position > literalStart && !emit(literalStart, position - literalStart, false)) return null;
      if (!emit(position, end - position, true)) return null;
      literalStart = end;
    }
    position = end;
  }
  if (literalStart < input.length && !emit(literalStart, input.length - literalStart, false)) return null;
  return Buffer.from(output.subarray(0, written));
}

function mixedRleDecode(payload, outputSize) {
  const output = Buffer.alloc(outputSize);
  const state = { position: 0 };
  let written = 0;
  while (state.position < payload.length) {
    const code = readVarUint(payload, state);
    const length = Math.floor(code / 2);
    if (!length || length > outputSize - written) fail('invalid_archive', 'Некорректная длина серии');
    if (code % 2) {
      if (state.position >= payload.length) fail('invalid_archive', 'Обрезана серия');
      output.fill(payload[state.position++], written, written + length);
    } else {
      if (length > payload.length - state.position) fail('invalid_archive', 'Обрезан литеральный участок');
      payload.copy(output, written, state.position, state.position + length);
      state.position += length;
    }
    written += length;
  }
  if (written !== outputSize) fail('invalid_archive', 'Размер серий не совпадает с размером файла');
  return output;
}

function hasLongRuns(input) {
  // Probe several regions before adding a full pass on large media files.
  if (input.length <= 64 * 1024) return true;
  const size = 4096;
  for (const start of [0, Math.floor(input.length / 2), Math.max(0, input.length - size)]) {
    const end = Math.min(input.length, start + size);
    for (let i = start + 3; i < end; i++) {
      if (input[i] === input[i - 1] && input[i] === input[i - 2] && input[i] === input[i - 3]) return true;
    }
  }
  return false;
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
  return entropyFromCounts(counts, data.length);
}

function entropyFromCounts(counts, total) {
  let result = 0;
  for (const count of counts) {
    if (count) {
      const probability = count / total;
      result -= probability * Math.log2(probability);
    }
  }
  return result;
}

function looksLikeAsciiText(input) {
  const sample = input.subarray(0, Math.min(input.length, 32 * 1024));
  if (sample.length < 128) return false;
  let printable = 0;
  let letters = 0;
  for (const byte of sample) {
    if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) printable++;
    if ((byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)) letters++;
  }
  return printable / sample.length >= 0.96 && letters / sample.length >= 0.12;
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
  // Compact one-byte records: 0x00 remains reserved for the empty file and
  // header bytes 0xf0..0xff use an escape record.
  if (input.length === 1) {
    return input[0] > 0 && input[0] < 0xf0
      ? Buffer.from([input[0]])
      : Buffer.from([COMPACT_ONE_BYTE_MARKER, input[0]]);
  }
  const checksum = sha256(input);
  let best = { method: 0, params: Buffer.alloc(0), payload: input, total: input.length + 5 };

  const encodedSize = (method, params, payload) => {
    if (method === 0) return 5 + payload.length;
    return 1 + writeVarUint(input.length).length + 4 + params.length + payload.length;
  };
  const considerHuffman = (method, params, payload) => {
    const compact = compactHuffmanParams(method, params);
    if (compact && compact.length < params.length) {
      method = 11;
      params = compact;
    }
    const total = encodedSize(method, params, payload);
    if (total < best.total) best = { method, params, payload, total };
  };
  const considerTokenLz = (lzStream, wideDistance) => {
    const tokenHuffman = lzTokenHuffmanEncode(input, lzStream, wideDistance);
    if (!tokenHuffman) return;
    const payload = Buffer.concat([
      Buffer.from([wideDistance ? 1 : 0]), Buffer.from(writeVarUint(tokenHuffman.params.length)),
      tokenHuffman.params, tokenHuffman.payload
    ]);
    const total = encodedSize(8, Buffer.alloc(0), payload);
    if (total < best.total) best = { method: 8, params: Buffer.alloc(0), payload, total };
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

  const wordTransformId = chooseWordTransform(input);
  const transformId = chooseTransform(input);
  const recordStride = chooseRecordStride(input);
  const incompressible = !wordTransformId && !transformId && !recordStride && looksIncompressible(input);
  if (incompressible) {
    // Entropy probes can miss a repeated region when the duplicated pages are
    // farther apart than the regular LZ window. Make one bounded wide-window
    // pass before falling back to store; do not run BWT or numeric transforms.
    if (input.length > WINDOW_SIZE && input.length <= 2 * 1024 * 1024 && best.method === 0) {
      const lz = lzssEncode(input, 12, TOKEN_WINDOW_SIZE);
      considerTokenLz(lz, true);
    }
    return createArchive(best.method, input, best.params, best.payload, checksum);
  }

  const rle = rleEncode(input);
  if (rle) {
    const rleTotal = encodedSize(4, Buffer.alloc(0), rle);
    if (rleTotal < best.total) best = { method: 4, params: Buffer.alloc(0), payload: rle, total: rleTotal };
  }

  // Keep the hash-chain effort proportional to file size. Deep matching is
  // useful for small text; on multi-megabyte files it disproportionately costs
  // CPU while bringing only marginal compression gains.
  const textLike = looksLikeAsciiText(input);
  const searchLimit = input.length < 64 * 1024 ? 48 : input.length < 1024 * 1024 ? 24 : input.length < 8 * 1024 * 1024 ? 12 : 6;
  // ASCII prose can have many equally valid matches. Try the normal shallow
  // chain and one deeper chain, then keep the shorter archive. This avoids
  // making varied prose worse while still helping text with distant repeats.
  const searchLimits = textLike && input.length < 1024 * 1024
    ? [searchLimit, 96]
    : [searchLimit];
  const tokenCandidateAllowed = input.length <= 16 * 1024 * 1024 && (!incompressible || input.length > WINDOW_SIZE);
  for (const limit of new Set(searchLimits)) {
    const lz = lzssEncode(input, limit);
    const rawLzTotal = encodedSize(9, Buffer.alloc(0), lz);
    if (rawLzTotal < best.total) best = { method: 9, params: Buffer.alloc(0), payload: lz, total: rawLzTotal };
    if (tokenCandidateAllowed) {
      const tokenOptions = input.length > 128 * 1024 && input.length <= 2 * 1024 * 1024
        ? [{ lz, wideDistance: false }, { lz: lzssEncode(input, limit, TOKEN_WINDOW_SIZE), wideDistance: true }]
        : [{ lz, wideDistance: false }];
      for (const option of tokenOptions) {
        considerTokenLz(option.lz, option.wideDistance);
      }
    }
    const lzHuffman = buildHuffman(lz);
    if (lzHuffman) {
      const params = huffmanParams(lzHuffman);
      considerHuffman(1, params, lzHuffman.data);
    }
  }

  const directHuffman = buildHuffman(input);
  if (directHuffman) {
    const params = huffmanParams(directHuffman);
    considerHuffman(2, params, directHuffman.data);
  }

  if (!transformId && shouldTryDelta(input)) {
    const delta = deltaEncode(input);
    const deltaLz = lzssEncode(delta, searchLimit);
    const deltaHuffman = buildHuffman(deltaLz);
    if (deltaHuffman) {
      const params = huffmanParams(deltaHuffman);
      considerHuffman(3, params, deltaHuffman.data);
    }
  }

  if (transformId) {
    const transformed = applyTransform(input, transformId);
    const transformedLz = lzssEncode(transformed, searchLimit);
    const transformedHuffman = buildHuffman(transformedLz);
    if (transformedHuffman) {
      const params = Buffer.concat([Buffer.from([transformId]), huffmanParams(transformedHuffman)]);
      considerHuffman(6, params, transformedHuffman.data);
    }
  }
  if (hasLongRuns(input)) {
    const headerSize = encodedSize(10, Buffer.alloc(0), Buffer.alloc(0));
    const mixed = mixedRleEncode(input, best.total - headerSize);
    if (mixed) {
      const total = headerSize + mixed.length;
      if (total < best.total) best = { method: 10, params: Buffer.alloc(0), payload: mixed, total };
    }
  }
  if (recordStride && input.length >= 8 * 1024 && input.length <= 2 * 1024 * 1024) {
    const stride = recordStride;
    const transformId = 16 + RECORD_STRIDES.indexOf(stride);
    const transformed = deltaStride(input, stride);
    const encoded = buildHuffman(transformed);
    if (encoded) {
      considerHuffman(6, Buffer.concat([Buffer.from([transformId]), huffmanParams(encoded)]), encoded.data);
    }
    const payload = Buffer.concat([Buffer.from(writeVarUint(stride)), contextBlocksEncode(transformed, 512 * 1024)]);
    const total = encodedSize(7, Buffer.alloc(0), payload);
    if (total < best.total) {
      best = { method: 7, params: Buffer.alloc(0), payload, total };
    }

    // A byte transpose groups similar record columns before BWT. The detector
    // chooses a phase from the sample, then the full archive still competes
    // against every existing method by total size.
    const transposeStride = stride >= 8 && stride <= 64 ? stride : 0;
    if (transposeStride) {
      const phases = chooseTransposeParameters(input, transposeStride);
      const transposeCandidates = [];
      for (const phase of phases) {
        const transposed = transposeBytes(input, transposeStride, phase);
        for (const blockSize of [16, 20, 24, 28, 32, 40]) {
          const payload = Buffer.concat([
            Buffer.from(writeVarUint(RECORD_TRANSPOSE_MARKER)),
            Buffer.from(writeVarUint(transposeStride)),
            Buffer.from(writeVarUint(phase)),
            contextBlocksEncode(transposed, blockSize * 1024)
          ]);
          const total = encodedSize(7, Buffer.alloc(0), payload);
          transposeCandidates.push({ method: 7, params: Buffer.alloc(0), payload, total });
        }
      }
      transposeCandidates.sort((a, b) => a.total - b.total);
      if (transposeCandidates[0]?.total < best.total) best = transposeCandidates[0];
    }
  }
  if (input.length <= 4096) {
    const smallLz = smallLzEncode(input);
    const smallLzTotal = encodedSize(12, Buffer.alloc(0), smallLz);
    if (smallLzTotal < best.total) best = { method: 12, params: Buffer.alloc(0), payload: smallLz, total: smallLzTotal };
  }
  if (textLike && input.length >= 16 * 1024 && input.length <= 256 * 1024) {
    const wordPayload = wordDictionaryEncode(input, searchLimit);
    if (wordPayload) {
      const wordTotal = encodedSize(14, Buffer.alloc(0), wordPayload);
      if (wordTotal < best.total) best = { method: 14, params: Buffer.alloc(0), payload: wordPayload, total: wordTotal };
    }
  }
  // A separate context-sorting candidate helps diverse prose and structured
  // binary that don't have long exact LZ matches. Keep all previous winners.
  if (input.length >= 64 && input.length <= 2 * 1024 * 1024) {
    for (const blockSize of [128, 512]) {
      const contextPayload = contextBlocksEncode(input, blockSize * 1024, true);
      const total = encodedSize(13, Buffer.alloc(0), contextPayload);
      if (total < best.total) best = { method: 13, params: Buffer.alloc(0), payload: contextPayload, total };
    }
  }
  if (wordTransformId) {
    const transformed = numericTransform(input, wordTransformId);
    for (const blockSize of [128, 512]) {
      const payload = Buffer.concat([Buffer.from([wordTransformId]), contextBlocksEncode(transformed, blockSize * 1024)]);
      const total = encodedSize(15, Buffer.alloc(0), payload);
      if (total < best.total) best = { method: 15, params: Buffer.alloc(0), payload, total };
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
  if (![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].includes(method)) fail('unsupported_method', `Неподдерживаемый метод: ${method}`);
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
  if (method === 11) {
    if (state.position >= archive.length) fail('invalid_archive', 'Обрезана компактная таблица');
    const innerMethod = archive[state.position];
    if (![1, 2, 3, 6].includes(innerMethod)) fail('invalid_archive', 'Некорректный метод таблицы');
    const offset = innerMethod === 6 ? 1 : 0;
    if (state.position + 7 + offset > archive.length) fail('invalid_archive', 'Обрезана компактная таблица');
    const symbols = archive.readUInt16LE(state.position + 5 + offset);
    const size = 7 + offset + symbols + Math.ceil(symbols / 2);
    if (!symbols || symbols > 256 || size > archive.length - state.position) fail('invalid_archive', 'Некорректный размер таблицы');
    params = archive.subarray(state.position, state.position + size);
    state.position += size;
  } else if (method === 5) {
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
    if (![1, 2, 5, 6, 7].includes(transformId) && !recordStrideFromTransform(transformId)) fail('invalid_archive', 'Неизвестное преобразование данных');
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
  if (archive.length === 1 && archive[0] > 0 && archive[0] < 0xf0) return Buffer.from([archive[0]]);
  if (archive.length === 2 && archive[0] === COMPACT_ONE_BYTE_MARKER) return Buffer.from([archive[1]]);
  let header = readHeader(archive);
  if (header.method === 11) header = expandCompactHeader(header);
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
  } else if (header.method === 8) {
    if (header.payload.length < 2 || header.payload[0] > 1) fail('invalid_archive', 'Некорректный режим окна токенного LZ');
    const maxDistance = header.payload[0] ? TOKEN_WINDOW_SIZE : WINDOW_SIZE;
    const state = { position: 1 };
    const paramsLength = readVarUint(header.payload, state);
    if (!paramsLength || paramsLength > header.payload.length - state.position) fail('invalid_archive', 'Некорректный размер таблиц токенного LZ');
    const params = header.payload.subarray(state.position, state.position + paramsLength);
    state.position += paramsLength;
    output = lzTokenHuffmanDecode(header.payload.subarray(state.position), params, header.originalSize, maxDistance);
  } else if (header.method === 7) {
    const state = { position: 0 };
    const stride = readVarUint(header.payload, state);
    if (stride === RECORD_TRANSPOSE_MARKER) {
      const transposeStride = readVarUint(header.payload, state);
      const phase = readVarUint(header.payload, state);
      if (transposeStride < 2 || transposeStride > 4096 || phase >= transposeStride) fail('invalid_archive', 'Некорректные параметры транспонирования записей');
      output = untransposeBytes(contextBlocksDecode(header.payload.subarray(state.position), header.originalSize), transposeStride, phase);
    } else {
      if (!RECORD_STRIDES.includes(stride)) fail('invalid_archive', 'Некорректный шаг бинарных записей');
      output = restoreDeltaStride(contextBlocksDecode(header.payload.subarray(state.position), header.originalSize), stride);
    }
  } else if (header.method === 9) {
    output = lzssDecode(header.payload, header.originalSize);
  } else if (header.method === 10) {
    output = mixedRleDecode(header.payload, header.originalSize);
  } else if (header.method === 12) {
    output = smallLzDecode(header.payload, header.originalSize);
  } else if (header.method === 14) {
    output = wordDictionaryDecode(header.payload, header.originalSize);
  } else if (header.method === 13) {
    output = contextBlocksDecode(header.payload, header.originalSize);
  } else if (header.method === 15) {
    const id = header.payload[0];
    if (![8, 9, 10, 11].includes(id) && !recordStrideFromTransform(id)) fail('invalid_archive', 'Неизвестный числовой фильтр');
    output = numericTransform(contextBlocksDecode(header.payload.subarray(1), header.originalSize), id, true);
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
  methods: { 0: 'store', 1: 'lzss+huffman', 2: 'huffman', 3: 'delta+lzss+huffman', 4: 'rle', 5: 'repeat', 6: 'transform+lzss+huffman', 7: 'record-context+bwt', 8: 'lz-token+huffman', 9: 'lzss', 10: 'mixed-rle', 11: 'compact-huffman', 12: 'small-lz', 13: 'bwt+mtf+huffman', 14: 'word-dictionary', 15: 'word-delta+bwt' }
};

export const _testInternals = { lzssEncode, lzssDecode, smallLzEncode, smallLzDecode, wordDictionaryEncode, bwtEncode, bwtDecode, mtfRunsEncode, mtfRunsDecode, mtfBinaryEncode, mtfBinaryDecode, arithmeticEncode, arithmeticDecode, contextBlocksEncode, contextBlocksDecode, numericTransform, transposeBytes, untransposeBytes, chooseTransposeParameters, buildHuffman, decodeHuffman, lzTokenHuffmanEncode, lzTokenHuffmanDecode, chooseRecordStride };
