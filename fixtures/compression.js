// Deterministic synthetic coverage, not the private files used by the arena.
export function randomBytes(size, seed = 0x12345678) {
  const data = Buffer.alloc(size);
  let state = seed;
  for (let i = 0; i < size; i++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    data[i] = state & 255;
  }
  return data;
}

export function compressionFixtures() {
  const words = 'the archive contains original data and repeated words every file must restore exactly without losing information a browser can process text numbers values results compression algorithm sequence dictionary reference'.split(' ');
  let state = 0x12345678;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const english = Buffer.from(Array.from({ length: 40000 }, (_, i) => words[next() % words.length] + (i % 20 ? ' ' : '\n')).join(''));
  const records = Buffer.alloc(409616);
  for (let at = 16; at + 20 <= records.length; at += 20) {
    const row = (at - 16) / 20;
    records.writeUInt32LE(row, at);
    records.writeUInt32LE(row % 64, at + 4);
    records.writeFloatLE(Math.sin(row / 16), at + 8);
    records.writeUInt32LE(next() % 100000, at + 12);
    records.writeUInt32LE(row % 3, at + 16);
  }
  const pcm = Buffer.alloc(240016);
  for (let at = 16; at + 1 < pcm.length; at += 2) {
    pcm.writeInt16LE(Math.round(20000 * Math.sin(at / 29) + 1000 * Math.sin(at / 7)), at);
  }
  const csv = Buffer.from(Array.from({ length: 10000 }, (_, i) => `${i},city-${i % 120},${next() % 10000},active\n`).join(''));
  const json = Buffer.from(JSON.stringify(Array.from({ length: 6000 }, (_, id) => ({ id, city: `city-${id % 120}`, active: !!(id % 3), value: next() % 10000 }))));
  const russian = Buffer.from(Array.from({ length: 2500 }, (_, i) => `Запись ${i}: Архиватор сохраняет данные без потерь. Проверка целостности защищает исходные файлы. Значение ${next() % 10000}.\n`).join(''));
  const zeros = Buffer.concat([randomBytes(16), Buffer.alloc(307200)]);
  return [
    ['english-varied-240k', english.subarray(0, 245760)],
    ['russian-numbered', russian],
    ['csv-varied', csv], ['json-varied', json],
    ['binary-records', records], ['pcm16-signal', pcm],
    ['header+zeros', zeros],
    ['noise-272k', randomBytes(272944)],
    ['tiny-17', Buffer.from('0123456789abcdef!')],
    ['tiny-16', Buffer.from('0123456789abcdef')]
  ];
}
