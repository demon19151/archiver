const API_BASE = location.origin;

// DOM elements
const compressInput = document.getElementById('compressInput');
const compressDropZone = document.getElementById('compressDropZone');
const compressFileList = document.getElementById('compressFileList');
const compressButton = document.getElementById('compressButton');
const downloadCompressedButton = document.getElementById('downloadCompressedButton');

const decompressInput = document.getElementById('decompressInput');
const decompressDropZone = document.getElementById('decompressDropZone');
const decompressFileList = document.getElementById('decompressFileList');
const decompressButton = document.getElementById('decompressButton');
const downloadDecompressedButton = document.getElementById('downloadDecompressedButton');

const idleState = document.getElementById('idleState');
const compressState = document.getElementById('compressState');
const decompressState = document.getElementById('decompressState');

const compressProgress = document.getElementById('compressProgress');
const compressStats = document.getElementById('compressStats');
const decompressProgress = document.getElementById('decompressProgress');
const decompressStats = document.getElementById('decompressStats');
// Vercel function request bodies are limited to roughly 4.5 MB. Keep blocks
// at 4 MiB to leave room for transport overhead, and process a small bounded
// number concurrently to amortize serverless/network latency on large files.
const CHUNK_SIZE = 4 * 1024 * 1024;
const CHUNK_CONCURRENCY = 3;

// State
let compressFiles = [];
let decompressArchives = [];
let compressedResult = null;
let decompressedResult = null;
let currentMode = null; // 'compress' or 'decompress'

// Helpers
function formatSize(bytes) {
  if (bytes === 0) return '0 Б';
  const units = ['Б', 'КБ', 'МБ', 'ГБ'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

async function readApiError(response, fallback) {
  const contentType = response.headers.get('content-type') || '';
  let detail = '';
  if (contentType.includes('application/json')) {
    const payload = await response.json().catch(() => null);
    detail = payload?.error?.message || payload?.message || '';
  } else {
    detail = (await response.text().catch(() => '')).trim().slice(0, 240);
  }
  return new Error(`${fallback} (HTTP ${response.status})${detail ? `: ${detail}` : ''}`);
}

function switchMode(mode) {
  currentMode = mode;
  idleState.hidden = true;
  compressState.hidden = mode !== 'compress';
  decompressState.hidden = mode !== 'decompress';
  
  if (mode !== 'compress') {
    compressFiles = [];
    compressFileList.hidden = true;
    compressFileList.innerHTML = '';
    compressedResult = null;
  }
  
  if (mode !== 'decompress') {
    decompressArchives = [];
    decompressFileList.hidden = true;
    decompressFileList.innerHTML = '';
    decompressedResult = null;
  }
}

function resetToIdle() {
  currentMode = null;
  compressFiles = [];
  decompressArchives = [];
  compressedResult = null;
  decompressedResult = null;
  
  compressFileList.hidden = true;
  compressFileList.innerHTML = '';
  decompressFileList.hidden = true;
  decompressFileList.innerHTML = '';
  
  idleState.hidden = false;
  compressState.hidden = true;
  decompressState.hidden = true;
  
  compressProgress.textContent = '';
  compressStats.innerHTML = '';
  decompressProgress.textContent = '';
  decompressStats.innerHTML = '';
  
  downloadCompressedButton.hidden = true;
  downloadDecompressedButton.hidden = true;
}

// Compress file list
function updateCompressFileList() {
  if (compressFiles.length === 0) {
    compressFileList.hidden = true;
    compressButton.disabled = true;
    compressProgress.textContent = 'Файлы не выбраны';
    compressStats.innerHTML = '';
    return;
  }
  
  compressFileList.hidden = false;
  compressFileList.innerHTML = '';
  
  compressFiles.forEach((fileData, index) => {
    const item = document.createElement('div');
    item.className = 'file-item';
    
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = fileData.selected;
    checkbox.addEventListener('change', () => {
      compressFiles[index].selected = checkbox.checked;
      updateCompressStats();
    });
    
    const info = document.createElement('div');
    info.className = 'file-info';
    
    const name = document.createElement('div');
    name.className = 'file-name';
    name.textContent = fileData.file.name;
    name.title = fileData.file.name;
    
    const size = document.createElement('div');
    size.className = 'file-size';
    size.textContent = formatSize(fileData.file.size);
    
    info.append(name, size);
    
    const removeBtn = document.createElement('button');
    removeBtn.className = 'file-remove';
    removeBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>';
    removeBtn.addEventListener('click', () => {
      compressFiles.splice(index, 1);
      updateCompressFileList();
    });
    
    item.append(checkbox, info, removeBtn);
    compressFileList.append(item);
  });
  
  updateCompressStats();
}

function updateCompressStats() {
  const selected = compressFiles.filter(f => f.selected);
  const totalSize = selected.reduce((sum, f) => sum + f.file.size, 0);
  
  compressButton.disabled = selected.length === 0;
  
  if (selected.length === 0) {
    compressProgress.textContent = 'Выберите файлы для сжатия';
    compressStats.innerHTML = '';
  } else {
    compressProgress.textContent = `Готово к сжатию: ${selected.length} файл(ов)`;
    compressStats.innerHTML = `
      <div class="stat-row">
        <span class="stat-label">Файлов выбрано:</span>
        <span class="stat-value">${selected.length}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Общий размер:</span>
        <span class="stat-value">${formatSize(totalSize)}</span>
      </div>
    `;
  }
}

// Decompress file list
function updateDecompressFileList() {
  if (decompressArchives.length === 0) {
    decompressFileList.hidden = true;
    decompressButton.disabled = true;
    decompressProgress.textContent = 'Архив не выбран';
    decompressStats.innerHTML = '';
    return;
  }
  
  decompressFileList.hidden = false;
  decompressFileList.innerHTML = '';
  
  decompressArchives.forEach((fileData, index) => {
    const item = document.createElement('div');
    item.className = 'file-item';
    
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = fileData.selected;
    checkbox.addEventListener('change', () => {
      decompressArchives[index].selected = checkbox.checked;
      updateDecompressStats();
    });
    
    const info = document.createElement('div');
    info.className = 'file-info';
    
    const name = document.createElement('div');
    name.className = 'file-name';
    name.textContent = fileData.file.name;
    name.title = fileData.file.name;
    
    const size = document.createElement('div');
    size.className = 'file-size';
    size.textContent = formatSize(fileData.file.size);
    
    info.append(name, size);
    
    const removeBtn = document.createElement('button');
    removeBtn.className = 'file-remove';
    removeBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>';
    removeBtn.addEventListener('click', () => {
      decompressArchives.splice(index, 1);
      updateDecompressFileList();
    });
    
    item.append(checkbox, info, removeBtn);
    decompressFileList.append(item);
  });
  
  updateDecompressStats();
}

function updateDecompressStats() {
  const selected = decompressArchives.filter(f => f.selected);
  const totalSize = selected.reduce((sum, f) => sum + f.file.size, 0);
  
  decompressButton.disabled = selected.length === 0;
  
  if (selected.length === 0) {
    decompressProgress.textContent = 'Выберите архивы для распаковки';
    decompressStats.innerHTML = '';
  } else {
    decompressProgress.textContent = `Готово к распаковке: ${selected.length} архив(ов)`;
    decompressStats.innerHTML = `
      <div class="stat-row">
        <span class="stat-label">Архивов выбрано:</span>
        <span class="stat-value">${selected.length}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Общий размер:</span>
        <span class="stat-value">${formatSize(totalSize)}</span>
      </div>
    `;
  }
}

// Drag and drop
function setupDropZone(dropZone, input, onFiles) {
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();
    });
  });
  
  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => {
      dropZone.classList.add('drag-over');
    });
  });
  
  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => {
      dropZone.classList.remove('drag-over');
    });
  });
  
  dropZone.addEventListener('drop', e => {
    const files = [...e.dataTransfer.files];
    if (files.length) onFiles(files);
  });
  
  dropZone.addEventListener('click', () => input.click());
  
  input.addEventListener('change', () => {
    const files = [...input.files];
    if (files.length) onFiles(files);
    input.value = '';
  });
}

setupDropZone(compressDropZone, compressInput, files => {
  if (currentMode === 'decompress') {
    if (!confirm('Переключиться в режим сжатия? Текущий прогресс будет сброшен.')) return;
  }
  switchMode('compress');
  compressFiles.push(...files.map(file => ({ file, selected: true })));
  updateCompressFileList();
  downloadCompressedButton.hidden = true;
  downloadCompressedButton.disabled = true;
  compressedResult = null;
});

setupDropZone(decompressDropZone, decompressInput, files => {
  if (currentMode === 'compress') {
    if (!confirm('Переключиться в режим распаковки? Текущий прогресс будет сброшен.')) return;
  }
  switchMode('decompress');
  decompressArchives.push(...files.map(file => ({ file, selected: true })));
  updateDecompressFileList();
  downloadDecompressedButton.hidden = true;
  downloadDecompressedButton.disabled = true;
  decompressedResult = null;
});

// Compress
compressButton.addEventListener('click', async () => {
  const selected = compressFiles.filter(f => f.selected);
  if (selected.length === 0) return;
  
  compressButton.disabled = true;
  downloadCompressedButton.hidden = true;
  compressProgress.textContent = 'Сжатие...';
  compressStats.innerHTML = '';
  
  const startTime = performance.now();
  const results = [];
  
  try {
    for (let i = 0; i < selected.length; i++) {
      const { file } = selected[i];
      if (file.size > CHUNK_SIZE) {
        const count = Math.ceil(file.size / CHUNK_SIZE);
        let completed = 0;
        const chunks = await mapWithConcurrency(count, CHUNK_CONCURRENCY, async chunkIndex => {
          compressProgress.textContent = `Сжатие ${i + 1}/${selected.length}\n${file.name}: блоки ${completed}/${count}`;
          const start = chunkIndex * CHUNK_SIZE;
          const bytes = await file.slice(start, Math.min(start + CHUNK_SIZE, file.size)).arrayBuffer();
          const archiveChunk = await postBinary('/v1/compress', bytes, `Ошибка сжатия блока ${chunkIndex + 1}`);
          completed++;
          compressProgress.textContent = `Сжатие ${i + 1}/${selected.length}\n${file.name}: блоки ${completed}/${count}`;
          return archiveChunk;
        });
        const archive = createChunkedArchive(file.name, file.size, chunks);
        results.push({ name: file.name, archiveName: `${file.name}.sabl`, original: file.size, compressed: archive.byteLength, data: archive });
      } else {
        compressProgress.textContent = `Сжатие файла ${i + 1} из ${selected.length}...\n${file.name}`;
        const data = await file.arrayBuffer();
        const compressed = await postBinary('/v1/compress', data, 'Ошибка сжатия');
        results.push({ name: file.name, original: data.byteLength, compressed: compressed.byteLength, data: compressed });
      }
    }
    
    const totalOriginal = results.reduce((sum, r) => sum + r.original, 0);
    const totalCompressed = results.reduce((sum, r) => sum + r.compressed, 0);
    const ratio = totalOriginal > 0 ? (totalOriginal / totalCompressed).toFixed(2) : '1.00';
    const percent = totalOriginal > 0 ? ((totalCompressed / totalOriginal) * 100).toFixed(1) : '100.0';
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
    
    // Create SARB if multiple files
    if (results.length === 1) {
      compressedResult = { blob: new Blob([results[0].data]), name: results[0].archiveName || `${results[0].name}.sarc` };
    } else {
      const sarb = createSARB(results);
      compressedResult = { blob: new Blob([sarb]), name: 'compressed-files.sarb' };
    }
    
    compressProgress.textContent = `✓ Сжатие завершено за ${elapsed} с`;
    compressStats.innerHTML = `
      <div class="stat-row">
        <span class="stat-label">Файлов обработано:</span>
        <span class="stat-value">${results.length}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Исходный размер:</span>
        <span class="stat-value">${formatSize(totalOriginal)}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Размер архива:</span>
        <span class="stat-value highlight">${formatSize(totalCompressed)}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Коэффициент:</span>
        <span class="stat-value highlight">${ratio}×</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Процент сжатия:</span>
        <span class="stat-value">${percent}%</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Время обработки:</span>
        <span class="stat-value">${elapsed} с</span>
      </div>
    `;
    
    downloadCompressedButton.hidden = false;
    downloadCompressedButton.disabled = false;
  } catch (err) {
    compressProgress.textContent = `✗ Ошибка: ${err.message}`;
    compressStats.innerHTML = '';
  } finally {
    compressButton.disabled = false;
  }
});

downloadCompressedButton.addEventListener('click', () => {
  if (!compressedResult) return;
  const url = URL.createObjectURL(compressedResult.blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = compressedResult.name;
  a.click();
  URL.revokeObjectURL(url);
});

async function postBinary(path, body, label) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body
  });
  if (response.ok) return response.arrayBuffer();
  const contentType = response.headers.get('content-type') || '';
  let detail = '';
  if (contentType.includes('application/json')) {
    const payload = await response.json().catch(() => null);
    detail = payload?.error?.message || payload?.message || '';
  } else {
    detail = (await response.text().catch(() => '')).trim().slice(0, 240);
  }
  throw new Error(`${label} (HTTP ${response.status})${detail ? `: ${detail}` : ''}`);
}

async function mapWithConcurrency(count, concurrency, mapper) {
  const results = new Array(count);
  let nextIndex = 0;
  async function worker() {
    while (true) {
      const index = nextIndex++;
      if (index >= count) return;
      results[index] = await mapper(index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(count, concurrency) }, () => worker()));
  return results;
}

function createChunkedArchive(name, originalSize, chunks) {
  const nameBytes = new TextEncoder().encode(name);
  if (nameBytes.length > 65535) throw new Error('Слишком длинное имя файла');
  const tableSize = 20 + nameBytes.length + chunks.length * 4;
  const totalSize = tableSize + chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const output = new Uint8Array(totalSize);
  const view = new DataView(output.buffer);
  output.set([0x53, 0x41, 0x42, 0x4c, 1, 0], 0); // SABL v1
  view.setUint16(6, nameBytes.length, true);
  view.setUint32(8, chunks.length, true);
  view.setBigUint64(12, BigInt(originalSize), true);
  output.set(nameBytes, 20);
  let tablePosition = 20 + nameBytes.length;
  let payloadPosition = tableSize;
  for (const chunk of chunks) {
    view.setUint32(tablePosition, chunk.byteLength, true);
    tablePosition += 4;
    output.set(new Uint8Array(chunk), payloadPosition);
    payloadPosition += chunk.byteLength;
  }
  return output.buffer;
}

function isChunkedArchive(buffer) {
  if (buffer.byteLength < 4) return false;
  const bytes = new Uint8Array(buffer, 0, 4);
  return bytes[0] === 0x53 && bytes[1] === 0x41 && bytes[2] === 0x42 && bytes[3] === 0x4c;
}

async function decompressChunkedArchive(buffer, fallbackName, onProgress = () => {}) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 20 || bytes[4] !== 1 || bytes[5] !== 0) throw new Error('Повреждённый блочный архив');
  const view = new DataView(buffer);
  const nameLength = view.getUint16(6, true);
  const chunkCount = view.getUint32(8, true);
  const originalSizeBig = view.getBigUint64(12, true);
  if (originalSizeBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Исходный файл слишком велик');
  const originalSize = Number(originalSizeBig);
  let position = 20 + nameLength;
  if (position > bytes.length || chunkCount > Math.floor((bytes.length - position) / 4)) throw new Error('Повреждена таблица блоков');
  const sizes = [];
  let payloadPosition = position + chunkCount * 4;
  for (let i = 0; i < chunkCount; i++) {
    const size = view.getUint32(position, true);
    position += 4;
    sizes.push(size);
  }
  if (sizes.reduce((sum, size) => sum + size, payloadPosition) !== bytes.length) throw new Error('Размер блочного архива не совпадает');
  const output = new Uint8Array(originalSize);
  let outputPosition = 0;
  const name = new TextDecoder().decode(bytes.subarray(20, 20 + nameLength));
  const chunkOffsets = [];
  for (const size of sizes) {
    chunkOffsets.push(payloadPosition);
    payloadPosition += size;
  }
  let completed = 0;
  const decodedChunks = await mapWithConcurrency(chunkCount, CHUNK_CONCURRENCY, async i => {
    onProgress(`${completed}/${chunkCount}`);
    const chunkArchive = bytes.slice(chunkOffsets[i], chunkOffsets[i] + sizes[i]);
    const decoded = new Uint8Array(await postBinary('/v1/decompress', chunkArchive, `Ошибка распаковки блока ${i + 1}`));
    completed++;
    onProgress(`${completed}/${chunkCount}`);
    return decoded;
  });
  for (const chunk of decodedChunks) {
    if (outputPosition + chunk.length > output.length) throw new Error('Блоки превышают исходный размер');
    output.set(chunk, outputPosition);
    outputPosition += chunk.length;
  }
  if (outputPosition !== output.length) throw new Error('Восстановленный размер файла не совпадает');
  return { name: name || fallbackName.replace(/\.(sarc|sarb)$/i, ''), compressed: bytes.length, decompressed: output.length, data: output.buffer };
}

// Decompress
decompressButton.addEventListener('click', async () => {
  const selected = decompressArchives.filter(f => f.selected);
  if (selected.length === 0) return;
  
  decompressButton.disabled = true;
  downloadDecompressedButton.hidden = true;
  decompressProgress.textContent = 'Распаковка...';
  decompressStats.innerHTML = '';
  
  const startTime = performance.now();
  const results = [];
  
  try {
    for (let i = 0; i < selected.length; i++) {
      const { file } = selected[i];
      decompressProgress.textContent = `Распаковка архива ${i + 1} из ${selected.length}...\n${file.name}`;
      
      const data = await file.arrayBuffer();
      
      // Check if SARB
      if (isChunkedArchive(data)) {
        results.push(await decompressChunkedArchive(data, file.name, progress => {
          decompressProgress.textContent = `Распаковка архива ${i + 1}/${selected.length}\n${file.name}: блок ${progress}`;
        }));
      } else if (isSARB(data)) {
        const entries = parseSARB(data);
        for (const entry of entries) {
          if (isChunkedArchive(entry.data)) {
            results.push(await decompressChunkedArchive(entry.data, entry.name, progress => {
              decompressProgress.textContent = `Распаковка ${entry.name}: блок ${progress}`;
            }));
          } else {
            const decompressed = await postBinary('/v1/decompress', entry.data, 'Ошибка распаковки');
            results.push({ name: entry.name.replace(/\.sarc$/i, ''), compressed: entry.data.byteLength, decompressed: decompressed.byteLength, data: decompressed });
          }
        }
      } else {
        const decompressed = await postBinary('/v1/decompress', data, 'Ошибка распаковки');
        const name = file.name.replace(/\.(sarc|sarb)$/i, '');
        results.push({ name, compressed: data.byteLength, decompressed: decompressed.byteLength, data: decompressed });
      }
    }
    
    const totalCompressed = results.reduce((sum, r) => sum + r.compressed, 0);
    const totalDecompressed = results.reduce((sum, r) => sum + r.decompressed, 0);
    const ratio = totalCompressed > 0 ? (totalDecompressed / totalCompressed).toFixed(2) : '1.00';
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
    
    decompressedResult = results;
    
    decompressProgress.textContent = `✓ Распаковка завершена за ${elapsed} с`;
    decompressStats.innerHTML = `
      <div class="stat-row">
        <span class="stat-label">Файлов восстановлено:</span>
        <span class="stat-value">${results.length}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Размер архивов:</span>
        <span class="stat-value">${formatSize(totalCompressed)}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Восстановлено:</span>
        <span class="stat-value highlight">${formatSize(totalDecompressed)}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Коэффициент:</span>
        <span class="stat-value highlight">${ratio}×</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Время обработки:</span>
        <span class="stat-value">${elapsed} с</span>
      </div>
    `;
    
    downloadDecompressedButton.hidden = false;
    downloadDecompressedButton.disabled = false;
  } catch (err) {
    decompressProgress.textContent = `✗ Ошибка: ${err.message}`;
    decompressStats.innerHTML = '';
  } finally {
    decompressButton.disabled = false;
  }
});

downloadDecompressedButton.addEventListener('click', async () => {
  if (!decompressedResult || decompressedResult.length === 0) return;
  
  const JSZip = await import('https://cdn.jsdelivr.net/npm/jszip@3.10.1/+esm');
  const zip = new JSZip.default();
  const folder = zip.folder('restored-files');
  
  decompressedResult.forEach(entry => {
    folder.file(entry.name, entry.data);
  });
  
  const blob = await zip.generateAsync({ type: 'blob' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'restored-files.zip';
  a.click();
  URL.revokeObjectURL(url);
});

// SARB format helpers
function createSARB(entries) {
  const signature = new TextEncoder().encode('SARB');
  const version = new Uint8Array([1]);
  const count = new Uint32Array([entries.length]);
  
  const parts = [signature, version, new Uint8Array(count.buffer)];
  
  entries.forEach(entry => {
    const nameBytes = new TextEncoder().encode(entry.name);
    const nameLen = new Uint32Array([nameBytes.length]);
    const dataLen = new Uint32Array([entry.data.byteLength]);
    
    parts.push(new Uint8Array(nameLen.buffer));
    parts.push(nameBytes);
    parts.push(new Uint8Array(dataLen.buffer));
    parts.push(new Uint8Array(entry.data));
  });
  
  const totalLength = parts.reduce((sum, p) => sum + p.byteLength, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  
  parts.forEach(part => {
    result.set(part, offset);
    offset += part.byteLength;
  });
  
  return result.buffer;
}

function isSARB(buffer) {
  if (buffer.byteLength < 4) return false;
  const view = new Uint8Array(buffer, 0, 4);
  const sig = new TextDecoder().decode(view);
  return sig === 'SARB';
}

function parseSARB(buffer) {
  const view = new DataView(buffer);
  let offset = 0;
  
  const sig = new TextDecoder().decode(new Uint8Array(buffer, offset, 4));
  offset += 4;
  if (sig !== 'SARB') throw new Error('Неверная сигнатура SARB');
  
  const version = view.getUint8(offset);
  offset += 1;
  if (version !== 1) throw new Error(`Неизвестная версия SARB: ${version}`);
  
  const count = view.getUint32(offset, true);
  offset += 4;
  
  const entries = [];
  
  for (let i = 0; i < count; i++) {
    const nameLen = view.getUint32(offset, true);
    offset += 4;
    
    const nameBytes = new Uint8Array(buffer, offset, nameLen);
    const name = new TextDecoder().decode(nameBytes);
    offset += nameLen;
    
    const dataLen = view.getUint32(offset, true);
    offset += 4;
    
    const data = buffer.slice(offset, offset + dataLen);
    offset += dataLen;
    
    entries.push({ name, data });
  }
  
  return entries;
}
