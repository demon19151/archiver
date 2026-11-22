import { runCodec } from './codec-client.js';

// DOM elements
const fileInput = document.getElementById('fileInput');
const dropZone = document.getElementById('dropZone');
const emptyState = document.getElementById('emptyState');
const fileSection = document.getElementById('fileSection');
const fileList = document.getElementById('fileList');
const fileCount = document.getElementById('fileCount');
const totalSize = document.getElementById('totalSize');
const selectAllButton = document.getElementById('selectAllButton');
const addFilesButton = document.getElementById('addFilesButton');
const clearButton = document.getElementById('clearButton');

const compressMode = document.getElementById('compressMode');
const decompressMode = document.getElementById('decompressMode');

const idleState = document.getElementById('idleState');
const readyState = document.getElementById('readyState');
const processingState = document.getElementById('processingState');
const successState = document.getElementById('successState');
const errorState = document.getElementById('errorState');

const readyFileCount = document.getElementById('readyFileCount');
const readyTotalSize = document.getElementById('readyTotalSize');
const startButton = document.getElementById('startButton');
const startButtonText = document.getElementById('startButtonText');

const processingText = document.getElementById('processingText');
const processingProgress = document.getElementById('processingProgress');
const processingProgressBar = document.getElementById('processingProgressBar');
const progressTrack = processingProgressBar.parentElement;

const resultStats = document.getElementById('resultStats');
const downloadButton = document.getElementById('downloadButton');
const downloadButtonText = document.getElementById('downloadButtonText');
const resetButton = document.getElementById('resetButton');

const errorMessage = document.getElementById('errorMessage');
const retryButton = document.getElementById('retryButton');
const themeToggle = document.getElementById('themeToggle');
const languageSelect = document.getElementById('languageSelect');
const leftTitle = document.getElementById('leftTitle');
const leftSubtitle = document.getElementById('leftSubtitle');
const dropText = document.getElementById('dropText');
const formatBadgeText = document.querySelector('#formatBadge [data-i18n]');
const themeSun = themeToggle.querySelector('.theme-sun');
const themeMoon = themeToggle.querySelector('.theme-moon');
const modeSwitcher = document.querySelector('.mode-switcher');

// State
let currentMode = 'compress';
let files = [];
let result = null;
let currentLanguage = localStorage.getItem('archiver-language') || 'ru';

const translations = {
  ru: {
    brandName: 'Архиватор Онлайн',
    brandTagline: 'Сжатие и распаковка файлов в браузере',
    navHome: 'Главная',
    navFeatures: 'Возможности',
    navFormats: 'Форматы',
    navAbout: 'О сервисе',
    mainNavLabel: 'Основная навигация',
    operationLabel: 'Операция',
    modeLabel: 'Режим работы',
    benefitsLabel: 'Преимущества',
    languageLabel: 'Язык',
    themeDark: 'Включить светлую тему',
    themeLight: 'Включить тёмную тему',
    compressTitle: 'Сжатие файлов',
    compressSubtitle: 'Объедините файлы в архив и уменьшите их размер',
    decompressTitle: 'Распаковка архива',
    decompressSubtitle: 'Извлеките файлы из архива в удобном виде',
    dropCompress: 'Перетащите файлы сюда',
    dropDecompress: 'Перетащите архив сюда',
    dropHint: 'или нажмите для выбора',
    allFiles: 'Поддерживаются любые файлы',
    archiveFormats: 'Поддерживаются архивы SARC и SARB',
    emptyFiles: 'Файлы не выбраны',
    selectAll: 'Выбрать все',
    addFiles: 'Добавить ещё',
    clear: 'Очистить',
    switchModeConfirm: 'Смена режима очистит выбранные файлы. Продолжить?',
    privacy: 'Файлы обрабатываются локально в браузере',
    compressMode: 'Сжатие',
    decompressMode: 'Распаковка',
    idle: 'Выберите файлы для начала работы',
    readyKicker: 'Готово к запуску',
    selectedFiles: 'Файлов выбрано:',
    totalSize: 'Общий размер:',
    compressFiles: 'Сжать файлы',
    decompressFile: 'Распаковать архив',
    processingCompress: 'Сжатие файлов...',
    processingDecompress: 'Распаковка архивов...',
    done: 'Готово!',
    downloadArchive: 'Скачать архив',
    downloadFiles: 'Скачать файлы (.zip)',
    processOther: 'Обработать другие файлы',
    errorTitle: 'Ошибка',
    retry: 'Попробовать снова',
    fastTitle: 'Быстро',
    fastText: 'Обработка в отдельном Worker',
    safeTitle: 'Безопасно',
    safeText: 'Файлы не покидают браузер',
    losslessTitle: 'Без потери данных',
    losslessText: 'Байты восстанавливаются точно',
    formatsNote: 'Поддерживаются собственные архивы SARC и пакетный формат SARB.',
    processedFiles: 'Файлов обработано:',
    beforeSize: 'Размер до сжатия:',
    archiveSize: 'Размер архива:',
    savings: 'Экономия:',
    processingTime: 'Время обработки:',
    processed: 'Обработано',
    extracted: 'Распаковано',
    archivesProcessed: 'Архивов распаковано:',
    restoredFiles: 'Файлов восстановлено:',
    archivesSize: 'Размер архивов:',
    restoredSize: 'Восстановленный размер:'
  },
  en: {
    brandName: 'Online Archiver',
    brandTagline: 'Compress and extract files in your browser',
    navHome: 'Home',
    navFeatures: 'Features',
    navFormats: 'Formats',
    navAbout: 'About',
    mainNavLabel: 'Main navigation',
    operationLabel: 'Operation',
    modeLabel: 'Working mode',
    benefitsLabel: 'Benefits',
    languageLabel: 'Language',
    themeDark: 'Switch to light theme',
    themeLight: 'Switch to dark theme',
    compressTitle: 'Compress files',
    compressSubtitle: 'Combine files into an archive and reduce their size',
    decompressTitle: 'Extract archive',
    decompressSubtitle: 'Restore files from an archive',
    dropCompress: 'Drop files here',
    dropDecompress: 'Drop an archive here',
    dropHint: 'or click to browse',
    allFiles: 'All file types are supported',
    archiveFormats: 'SARC and SARB archives are supported',
    emptyFiles: 'No files selected',
    selectAll: 'Select all',
    addFiles: 'Add more',
    clear: 'Clear',
    switchModeConfirm: 'Switching mode will clear the selected files. Continue?',
    privacy: 'Files are processed locally in your browser',
    compressMode: 'Compress',
    decompressMode: 'Extract',
    idle: 'Select files to get started',
    readyKicker: 'Ready to start',
    selectedFiles: 'Files selected:',
    totalSize: 'Total size:',
    compressFiles: 'Compress files',
    decompressFile: 'Extract archive',
    processingCompress: 'Compressing files...',
    processingDecompress: 'Extracting archives...',
    done: 'Done!',
    downloadArchive: 'Download archive',
    downloadFiles: 'Download files (.zip)',
    processOther: 'Process other files',
    errorTitle: 'Error',
    retry: 'Try again',
    fastTitle: 'Fast',
    fastText: 'Processed in a separate Worker',
    safeTitle: 'Private',
    safeText: 'Files never leave your browser',
    losslessTitle: 'Lossless',
    losslessText: 'Every byte is restored exactly',
    formatsNote: 'Supports SARC archives and the SARB batch format.',
    processedFiles: 'Files processed:',
    beforeSize: 'Original size:',
    archiveSize: 'Archive size:',
    savings: 'Saved:',
    processingTime: 'Processing time:',
    processed: 'Processed',
    extracted: 'Extracted',
    archivesProcessed: 'Archives extracted:',
    restoredFiles: 'Files restored:',
    archivesSize: 'Archive size:',
    restoredSize: 'Restored size:'
  }
};

function tr(key) {
  return translations[currentLanguage][key] || translations.ru[key] || key;
}

function applyLanguage(language) {
  const activeState = [idleState, readyState, processingState, successState, errorState]
    .find(state => !state.hidden);
  currentLanguage = language === 'en' ? 'en' : 'ru';
  localStorage.setItem('archiver-language', currentLanguage);
  document.documentElement.lang = currentLanguage;
  languageSelect.value = currentLanguage;
  document.querySelectorAll('[data-i18n]').forEach(element => {
    element.textContent = tr(element.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-aria]').forEach(element => {
    element.setAttribute('aria-label', tr(element.dataset.i18nAria));
  });
  updateThemeButton();
  updateModeCopy();
  updateFileList();
  if (activeState) showState(activeState);
  if (!successState.hidden) renderResultStats();
}

function applyTheme(theme) {
  const selectedTheme = theme === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = selectedTheme;
  localStorage.setItem('archiver-theme', selectedTheme);
  updateThemeButton();
}

function updateThemeButton() {
  const isLight = document.documentElement.dataset.theme === 'light';
  themeSun.hidden = isLight;
  themeMoon.hidden = !isLight;
  const label = isLight ? tr('themeLight') : tr('themeDark');
  themeToggle.setAttribute('aria-label', label);
  themeToggle.title = label;
}

function updateModeCopy() {
  const isCompress = currentMode === 'compress';
  leftTitle.textContent = tr(isCompress ? 'compressTitle' : 'decompressTitle');
  leftSubtitle.textContent = tr(isCompress ? 'compressSubtitle' : 'decompressSubtitle');
  dropText.textContent = tr(isCompress ? 'dropCompress' : 'dropDecompress');
  formatBadgeText.textContent = tr(isCompress ? 'allFiles' : 'archiveFormats');
  startButtonText.textContent = tr(isCompress ? 'compressFiles' : 'decompressFile');
  downloadButtonText.textContent = tr(isCompress ? 'downloadArchive' : 'downloadFiles');
  processingText.textContent = tr(isCompress ? 'processingCompress' : 'processingDecompress');
  compressMode.setAttribute('aria-selected', String(isCompress));
  decompressMode.setAttribute('aria-selected', String(!isCompress));
}

function renderResultStats() {
  if (!result) return;
  if (result.type === 'compress') {
    const ratio = result.originalSize > 0 ? result.originalSize / result.archiveSize : 1;
    const savings = result.originalSize > 0
      ? Math.round(((result.originalSize - result.archiveSize) / result.originalSize) * 100)
      : 0;
    resultStats.innerHTML = `
      <div class="stat-row"><span class="stat-label">${tr('processedFiles')}</span><span class="stat-value">${result.files.length}</span></div>
      <div class="stat-row"><span class="stat-label">${tr('beforeSize')}</span><span class="stat-value">${formatSize(result.originalSize)}</span></div>
      <div class="stat-row"><span class="stat-label">${tr('archiveSize')}</span><span class="stat-value">${formatSize(result.archiveSize)}</span></div>
      <div class="stat-row"><span class="stat-label">${tr('savings')}</span><span class="stat-value highlight">${savings}% (${ratio.toFixed(2)}×)</span></div>
      <div class="stat-row"><span class="stat-label">${tr('processingTime')}</span><span class="stat-value">${(result.elapsed / 1000).toFixed(2)} s</span></div>
    `;
  } else {
    resultStats.innerHTML = `
      <div class="stat-row"><span class="stat-label">${tr('archivesProcessed')}</span><span class="stat-value">${result.archiveCount}</span></div>
      <div class="stat-row"><span class="stat-label">${tr('restoredFiles')}</span><span class="stat-value highlight">${result.files.length}</span></div>
      <div class="stat-row"><span class="stat-label">${tr('archivesSize')}</span><span class="stat-value">${formatSize(result.compressedInputSize)}</span></div>
      <div class="stat-row"><span class="stat-label">${tr('restoredSize')}</span><span class="stat-value">${formatSize(result.totalRestored)}</span></div>
      <div class="stat-row"><span class="stat-label">${tr('processingTime')}</span><span class="stat-value">${(result.elapsed / 1000).toFixed(2)} s</span></div>
    `;
  }
}

// Helpers
function formatSize(bytes) {
  if (bytes === 0) return '0 Б';
  const units = currentLanguage === 'en' ? ['B', 'KB', 'MB', 'GB'] : ['Б', 'КБ', 'МБ', 'ГБ'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function formatFileCount(count) {
  if (currentLanguage === 'en') return `${count} ${count === 1 ? 'file' : 'files'}`;
  const lastTwo = count % 100;
  const last = count % 10;
  const noun = lastTwo >= 11 && lastTwo <= 14 ? 'файлов'
    : last === 1 ? 'файл'
      : last >= 2 && last <= 4 ? 'файла' : 'файлов';
  return `${count} ${noun}`;
}

function showState(state) {
  [idleState, readyState, processingState, successState, errorState].forEach(s => s.hidden = true);
  state.hidden = false;
}

function switchMode(mode) {
  if (!processingState.hidden) return;
  if (files.length > 0 && !window.confirm(tr('switchModeConfirm'))) return;
  currentMode = mode;
  modeSwitcher.dataset.mode = mode;
  compressMode.classList.toggle('active', mode === 'compress');
  decompressMode.classList.toggle('active', mode === 'decompress');

  fileInput.accept = mode === 'compress' ? '' : '.sarc,.sarb';
  updateModeCopy();
  startButton.querySelector('svg path').setAttribute('d',
    mode === 'compress'
      ? 'M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12'
      : 'M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3'
  );

  resetFiles();
}

function resetFiles() {
  files = [];
  result = null;
  updateFileList();
  showState(idleState);
}

function updateFileList() {
  if (files.length === 0) {
    emptyState.hidden = false;
    fileSection.hidden = true;
    showState(idleState);
    return;
  }

  emptyState.hidden = true;
  fileSection.hidden = false;

  const total = files.reduce((sum, f) => sum + f.file.size, 0);

  fileCount.textContent = formatFileCount(files.length);
  totalSize.textContent = formatSize(total);

  fileList.innerHTML = '';
  files.forEach((fileData, index) => {
    const item = document.createElement('div');
    item.className = 'file-item';

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = fileData.selected;
    checkbox.addEventListener('change', () => {
      files[index].selected = checkbox.checked;
      updateReadyState();
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
      files.splice(index, 1);
      updateFileList();
    });

    item.append(checkbox, info, removeBtn);
    fileList.append(item);
  });

  updateReadyState();
}

function updateReadyState() {
  const selected = files.filter(f => f.selected);
  const selectedTotal = selected.reduce((sum, f) => sum + f.file.size, 0);

  readyFileCount.textContent = formatFileCount(selected.length);
  readyTotalSize.textContent = formatSize(selectedTotal);
  startButton.disabled = selected.length === 0;

  if (selected.length > 0) {
    showState(readyState);
  } else if (files.length > 0) {
    showState(readyState);
  }
}

function updateProgress(percent, total, processed, label) {
  const safePercent = Math.max(0, Math.min(100, percent));
  processingProgressBar.style.width = `${safePercent}%`;
  progressTrack.setAttribute('aria-valuenow', String(safePercent));
  const progressLabel = label || tr('processed');
  processingProgress.textContent = total
    ? currentLanguage === 'en'
      ? `${progressLabel} ${processed || 0} of ${total} (${safePercent}%)`
      : `${progressLabel} ${processed || 0} из ${total} (${safePercent}%)`
    : currentLanguage === 'en' ? 'Preparing…' : 'Подготовка…';
}

// Drag and drop
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
  const droppedFiles = Array.from(e.dataTransfer.files);
  addFiles(droppedFiles);
});

dropZone.addEventListener('click', () => {
  fileInput.click();
});

fileInput.addEventListener('change', () => {
  if (fileInput.files.length > 0) {
    addFiles(Array.from(fileInput.files));
    fileInput.value = '';
  }
});

function addFiles(newFiles) {
  const accepted = currentMode === 'compress'
    ? newFiles
    : newFiles.filter(f => f.name.match(/\.(sarc|sarb)$/i));

  files.push(...accepted.map(file => ({ file, selected: true })));
  updateFileList();
}

selectAllButton.addEventListener('click', () => {
  const allSelected = files.every(f => f.selected);
  files.forEach(f => f.selected = !allSelected);
  updateFileList();
});

addFilesButton.addEventListener('click', () => fileInput.click());

clearButton.addEventListener('click', () => {
  resetFiles();
});

compressMode.addEventListener('click', () => {
  if (currentMode !== 'compress') {
    switchMode('compress');
  }
});

decompressMode.addEventListener('click', () => {
  if (currentMode !== 'decompress') {
    switchMode('decompress');
  }
});

async function runSelectedOperation() {
  const selected = files.filter(f => f.selected);
  if (selected.length === 0) return;

  startButton.disabled = true;
  retryButton.disabled = true;
  compressMode.disabled = true;
  decompressMode.disabled = true;
  clearButton.disabled = true;
  selectAllButton.disabled = true;
  addFilesButton.disabled = true;
  fileList.querySelectorAll('input, button').forEach(control => control.disabled = true);

  showState(processingState);
  processingText.textContent = tr(currentMode === 'compress' ? 'processingCompress' : 'processingDecompress');
  updateProgress(0, selected.length);

  try {
    if (currentMode === 'compress') {
      await compressFiles(selected.map(f => f.file));
    } else {
      await decompressFiles(selected.map(f => f.file));
    }
  } catch (error) {
    showError(error);
  } finally {
    startButton.disabled = files.every(f => !f.selected);
    retryButton.disabled = false;
    compressMode.disabled = false;
    decompressMode.disabled = false;
    clearButton.disabled = false;
    selectAllButton.disabled = false;
    addFilesButton.disabled = false;
    fileList.querySelectorAll('input, button').forEach(control => control.disabled = false);
  }
}

startButton.addEventListener('click', runSelectedOperation);

async function compressFiles(filesToCompress) {
  const startTime = performance.now();
  const totalSize = filesToCompress.reduce((sum, f) => sum + f.size, 0);

  let processed = 0;
  const reportProgress = () => {
    const percent = Math.round((processed / filesToCompress.length) * 100);
    updateProgress(percent, filesToCompress.length, processed, tr('processed'));
  };

  const results = [];
  for (const file of filesToCompress) {
    const buffer = await file.arrayBuffer();
    const compressedResult = await runCodec('compress', buffer);
    results.push({ name: file.name, data: new Uint8Array(compressedResult.buffer), originalSize: file.size });
    processed++;
    reportProgress();
  }

  const encodedSize = results.reduce((sum, r) => sum + r.data.byteLength, 0);
  const archiveBytes = results.length === 1
    ? results[0].data
    : new Uint8Array(createSARB(results));
  const archiveSize = archiveBytes.byteLength;
  const elapsed = performance.now() - startTime;
  const ratio = totalSize > 0 ? totalSize / archiveSize : 1;
  const savings = totalSize > 0 ? Math.round(((totalSize - archiveSize) / totalSize) * 100) : 0;

  result = {
    type: 'compress',
    files: results,
    blob: new Blob([archiveBytes], { type: 'application/octet-stream' }),
    name: results.length === 1 ? `${results[0].name}.sarc` : 'compressed-files.sarb',
    originalSize: totalSize,
    archiveSize,
    encodedSize,
    elapsed
  };

  showState(successState);
  renderResultStats();
}

async function decompressFiles(archives) {
  const startTime = performance.now();

  let processed = 0;
  const reportProgress = () => {
    const percent = Math.round((processed / archives.length) * 100);
    updateProgress(percent, archives.length, processed, tr('extracted'));
  };

  const results = [];
  const compressedInputSize = archives.reduce((sum, archive) => sum + archive.size, 0);
  for (const archive of archives) {
    const buffer = await archive.arrayBuffer();
    const entries = isSARB(buffer)
      ? parseSARB(buffer)
      : [{ name: archive.name.replace(/\.sarc$/i, ''), data: buffer }];

    for (const entry of entries) {
      const restored = await runCodec('decompress', entry.data);
      results.push({ name: entry.name, data: new Uint8Array(restored.buffer) });
    }
    processed++;
    reportProgress();
  }

  const totalRestored = results.reduce((sum, r) => sum + r.data.length, 0);
  const elapsed = performance.now() - startTime;

  result = { type: 'decompress', files: results, archiveCount: archives.length, compressedInputSize, totalRestored, elapsed };

  showState(successState);
  renderResultStats();
}

function showError(error) {
  showState(errorState);
  errorMessage.textContent = error.message || 'Произошла неизвестная ошибка';
}

downloadButton.addEventListener('click', () => {
  if (!result) return;

  if (result.type === 'compress') {
    downloadBlob(result.blob, result.name);
  } else if (result.type === 'decompress') {
    downloadRestoredFiles(result.files);
  }
});

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

async function downloadRestoredFiles(restoredFiles) {
  const { default: JSZip } = await import('https://cdn.jsdelivr.net/npm/jszip@3.10.1/+esm');
  const zip = new JSZip();
  const folder = zip.folder('restored-files');
  restoredFiles.forEach(file => folder.file(file.name, file.data));
  downloadBlob(await zip.generateAsync({ type: 'blob' }), 'restored-files.zip');
}

function createSARB(entries) {
  const encoder = new TextEncoder();
  const encodedEntries = entries.map(entry => ({
    name: encoder.encode(entry.name),
    data: entry.data instanceof Uint8Array ? entry.data : new Uint8Array(entry.data)
  }));
  const totalSize = 9 + encodedEntries.reduce((sum, entry) => sum + 8 + entry.name.length + entry.data.length, 0);
  const output = new Uint8Array(totalSize);
  const view = new DataView(output.buffer);
  output.set(encoder.encode('SARB'), 0);
  output[4] = 1;
  view.setUint32(5, encodedEntries.length, true);
  let offset = 9;
  for (const entry of encodedEntries) {
    view.setUint32(offset, entry.name.length, true);
    offset += 4;
    output.set(entry.name, offset);
    offset += entry.name.length;
    view.setUint32(offset, entry.data.length, true);
    offset += 4;
    output.set(entry.data, offset);
    offset += entry.data.length;
  }
  return output;
}

function isSARB(buffer) {
  if (buffer.byteLength < 4) return false;
  return new TextDecoder().decode(new Uint8Array(buffer, 0, 4)) === 'SARB';
}

function parseSARB(buffer) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  const decoder = new TextDecoder();
  let offset = 4;
  if (view.getUint8(offset++) !== 1) throw new Error('Неподдерживаемая версия архива SARB');
  if (offset + 4 > buffer.byteLength) throw new Error('Повреждённый архив SARB');
  const count = view.getUint32(offset, true);
  offset += 4;
  if (count > 100000) throw new Error('Слишком много файлов в архиве SARB');

  const entries = [];
  for (let i = 0; i < count; i++) {
    if (offset + 4 > buffer.byteLength) throw new Error('Повреждённый список файлов SARB');
    const nameLength = view.getUint32(offset, true);
    offset += 4;
    if (nameLength > buffer.byteLength - offset || offset + nameLength + 4 > buffer.byteLength) {
      throw new Error('Некорректное имя файла в архиве SARB');
    }
    const name = decoder.decode(bytes.subarray(offset, offset + nameLength));
    offset += nameLength;
    const dataLength = view.getUint32(offset, true);
    offset += 4;
    if (dataLength > buffer.byteLength - offset) throw new Error('Обрезаны данные файла в архиве SARB');
    entries.push({ name, data: buffer.slice(offset, offset + dataLength) });
    offset += dataLength;
  }
  if (offset !== buffer.byteLength) throw new Error('В архиве SARB есть лишние данные');
  return entries;
}

resetButton.addEventListener('click', () => {
  resetFiles();
});

retryButton.addEventListener('click', () => {
  runSelectedOperation();
});

themeToggle.addEventListener('click', () => {
  applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
});

languageSelect.addEventListener('change', () => {
  applyLanguage(languageSelect.value);
});

// Initialize
applyTheme(localStorage.getItem('archiver-theme') || 'dark');
applyLanguage(currentLanguage);
switchMode('compress');

document.querySelectorAll('.main-nav .nav-link').forEach(link => {
  link.addEventListener('click', () => {
    document.querySelector('.main-nav .nav-link.active')?.classList.remove('active');
    link.classList.add('active');
  });
});
