import { ArchiveError, compress, decompress, MAX_ORIGINAL_SIZE } from '../src/codec.js';

const MAX_ARCHIVE_SIZE = MAX_ORIGINAL_SIZE + 4 * 1024 * 1024;

export function sendJson(res, status, value) {
  const body = JSON.stringify(value);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Compression-Profile');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Private-Network', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.end(body);
}

export function sendBytes(res, body) {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', body.length);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Compression-Profile');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Private-Network', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.end(body);
}

export function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) {
        reject(new ArchiveError('input_too_large', 'Тело запроса превышает допустимый размер', 413));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks, size)));
    req.on('error', reject);
  });
}

export async function handleCodec(req, res, operation) {
  try {
    if (req.method === 'OPTIONS') {
      sendJson(res, 204, {});
      return;
    }
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: { code: 'method_not_allowed', message: 'Требуется POST-запрос' } });
      return;
    }
    const body = await readBody(req, operation === 'compress' ? MAX_ORIGINAL_SIZE : MAX_ARCHIVE_SIZE);
    const fast = req.headers['x-compression-profile'] === 'fast';
    sendBytes(res, operation === 'compress' ? compress(body, { fast }) : decompress(body));
  } catch (error) {
    if (error instanceof ArchiveError) {
      sendJson(res, error.status, { error: { code: error.code, message: error.message } });
    } else {
      console.error(error);
      sendJson(res, 500, { error: { code: 'internal_error', message: 'Внутренняя ошибка сервиса' } });
    }
  }
}
