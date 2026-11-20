import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compress, decompress, ArchiveError, MAX_ORIGINAL_SIZE } from './codec.js';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'public');
const PORT = Number(process.env.PORT || 3000);
const MAX_ARCHIVE_SIZE = MAX_ORIGINAL_SIZE + 4 * 1024 * 1024;

function sendJson(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Private-Network': 'true',
    'Access-Control-Max-Age': '86400'
  });
  response.end(body);
}

function sendBytes(response, body, contentType = 'application/octet-stream') {
  response.writeHead(200, {
    'Content-Type': contentType,
    'Content-Length': body.length,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Private-Network': 'true',
    'Access-Control-Max-Age': '86400'
  });
  response.end(body);
}

function readBody(request, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new ArchiveError('input_too_large', 'Тело запроса превышает допустимый размер', 413));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks, size)));
    request.on('error', reject);
  });
}

async function serveStatic(request, response) {
  const requested = request.url === '/' ? '/index.html' : request.url;
  const pathname = requested.split('?')[0];
  const safePath = pathname.replaceAll('..', '').replace(/^\//, '');
  const file = join(root, safePath);
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
  try {
    const body = await readFile(file);
    sendBytes(response, body, types[extname(file)] || 'application/octet-stream');
  } catch {
    sendJson(response, 404, { error: { code: 'not_found', message: 'Страница не найдена' } });
  }
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === 'OPTIONS') {
      response.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Allow-Private-Network': 'true',
        'Access-Control-Max-Age': '86400'
      });
      response.end();
      return;
    }
    if (request.method === 'GET' && request.url === '/v1/health') {
      sendJson(response, 200, { status: 'ok' });
      return;
    }
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (request.method === 'POST' && (pathname === '/v1/compress' || pathname === '/v1/decompress')) {
      const body = await readBody(request, pathname === '/v1/compress' ? MAX_ORIGINAL_SIZE : MAX_ARCHIVE_SIZE);
      const result = pathname === '/v1/compress' ? compress(body) : decompress(body);
      sendBytes(response, result);
      return;
    }
    if (request.method === 'GET') {
      await serveStatic(request, response);
      return;
    }
    sendJson(response, 404, { error: { code: 'not_found', message: 'Маршрут не найден' } });
  } catch (error) {
    if (error instanceof ArchiveError) {
      sendJson(response, error.status, { error: { code: error.code, message: error.message } });
    } else {
      console.error(error);
      sendJson(response, 500, { error: { code: 'internal_error', message: 'Внутренняя ошибка сервиса' } });
    }
  }
});

server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Порт ${PORT} уже занят. Остановите предыдущий сервер или запустите: PORT=другой_порт npm start`);
  } else {
    console.error('Не удалось запустить HTTP-сервис:', error.message);
  }
  process.exitCode = 1;
});

server.listen(PORT, () => console.log(`Own Archiver: http://localhost:${PORT}`));
