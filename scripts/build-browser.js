import { build } from 'esbuild';
import { resolve } from 'node:path';
import { cp, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export async function buildBrowser(outfile = 'public/codec-worker.bundle.js') {
  await build({
    entryPoints: ['src/browser/worker.js'],
    outfile,
    bundle: true,
    platform: 'browser',
    format: 'iife',
    target: ['chrome100', 'firefox100', 'safari15'],
    minify: true,
    inject: [resolve('src/browser/globals.js')],
    plugins: [{
      name: 'browser-checksum',
      setup(builder) {
        builder.onResolve({ filter: /^node:crypto$/ }, () => ({ path: resolve('src/browser/crypto.js') }));
      }
    }]
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--dist')) {
    await mkdir('dist', { recursive: true });
    await cp('public', 'dist', { recursive: true });
    await buildBrowser('dist/codec-worker.bundle.js');
  } else {
    await buildBrowser();
  }
}
