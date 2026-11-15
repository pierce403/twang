import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

export async function buildPwa(dist) {
  const files = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(file);
      else if (entry.isFile()) {
        const relative = path.relative(dist, file).split(path.sep).join('/');
        const rootAsset = ['index.html', 'styles.css', 'favicon.svg', 'manifest.webmanifest'].includes(relative);
        const bundledAsset = /^(?:app|vendor|icons|fonts)\/.+\.(?:m?js|css|wasm|png|svg|webp|jpe?g|woff2?)$/i.test(relative);
        const publicRoot = ['certs/signal.pem', 'certs/signal-ed25519.pem'].includes(relative);
        if (rootAsset || bundledAsset || publicRoot) files.push(relative);
      }
    }
  }
  await walk(dist);
  files.sort();
  const template = await readFile(path.join(dist, 'sw.js'), 'utf8');
  if (!template.includes('__TWANG_BUILD_ID__') || !template.includes('__TWANG_PRECACHE__'))
    throw new Error('Service worker build template is missing');
  const hash = createHash('sha256').update(template);
  for (const file of files) hash.update(file).update('\0').update(await readFile(path.join(dist, file)));
  const version = hash.digest('hex').slice(0, 20);
  const source = template.replace('__TWANG_BUILD_ID__', JSON.stringify(version))
    .replace('__TWANG_PRECACHE__', JSON.stringify(files.map(file => `/${file}`)));
  await writeFile(path.join(dist, 'sw.js'), source);
  return { version, files };
}
