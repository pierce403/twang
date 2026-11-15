// Copy the pinned, installed Epoxy browser build into the static application.
// No CDN runtime dependency, no downloads, and no installation scripts are run here.
import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { build } from 'esbuild';

const root = fileURLToPath(new URL('../', import.meta.url));
const packageDir = path.join(root, 'node_modules/@mercuryworkshop/epoxy-tls');
const metadata = JSON.parse(await readFile(path.join(packageDir, 'package.json'), 'utf8'));
if (metadata.version !== '2.1.20-1') throw new Error(`Unexpected Epoxy version ${metadata.version}; expected pinned 2.1.20-1`);
const output = path.join(root, 'public/vendor/epoxy');
await mkdir(output, { recursive: true });
let js = await readFile(path.join(packageDir, 'full/epoxy.js'), 'utf8');
let replacements = 0;
let helper;
// wasm-bindgen embeds a helper ES module as a data URL. Move the exact helper
// bytes to a same-origin file so the UI does not need script-src data:.
js = js.replace(/from (['"])data:text\/javascript;base64,([A-Za-z0-9+/=]+)\1/g, (_all, _quote, encoded) => {
  if (++replacements !== 1) throw new Error('Unexpected multiple Epoxy inline modules');
  helper = Buffer.from(encoded, 'base64');
  return "from './epoxy-utils.mjs'";
});
if (replacements !== 1) throw new Error('Expected one Epoxy helper module; upstream packaging changed');
await writeFile(path.join(output, 'epoxy-utils.mjs'), helper);
await writeFile(path.join(output, 'epoxy.js'), js);
await copyFile(path.join(packageDir, 'full/epoxy.wasm'), path.join(output, 'epoxy.wasm'));
await copyFile(path.join(packageDir, 'full/epoxy.d.ts'), path.join(output, 'epoxy.d.ts'));
const license = await readFile(path.join(packageDir, 'LICENSE'), 'utf8').catch(() => null);
if (license) await writeFile(path.join(output, 'LICENSE'), license);
await writeFile(path.join(output, 'VERSION'), `${metadata.name}@${metadata.version}\nSource: https://github.com/MercuryWorkshop/epoxy-tls\nLicense: ${metadata.license}\nPackaging-only change: embedded JavaScript helper extracted to epoxy-utils.mjs.\n`);
console.log(`Prepared Epoxy ${metadata.version} browser assets`);

const signalPackage = path.join(root, 'node_modules/@getmaapp/signal-wasm');
const signalMetadata = JSON.parse(await readFile(path.join(signalPackage, 'package.json'), 'utf8'));
if (signalMetadata.version !== '0.6.6') throw new Error('Unexpected Signal WASM dependency version');
const signalOutput = path.join(root, 'public/vendor/signal');
await mkdir(signalOutput, { recursive: true });
for (const file of ['signal_wasm.js', 'signal_wasm_bg.wasm', 'signal_wasm.d.ts', 'LICENSE']) {
  await copyFile(path.join(signalPackage, file), path.join(signalOutput, file));
}
await writeFile(path.join(signalOutput, 'VERSION'), '@getmaapp/signal-wasm@0.6.6\nSource: https://github.com/getmaapp/signal-wasm\nLicense: AGPL-3.0-only\n');
const qrOutput = path.join(root, 'public/vendor/qrcode');
await mkdir(qrOutput, { recursive: true });
await build({ entryPoints: [path.join(root, 'node_modules/qrcode/lib/browser.js')],
  bundle: true, platform: 'browser', format: 'esm', target: 'es2022',
  outfile: path.join(qrOutput, 'qrcode.mjs'), minify: true });
await copyFile(path.join(root, 'node_modules/qrcode/license'), path.join(qrOutput, 'LICENSE'));
