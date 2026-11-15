import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, sep, extname } from 'node:path';
import { chromium } from 'playwright';

const dist = fileURLToPath(new URL('../../dist/', import.meta.url));
const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.wasm': 'application/wasm', '.webmanifest': 'application/manifest+json' };

test('PWA installs, reloads offline, and waits for idle tabs before updating', { timeout: 45000 }, async t => {
  let updated = false;
  const headers = (await readFile(resolve(dist, '_headers'), 'utf8')).split('\n')
    .map(line => line.match(/^\s+([\w-]+):\s*(.*)$/)).filter(Boolean);
  const server = http.createServer(async (request, response) => {
    try {
      for (const [, name, value] of headers) response.setHeader(name, value);
      const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
      const file = resolve(dist, `.${pathname === '/' ? '/index.html' : pathname}`);
      if (!file.startsWith(`${resolve(dist)}${sep}`)) { response.writeHead(403).end(); return; }
      let body = await readFile(file);
      if (updated && pathname === '/sw.js') body = Buffer.from(body.toString()
        .replace(/const BUILD_ID = "([a-f0-9]+)";/, 'const BUILD_ID = "$1-browser-update-test";'));
      response.writeHead(200, { 'Content-Type': types[extname(file)] || 'text/plain', 'Cache-Control': 'no-store' });
      response.end(body);
    } catch { response.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const browser = await chromium.launch({
    ...(process.env.TWANG_CHROMIUM_PATH ? { executablePath: process.env.TWANG_CHROMIUM_PATH } : {}),
    args: ['--no-sandbox'],
  });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const first = await context.newPage();
  const pageErrors = [];
  const navigations = [];
  first.on('pageerror', error => pageErrors.push(error.message));
  first.on('framenavigated', frame => {
    if (frame === first.mainFrame()) navigations.push(frame.url());
  });
  const url = `http://127.0.0.1:${server.address().port}/`;
  await first.goto(url);
  await first.waitForFunction(() => Boolean(navigator.serviceWorker.controller));
  const manifest = await first.locator('link[rel="manifest"]').getAttribute('href');
  assert.match(manifest, /manifest\.webmanifest$/);
  const cachePaths = await first.evaluate(async () => {
    const name = (await caches.keys()).find(name => name.startsWith('twang-static-v1-'));
    return (await (await caches.open(name)).keys()).map(request => new URL(request.url).pathname);
  });
  assert.ok(cachePaths.includes('/index.html'));
  assert.ok(cachePaths.includes('/vendor/epoxy/epoxy.wasm'));
  assert.ok(cachePaths.includes('/certs/signal.pem'));
  assert.ok(cachePaths.includes('/icons/icon-512.png'));
  assert.ok(cachePaths.every(path => !/\/test\/|\/api\/|\/reports\/|README|\.json$/.test(path)));

  const second = await context.newPage();
  await second.goto(url);
  await second.evaluate(async () => {
    const { setPwaBusy } = await import('/app/pwa.mjs');
    setPwaBusy(true, 'browser-test-link');
  });
  await first.evaluate(async () => {
    await caches.open('unrelated-app-test');
    window.__twangUpdateEvents = [];
    window.addEventListener('twang:pwa-update', event => {
      window.__twangUpdateEvents.push(event.detail);
      if (event.detail?.type === 'TWANG_PWA_UPDATE_BLOCKED' && event.detail.reason === 'busy-tab')
        window.__twangUpdateBlocked = true;
    });
  });
  updated = true;
  await first.evaluate(async () => {
    window.__twangTestRegistration = await navigator.serviceWorker.getRegistration();
    await window.__twangTestRegistration.update();
  });
  await first.waitForFunction(() => Boolean(window.__twangTestRegistration.waiting));
  await first.locator('#pwa-update').click();
  try {
    await first.waitForFunction(() => window.__twangUpdateBlocked === true, null, { timeout: 5000 });
  } catch (error) {
    const state = async page => page.evaluate(async () => {
      const registration = await navigator.serviceWorker.getRegistration();
      const button = document.querySelector('#pwa-update');
      return {
        url: location.href, controller: navigator.serviceWorker.controller?.state,
        waiting: registration?.waiting?.state, active: registration?.active?.state,
        blocked: window.__twangUpdateBlocked,
        updateEvents: window.__twangUpdateEvents,
        button: button && { text: button.textContent, hidden: button.hidden, disabled: button.disabled },
        status: document.querySelector('#pwa-status')?.textContent,
      };
    });
    throw new Error(`PWA update guard did not report a blocked update: ${JSON.stringify({
      first: await state(first), second: await state(second), navigations, pageErrors,
    })}`, { cause: error });
  }
  assert.equal(await first.evaluate(async () => Boolean((await navigator.serviceWorker.getRegistration()).waiting)), true);
  assert.equal(await second.locator('#pwa-update').isDisabled(), true);

  await second.evaluate(async () => {
    const { setPwaBusy } = await import('/app/pwa.mjs');
    setPwaBusy(false, 'browser-test-link');
  });
  await Promise.all([
    first.waitForNavigation({ waitUntil: 'domcontentloaded' }),
    first.locator('#pwa-update').click(),
  ]);
  await first.waitForFunction(() => Boolean(navigator.serviceWorker.controller));
  const cachesAfterUpdate = await first.evaluate(() => caches.keys());
  assert.equal(cachesAfterUpdate.filter(name => name.startsWith('twang-static-v1-')).length, 1);
  assert.ok(cachesAfterUpdate.includes('unrelated-app-test'));

  await context.setOffline(true);
  await first.reload({ waitUntil: 'domcontentloaded' });
  assert.match(await first.title(), /Twang/i);
  assert.equal(await first.locator('#link-start').count(), 1);
  assert.match(await first.locator('#online-label').textContent(), /offline/i);
  assert.equal(await first.evaluate(() => navigator.onLine), false);
});
