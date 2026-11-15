import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { buildPwa } from '../scripts/pwa-build.mjs';
import { canRegisterPwa, registerPwa, setPwaBusy, requestPwaUpdate } from '../app/pwa.mjs';

const template = await readFile(new URL('../public/sw.js', import.meta.url), 'utf8');

function worker({ clients = [] } = {}) {
  const events = new Map();
  const storage = new Map();
  let skipped = false;
  let claimed = false;
  const response = new Response('offline app shell');
  const cache = { match: async () => response.clone(), put: async () => {} };
  const context = {
    URL, Request, Response, Set, Promise, MessageChannel, setTimeout, clearTimeout,
    fetch: async () => new Response('network app shell'),
    caches: { open: async name => { storage.set(name, cache); return cache; },
      keys: async () => [...storage.keys()], delete: async name => storage.delete(name) },
    self: {
      location: { origin: 'https://twang.chat' },
      addEventListener: (name, handler) => events.set(name, handler),
      clients: { claim: async () => { claimed = true; }, matchAll: async () => clients },
      skipWaiting: async () => { skipped = true; },
    },
  };
  vm.runInNewContext(template.replace('__TWANG_BUILD_ID__', '"test-build"')
    .replace('__TWANG_PRECACHE__', '["/index.html","/app/main.mjs","/vendor/epoxy/epoxy.wasm"]'), context);
  return { events, storage, context, skipped: () => skipped, claimed: () => claimed };
}

test('manifest has installable standalone metadata and real raster icons', async () => {
  const manifest = JSON.parse(await readFile(new URL('../public/manifest.webmanifest', import.meta.url)));
  assert.equal(manifest.id, '/');
  assert.equal(manifest.scope, '/');
  assert.equal(manifest.start_url, '/');
  assert.equal(manifest.display, 'standalone');
  for (const size of [192, 512]) {
    const icon = manifest.icons.find(icon => icon.sizes === `${size}x${size}`);
    assert.ok(icon);
    const png = await readFile(new URL(`../public${icon.src}`, import.meta.url));
    assert.equal(png.toString('hex', 0, 8), '89504e470d0a1a0a');
    assert.equal(png.readUInt32BE(16), size);
    assert.equal(png.readUInt32BE(20), size);
  }
  assert.ok(manifest.icons.some(icon => icon.purpose.includes('maskable')));
});

test('build versions change with app assets and exclude account, report and fixture files', async t => {
  const dist = await mkdtemp(path.join(tmpdir(), 'twang-pwa-build-'));
  t.after(() => rm(dist, { recursive: true, force: true }));
  const files = {
    'sw.js': template, 'index.html': 'shell', 'app/main.mjs': 'first version',
    'vendor/tls.wasm': 'wasm bytes', 'certs/signal.pem': 'public CA',
    'certs/private-key.pem': 'must not be cached', 'accounts/secret.json': 'must not be cached',
    'reports/export.html': 'must not be cached', 'test/fixture.mjs': 'must not be cached',
  };
  for (const [file, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(dist, file)), { recursive: true });
    await writeFile(path.join(dist, file), content);
  }
  const first = await buildPwa(dist);
  assert.deepEqual(first.files, ['app/main.mjs', 'certs/signal.pem', 'index.html', 'vendor/tls.wasm']);
  assert.doesNotMatch(await readFile(path.join(dist, 'sw.js'), 'utf8'), /__TWANG_/);
  await writeFile(path.join(dist, 'sw.js'), template);
  const same = await buildPwa(dist);
  assert.equal(same.version, first.version);
  await writeFile(path.join(dist, 'app/main.mjs'), 'second version');
  await writeFile(path.join(dist, 'sw.js'), template);
  assert.notEqual((await buildPwa(dist)).version, first.version);
});

test('service worker intercepts only its immutable app shell, never connection or credential traffic', async () => {
  const { events } = worker();
  const handler = events.get('fetch');
  for (const [url, options] of [
    ['https://proxy.twang.chat/v1/tls-tunnel', {}],
    ['https://twang.chat/api/account', {}],
    ['https://twang.chat/reports/export.json', {}],
    ['https://twang.chat/app/main.mjs?token=private', {}],
    ['https://twang.chat/app/main.mjs', { headers: { Authorization: 'private' } }],
    ['https://twang.chat/app/main.mjs', { method: 'POST', body: 'private' }],
  ]) {
    let intercepted = false;
    handler({ request: new Request(url, options), respondWith: () => { intercepted = true; } });
    assert.equal(intercepted, false, url);
  }
  let result;
  handler({ request: new Request('https://twang.chat/app/main.mjs'), respondWith: promise => { result = promise; } });
  assert.equal(await (await result).text(), 'offline app shell');
});

test('activation removes only previous Twang shell caches and install does not skip waiting', async () => {
  const state = worker();
  state.storage.set('twang-static-v1-old', {});
  state.storage.set('another-app-cache', {});
  let installing;
  state.events.get('install')({ waitUntil: promise => { installing = promise; } });
  await installing;
  assert.equal(state.skipped(), false);
  let activating;
  state.events.get('activate')({ waitUntil: promise => { activating = promise; } });
  await activating;
  assert.equal(state.storage.has('twang-static-v1-old'), false);
  assert.equal(state.storage.has('another-app-cache'), true);
  assert.equal(state.claimed(), true);
});

test('explicit updates wait for every active app tab to be idle', async () => {
  for (const busy of [true, false]) {
    const state = worker({ clients: [{ postMessage(_message, ports) { ports[0].postMessage({ busy }); } }] });
    let updating;
    let blocked = false;
    state.events.get('message')({ data: { type: 'TWANG_PWA_ACTIVATE' },
      source: { postMessage: data => { if (data.type === 'TWANG_PWA_UPDATE_BLOCKED') blocked = true; } }, waitUntil: promise => { updating = promise; } });
    await updating;
    assert.equal(state.skipped(), !busy);
    assert.equal(blocked, busy);
  }
});

test('PWA registration requires HTTPS or a secure loopback development origin', () => {
  assert.equal(canRegisterPwa({ protocol: 'https:', hostname: 'twang.chat' }, true), true);
  assert.equal(canRegisterPwa({ protocol: 'http:', hostname: 'localhost' }, true), true);
  assert.equal(canRegisterPwa({ protocol: 'http:', hostname: 'twang.chat' }, false), false);
  assert.equal(canRegisterPwa({ protocol: 'file:', hostname: '' }, true), false);
});

test('a waiting update takes priority over a stale reload notification', async t => {
  const saved = new Map(['window', 'document', 'navigator'].map(key => [key,
    Object.getOwnPropertyDescriptor(globalThis, key)]));
  t.after(() => {
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  });
  const update = new EventTarget();
  const serviceWorker = new EventTarget();
  const registration = new EventTarget();
  const window = new EventTarget();
  let reloads = 0;
  let messagesStarted = false;
  let activation;
  window.location = { protocol: 'http:', hostname: 'localhost', reload: () => { reloads++; } };
  window.isSecureContext = true;
  serviceWorker.controller = { state: 'activated' };
  serviceWorker.register = async () => registration;
  serviceWorker.startMessages = () => { messagesStarted = true; };
  Object.defineProperty(globalThis, 'window', { value: window, configurable: true });
  Object.defineProperty(globalThis, 'document', { value: {
    querySelector: selector => selector === '#pwa-update' ? update : null,
  }, configurable: true });
  Object.defineProperty(globalThis, 'navigator', { value: { serviceWorker }, configurable: true });
  await registerPwa();
  assert.equal(messagesStarted, true);
  serviceWorker.dispatchEvent(new Event('controllerchange'));
  registration.waiting = { postMessage: (message, ports) => {
    activation = message;
    ports[0].postMessage({ type: 'TWANG_PWA_UPDATE_BLOCKED', reason: 'busy-tab' });
  } };
  setPwaBusy(false);
  const replied = new Promise(resolve => window.addEventListener('twang:pwa-update', resolve, { once: true }));
  update.dispatchEvent(new Event('click'));
  await replied;
  assert.equal(reloads, 0);
  assert.equal(activation.type, 'TWANG_PWA_ACTIVATE');
  assert.equal(update.textContent, 'Update app');
});

test('worker update results use the explicit reply port and fail closed on request errors', async () => {
  const statuses = [];
  const result = await requestPwaUpdate({ postMessage(message, ports) {
    assert.equal(message.type, 'TWANG_PWA_ACTIVATE');
    ports[0].postMessage({ type: 'TWANG_PWA_UPDATE_STATUS', stage: 'checking-tabs' });
    ports[0].postMessage({ type: 'TWANG_PWA_UPDATE_BLOCKED', reason: 'busy-tab' });
  } }, data => statuses.push(data));
  assert.equal(result.reason, 'busy-tab');
  assert.equal(statuses[0].stage, 'checking-tabs');
  assert.equal(statuses[1].type, 'TWANG_PWA_UPDATE_BLOCKED');
  const failed = await requestPwaUpdate({ postMessage() { throw new Error('Worker gone'); } });
  assert.equal(failed.type, 'TWANG_PWA_UPDATE_BLOCKED');
  assert.equal(failed.reason, 'request-failed');
});

test('worker client-query failures report a blocked update rather than hanging', async () => {
  const state = worker();
  state.context.self.clients.matchAll = async () => { throw new Error('Client query failed'); };
  const reply = new MessageChannel();
  const result = new Promise(resolve => { reply.port1.onmessage = event => {
    if (event.data.type === 'TWANG_PWA_UPDATE_BLOCKED') resolve(event.data);
  }; });
  let updating;
  state.events.get('message')({ data: { type: 'TWANG_PWA_ACTIVATE' }, ports: [reply.port2],
    waitUntil: promise => { updating = promise; } });
  await updating;
  assert.equal((await result).reason, 'state-check-failed');
  assert.equal(state.skipped(), false);
  reply.port1.close();reply.port2.close();
});
