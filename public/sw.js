/* Generated build constants. Build with npm run build before serving. */
const BUILD_ID = __TWANG_BUILD_ID__;
const PRECACHE = __TWANG_PRECACHE__;
const CACHE_PREFIX = 'twang-static-v1-';
const CACHE_NAME = `${CACHE_PREFIX}${BUILD_ID}`;
const STATIC_PATHS = new Set(PRECACHE);

self.addEventListener('install', event => {
  // Do not skip waiting: replacing a running client is an explicit user action.
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    try {
      for (const path of PRECACHE) {
        const request = new Request(new URL(path, self.location.origin),
          { credentials: 'omit', cache: 'reload' });
        const response = await fetch(request);
        if (!response.ok || response.redirected || response.type === 'opaque')
          throw new Error('Static app shell could not be cached');
        await cache.put(request, response);
      }
    } catch (error) {
      await caches.delete(CACHE_NAME);
      throw error;
    }
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    for (const name of await caches.keys()) {
      if (name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  // The cache is only an immutable, build-generated app shell. No runtime cache,
  // API responses, proxy traffic, QR URLs, reports, credentials or account keys.
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.search ||
      request.headers.has('authorization')) return;
  const path = request.mode === 'navigate' && url.pathname === '/' ? '/index.html' : url.pathname;
  if (!STATIC_PATHS.has(path)) return;
  event.respondWith((async () => {
    const cached = await (await caches.open(CACHE_NAME)).match(new URL(path, self.location.origin));
    return cached || fetch(new Request(request, { credentials: 'omit' }));
  })());
});

function clientBusy(client) {
  return new Promise(resolve => {
    const channel = new MessageChannel();
    let finished = false;
    const finish = busy => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      // port2 has been transferred into the window. Only close our local end.
      try { channel.port1.close(); } catch { /* Already closed. */ }
      resolve(busy);
    };
    // An old or unresponsive tab is treated as busy rather than silently replaced.
    const timeout = setTimeout(() => finish(true), 1500);
    channel.port1.onmessage = event => finish(event.data?.busy !== false);
    channel.port1.start();
    try { client.postMessage({ type: 'TWANG_PWA_STATE_REQUEST' }, [channel.port2]); }
    catch { finish(true); }
  });
}

self.addEventListener('message', event => {
  if (event.data?.type !== 'TWANG_PWA_ACTIVATE') return;
  const reply = data => {
    try { event.ports?.[0]?.postMessage(data); } catch { /* Requester went away. */ }
    try { event.source?.postMessage(data); } catch { /* Requester went away. */ }
  };
  event.waitUntil((async () => {
    reply({ type: 'TWANG_PWA_UPDATE_STATUS', stage: 'checking-tabs' });
    let timeout;
    try {
      const clients = await Promise.race([
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }),
        new Promise((_resolve, reject) => { timeout = setTimeout(() => reject(new Error('Client check timed out')), 2000); }),
      ]);
      clearTimeout(timeout);
      if ((await Promise.all(clients.map(clientBusy))).some(Boolean)) {
        reply({ type: 'TWANG_PWA_UPDATE_BLOCKED', reason: 'busy-tab' });
        return;
      }
      reply({ type: 'TWANG_PWA_UPDATE_ACTIVATING' });
      await self.skipWaiting();
    } catch (error) {
      reply({ type: 'TWANG_PWA_UPDATE_BLOCKED', reason: 'state-check-failed', error: error.name });
    } finally {
      clearTimeout(timeout);
    }
  })());
});
