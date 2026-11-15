import { loadEpoxy, createWebSocketTransport } from '/app/proxy-transport.mjs';

const check = (condition, message) => { if (!condition) throw new Error(message); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function deadline(promise, ms = 5000) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Test operation timed out')), ms); })]);
  } finally { clearTimeout(timer); }
}

// Real browser WebAssembly TLS tests, not mocked certificate results. The
// fixture CA and endpoint overrides are passed only to the low-level adapter.
export async function runBrowserSuite(config, progress = () => {}) {
  const epoxy = await loadEpoxy();
  const results = [];
  async function run(name, body) {
    const start = performance.now();
    try { const details = await body(); results.push({ name, ok: true, ...(details ? { details } : {}), durationMs: Math.round(performance.now() - start) }); }
    catch (error) { results.push({ name, ok: false, error: String(error?.stack || error), durationMs: Math.round(performance.now() - start) }); }
    progress([...results]);
  }
  async function clientFor({ endpoint = config.endpoint, certs = [config.cert], host = 'localhost', signal } = {}, body) {
    const abort = new AbortController();
    const externalAbort = () => abort.abort(signal.reason);
    if (signal?.aborted) externalAbort();
    else signal?.addEventListener('abort', externalAbort, { once: true });
    const options = new epoxy.EpoxyClientOptions();
    options.wisp_v2 = false;
    options.udp_extension_required = false;
    options.pem_files = certs;
    options.disable_certificate_validation = false;
    const transport = createWebSocketTransport({ endpoint, allowedHosts: ['localhost', 'wrong.localhost'], allowedPorts: [config.tlsPort], signal: abort.signal });
    const client = new epoxy.EpoxyClient(transport, options);
    try { return await body(client, `${host}:${config.tlsPort}`, abort); }
    finally {
      abort.abort();
      signal?.removeEventListener('abort', externalAbort);
      try { client.free(); } catch {}
    }
  }
  await run('WASM validates fixture CA and preserves binary TLS payload', async () => {
    await clientFor({}, async (client, target) => {
      const stream = await deadline(client.connect_tls(target));
      const writer = stream.write.getWriter();
      const reader = stream.read.getReader();
      const payload = Uint8Array.from({ length: 2 * 1024 * 1024 }, (_, i) => i % 251);
      const received = [];
      const reading = (async () => {
        let length = 0;
        while (length < payload.length) {
          const { done, value } = await reader.read();
          check(!done, `Unexpected EOF after ${length} bytes`);
          received.push(value);
          length += value.length;
        }
      })();
      reading.catch(() => {}); // Attach immediately while writes run concurrently.
      for (let offset = 0; offset < payload.length; offset += 16384) await writer.write(payload.subarray(offset, offset + 16384));
      await deadline(reading);
      const actual = new Uint8Array(received.reduce((n, x) => n + x.length, 0));
      let offset = 0;
      for (const chunk of received) { actual.set(chunk, offset); offset += chunk.length; }
      check(actual.length === payload.length && actual.every((byte, i) => byte === payload[i]), 'Binary TLS payload changed');
      reader.releaseLock();
      writer.releaseLock();
    });
  });
  await run('WASM rejects an untrusted certificate', async () => {
    let rejected = false;
    let reason;
    await clientFor({ certs: [] }, async (client, target) => {
      try { await deadline(client.connect_tls(target)); }
      catch (error) { reason = String(error); check(/UnknownIssuer|unknown issuer|certificate.*untrusted/i.test(reason), `Expected a certificate trust error, received ${reason}`); rejected = true; }
    });
    check(rejected, 'Untrusted certificate was accepted');
    return { reason };
  });
  await run('WASM rejects a certificate hostname mismatch', async () => {
    let rejected = false;
    let reason;
    await clientFor({ host: 'wrong.localhost' }, async (client, target) => {
      try { await deadline(client.connect_tls(target)); }
      catch (error) { reason = String(error); check(/NotValidForName|not valid for name|hostname mismatch/i.test(reason), `Expected a certificate hostname error, received ${reason}`); rejected = true; }
    });
    check(rejected, 'Wrong hostname was accepted');
    return { reason };
  });
  await run('WASM HTTPS returns a readable status and body', async () => {
    await clientFor({}, async (client, target) => {
      const response = await deadline(client.fetch(`https://${target}/`, { method: 'GET', redirect: 'error', credentials: 'omit' }));
      check(response.status === 418, `Expected HTTP 418, received ${response.status}`);
      check(await deadline(response.text()) === 'fixture response', 'HTTPS body changed');
    });
  });
  await run('WASM inner WSS upgrades with headers and receives binary data', async () => {
    await clientFor({}, async (client, target) => {
      let resolveMessage, rejectMessage;
      const message = new Promise((resolve, reject) => { resolveMessage = resolve; rejectMessage = reject; });
      message.catch(() => {});
      const handlers = new epoxy.EpoxyHandlers(() => {},
        () => rejectMessage(new Error('Inner WebSocket closed before a message')),
        error => rejectMessage(new Error(`Inner WebSocket failed: ${error}`)), resolveMessage);
      const socket = await deadline(client.connect_websocket(handlers,
        `wss://${target}/v1/websocket/provisioning/`, [], { 'X-Twang-Fixture': 'browser' }));
      const payload = new Uint8Array([0, 255, 7, 128, 0]);
      const data = await deadline(message);
      const actual = data instanceof Uint8Array ? data : new Uint8Array(data);
      check(actual.length === payload.length && actual.every((value, index) => value === payload[index]), 'Inner WebSocket payload changed');
      await socket.close(1000, 'Fixture complete');
    });
  });
  await run('Abort closes a pending TLS handshake promptly', async () => {
    await clientFor({ endpoint: config.endpoint.replace('/tunnel', '/stall') }, async (client, target, abort) => {
      const start = performance.now();
      const connecting = client.connect_tls(target);
      setTimeout(() => abort.abort(new DOMException('Fixture cancelled', 'AbortError')), 100);
      let rejected = false;
      try { await deadline(connecting, 1500); }
      catch (error) { check(!String(error).includes('Test operation timed out'), 'Aborted handshake remained pending'); rejected = true; }
      check(rejected && performance.now() - start < 1500, 'Abort did not reject promptly');
    });
  });
  await run('All fixture WebSocket tunnels are released', async () => {
    let stats;
    for (let i = 0; i < 20; i++) {
      stats = await (await fetch('/__e2e__/stats')).json();
      if (stats.active === 0) break;
      await sleep(25);
    }
    check(stats.opened >= 6, 'Expected real browser WebSocket connections');
    check(stats.active === 0, `${stats.active} WebSocket tunnel(s) leaked`);
  });
  return results;
}
