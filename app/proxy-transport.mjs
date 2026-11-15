import { bounded, SIGNAL_ENDPOINTS } from './transport.mjs';

export const PROXY_ENDPOINT = 'wss://proxy.twang.chat/v1/tls-tunnel';
export const PROXY_PROTOCOL = 'signal-tls-v1';
export const PROXY_TRUST_POLICY = 'Inner TLS runs in browser WebAssembly with certificate and hostname validation enabled. Bundled Signal roots are added to standard WebPKI roots. The proxy forwards encrypted TLS bytes and receives no Signal credentials or keys.';
const SIGNAL_HOSTS = SIGNAL_ENDPOINTS.map(endpoint => endpoint.host);
const MAX_BUFFER = 1024 * 1024;
let modulePromise;

export function loadEpoxy() {
  if (!modulePromise) modulePromise = import(new URL('../vendor/epoxy/epoxy.js', import.meta.url).href)
    .then(async mod => {
      await mod.default({ module_or_path: new URL('../vendor/epoxy/epoxy.wasm', import.meta.url) });
      return mod;
    }).catch(error => { modulePromise = undefined; throw error; });
  return modulePromise;
}

function packet(type, id, payload = new Uint8Array()) {
  const frame = new Uint8Array(payload.length + 5);
  frame[0] = type;
  new DataView(frame.buffer).setUint32(1, id, true);
  frame.set(payload, 5);
  return frame.buffer;
}
function credits(id) {
  const value = new Uint8Array(4);
  new DataView(value.buffer).setUint32(0, 64, true);
  return packet(3, id, value);
}
const abortError = signal => signal?.reason ?? new DOMException('Proxy transport cancelled', 'AbortError');

// Epoxy expects Wisp locally. Translate that private stream interface to one
// ordinary raw-TLS WebSocket per connection. No Wisp packet or CONNECT hostname
// is transmitted to the proxy; the actual inner ClientHello supplies Signal SNI.
// Explicit options are a low-level test/embedding seam. Production callers use
// createProxyClient(), which fixes the endpoint, hosts and port at build time.
export function createWebSocketTransport({ endpoint = PROXY_ENDPOINT,
  allowedHosts = SIGNAL_HOSTS, allowedPorts = [443], signal,
  onEvent = () => {}, WebSocketImpl = globalThis.WebSocket } = {}) {
  const url = new URL(endpoint);
  if (url.username || url.password || url.search || url.hash ||
    (url.protocol !== 'wss:' && !(url.protocol === 'ws:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
    throw new Error('Proxy must be a WSS endpoint without credentials, query or fragment');
  }
  const hosts = new Set(allowedHosts);
  const ports = new Set(allowedPorts);
  const active = new Set();
  const transport = async () => {
    signal?.throwIfAborted();
    let controller;
    let ended = false;
    const streams = new Map();
    const emit = frame => {
      if (ended) return;
      if ((controller.desiredSize ?? 0) < frame.byteLength) {
        end(new Error('Proxy receive buffer limit exceeded'));
        return;
      }
      controller.enqueue(frame);
    };
    function closeStream(id, notify = true) {
      const stream = streams.get(id);
      if (stream) { streams.delete(id); stream.socket.close(1000, 'Transport closed'); }
      if (notify) emit(packet(4, id, new Uint8Array([3])));
    }
    function end(error) {
      if (ended) return;
      ended = true;
      active.delete(end);
      signal?.removeEventListener('abort', aborted);
      for (const id of [...streams.keys()]) closeStream(id, false);
      if (error) controller.error(error); else controller.close();
    }
    const aborted = () => end(abortError(signal));
    const read = new ReadableStream({
      start(value) { controller = value; value.enqueue(credits(0)); },
      cancel() { end(); },
    }, { highWaterMark: MAX_BUFFER, size: value => value.byteLength });
    active.add(end);
    signal?.addEventListener('abort', aborted, { once: true });
    const write = new WritableStream({
      async write(value) {
        try {
          signal?.throwIfAborted();
          if (ended) throw new Error('Proxy transport is closed');
          const frame = value instanceof Uint8Array ? value : new Uint8Array(value);
          if (frame.length < 5 || frame.length > MAX_BUFFER) throw new Error('Invalid local TLS transport frame');
          const id = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(1, true);
          if (!id) throw new Error('Stream zero is reserved');
          if (frame[0] === 1) {
            if (frame.length < 9 || frame.length > 261 || streams.has(id) || streams.size >= 4)
              throw new Error('Invalid or excessive TLS streams');
            const host = new TextDecoder('utf-8', { fatal: true }).decode(frame.subarray(8));
            const port = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint16(6, true);
            if (frame[5] !== 1 || !hosts.has(host) || !ports.has(port))
              throw new Error('Only allowlisted Signal TLS destinations are permitted');
            onEvent({ level: 'info', phase: 'proxy-websocket', message: 'Opening configured proxy WebSocket tunnel' });
            const socket = new WebSocketImpl(url.href, PROXY_PROTOCOL);
            socket.binaryType = 'arraybuffer';
            const stream = { socket, credits: 64 };
            streams.set(id, stream);
            socket.addEventListener('message', event => {
              if (ended || streams.get(id) !== stream) return;
              if (!(event.data instanceof ArrayBuffer) || event.data.byteLength > 65536) {
                end(new Error('Proxy sent a non-binary or oversized TLS frame')); return;
              }
              emit(packet(2, id, new Uint8Array(event.data)));
            });
            socket.addEventListener('close', () => { if (streams.get(id) === stream) closeStream(id); });
            socket.addEventListener('error', () => end(new Error('Configured proxy WebSocket failed')));
            await new Promise((resolve, reject) => {
              const abort = () => { cleanup(); reject(abortError(signal)); };
              const failed = () => { cleanup(); reject(new Error('Configured proxy could not open a WebSocket tunnel')); };
              const opened = () => {
                cleanup();
                if (socket.protocol !== PROXY_PROTOCOL) { reject(new Error('Proxy did not negotiate signal-tls-v1')); return; }
                resolve();
              };
              const cleanup = () => {
                signal?.removeEventListener('abort', abort);
                socket.removeEventListener('open', opened);
                socket.removeEventListener('error', failed);
                socket.removeEventListener('close', failed);
              };
              socket.addEventListener('open', opened, { once: true });
              socket.addEventListener('error', failed, { once: true });
              socket.addEventListener('close', failed, { once: true });
              signal?.addEventListener('abort', abort, { once: true });
            });
            onEvent({ level: 'success', phase: 'inner-tls', message: 'Configured proxy WebSocket tunnel opened; validating inner Signal TLS' });
          } else if (frame[0] === 2) {
            const stream = streams.get(id);
            if (!stream || stream.socket.readyState !== 1) throw new Error('TLS tunnel is not open');
            if (--stream.credits < 0) throw new Error('TLS transport credit exhausted');
            for (let offset = 5; offset < frame.length; offset += 16384) {
              while (stream.socket.bufferedAmount > MAX_BUFFER - 16384) {
                await new Promise(resolve => setTimeout(resolve, 5));
                signal?.throwIfAborted();
                if (ended || stream.socket.readyState !== 1) throw new Error('TLS tunnel closed during write');
              }
              stream.socket.send(frame.subarray(offset, offset + 16384));
            }
            if (!stream.credits) { stream.credits = 64; emit(credits(id)); }
          } else if (frame[0] === 4 && frame.length === 6) closeStream(id, false);
          else throw new Error('Unsupported local TLS transport packet');
        } catch (error) { end(error); throw error; }
      },
      close() { end(); }, abort(error) { end(error); },
    });
    return { read, write };
  };
  transport.close = () => { for (const end of [...active]) end(); };
  return transport;
}

export async function createProxyClient(ctx) {
  ctx.setPhase('wasm');
  ctx.emit('info', 'Loading local WebAssembly TLS implementation');
  const mod = await loadEpoxy();
  ctx.check();
  const roots = await Promise.all(['signal', 'signal-ed25519'].map(async name => {
    const response = await fetch(new URL(`../certs/${name}.pem`, import.meta.url),
      { signal: ctx.signal, credentials: 'omit', cache: 'force-cache' });
    if (!response.ok) throw new Error(`Signal trust root ${name} failed to load`);
    const pem = await response.text();
    if (pem.length > 10000 || !pem.startsWith('-----BEGIN CERTIFICATE-----')) throw new Error('Invalid bundled Signal trust root');
    return pem;
  }));
  ctx.check();
  const settings = new mod.EpoxyClientOptions();
  settings.wisp_v2 = false;
  settings.udp_extension_required = false;
  settings.redirect_limit = 0;
  settings.header_limit = 100;
  settings.pem_files = roots;
  settings.disable_certificate_validation = false;
  const transport = createWebSocketTransport({ signal: ctx.signal,
    onEvent: event => { ctx.setPhase(event.phase); ctx.emit(event.level, event.message); } });
  const client = new mod.EpoxyClient(transport, settings);
  ctx.defer(() => { transport.close(); client.free(); });
  ctx.setEvidence({ proxy: PROXY_ENDPOINT, certificateValidation: true });
  ctx.setPhase('inner-tls');
  return { client, mod };
}

function target(options) {
  const host = options.host ?? options.target?.host;
  if (!SIGNAL_HOSTS.includes(host)) throw new Error('Only bundled Signal service endpoints are allowed');
  return host;
}
export function probeProxyTls(options = {}) {
  return bounded(options, async ctx => {
    const host = target(options);
    const { client } = await createProxyClient(ctx);
    const stream = await client.connect_tls(`${host}:443`);
    ctx.defer(() => { stream.read.cancel().catch(() => {}); stream.write.abort().catch(() => {}); });
    ctx.check();
    ctx.emit('success', `Certificate-validated inner TLS handshake completed for ${host}`);
    return { summary: 'Signal TLS handshake completed', details: { host, proxy: PROXY_ENDPOINT,
      transport: 'Browser WASM TLS through WebSocket proxy', tlsHandshake: true, certificateValidation: true } };
  });
}
export function probeProxyHttps(options = {}) {
  return bounded(options, async ctx => {
    const host = target(options);
    const { client } = await createProxyClient(ctx);
    const response = await client.fetch(`https://${host}/`, { method: 'GET', redirect: 'error', credentials: 'omit' });
    ctx.defer(() => response.body?.cancel());
    ctx.check();
    return { summary: `Signal returned HTTP ${response.status}`, details: { host, proxy: PROXY_ENDPOINT,
      httpStatus: response.status, transport: 'Browser WASM HTTPS through WebSocket proxy', certificateValidation: true,
      interpretation: 'A readable response verifies the transport, not a Signal messaging session.' } };
  });
}
export function probeProxyWebSocket(options = {}) {
  return bounded(options, async ctx => {
    const host = target(options);
    if (!SIGNAL_ENDPOINTS.find(endpoint => endpoint.host === host)?.provisioning)
      throw new Error('Provisioning WebSocket is tested only on Signal chat endpoints');
    const { client, mod } = await createProxyClient(ctx);
    const handlers = new mod.EpoxyHandlers(() => {}, () => {}, () => {}, () => {});
    const socket = await client.connect_websocket(handlers, `wss://${host}/v1/websocket/provisioning/`, [], {});
    ctx.defer(() => socket.close(1000, 'Diagnostic complete'));
    ctx.check();
    return { summary: 'Signal provisioning WebSocket upgrade completed', details: { host, proxy: PROXY_ENDPOINT,
      transport: 'Browser WASM WSS through WebSocket proxy', websocketUpgrade: true, certificateValidation: true,
      interpretation: 'Upgrade only; no QR code, account link, or authenticated messaging session was created.' } };
  });
}
