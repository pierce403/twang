import { decodeWebSocketMessage, decodeProvisioningAddress, encodeResponse } from './protobuf.mjs';

export const SIGNAL_ENDPOINTS = Object.freeze([
  { id: 'chat', host: 'chat.signal.org', label: 'Chat', description: 'Signal chat service', provisioning: true },
  { id: 'grpc', host: 'grpc.chat.signal.org', label: 'Chat / HTTP 2', description: 'Current native chat transport', provisioning: true },
  { id: 'storage', host: 'storage.signal.org', label: 'Storage', description: 'Encrypted account storage', provisioning: false },
  { id: 'cdn', host: 'cdn.signal.org', label: 'CDN 0', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdn2', host: 'cdn2.signal.org', label: 'CDN 2', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdn3', host: 'cdn3.signal.org', label: 'CDN 3', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdsi', host: 'cdsi.signal.org', label: 'Contact discovery', description: 'TLS reachability only; no discovery requests', provisioning: false },
  { id: 'svr2', host: 'svr2.signal.org', label: 'Secure recovery 2', description: 'TLS reachability only; no recovery requests', provisioning: false },
  { id: 'svrb', host: 'svrb.signal.org', label: 'Secure recovery B', description: 'TLS reachability only; no recovery requests', provisioning: false },
]);
const hosts = new Set(SIGNAL_ENDPOINTS.map(endpoint => endpoint.host));
const provisioningHosts = new Set(SIGNAL_ENDPOINTS.filter(endpoint => endpoint.provisioning).map(endpoint => endpoint.host));
export const TRUST_POLICY = 'Certificate and hostname validation enabled. Bundled Signal RSA and Ed25519 roots are added to Epoxy’s standard WebPKI roots; this PoC does not enforce Signal-only CA pinning.';
const PROVISIONING_PATH = '/v1/websocket/provisioning/';
const MAX_BINARY = 64 * 1024;
// MercuryWorkshop/wisp-protocol protocol.md, CLOSE packet reason codes.
// These describe what the relay reported, not an independently verified cause.
const WISP_CLOSE_REASONS = Object.freeze({
  0x01: 'Unspecified or unknown reason',
  0x02: 'Voluntary stream closure',
  0x03: 'Unexpected network stream closure',
  0x04: 'Incompatible extensions',
  0x41: 'Invalid stream destination information',
  0x42: 'Unreachable destination host (may include DNS resolution failure)',
  0x43: 'Destination connection timed out',
  0x44: 'Destination refused the connection',
  0x47: 'TCP data transfer timed out',
  0x48: 'Destination blocked by relay policy',
  0x49: 'Connection throttled by relay',
  0x81: 'Client unable to receive data',
  0xc0: 'Relay authentication failed: username/password',
  0xc1: 'Relay authentication failed: signature',
  0xc2: 'Relay authentication required',
});
let modulePromise;

function detail(error) {
  if (error instanceof Error) return error.message;
  return String(error ?? 'Unknown error');
}

function validateHost(host) {
  if (!hosts.has(host)) throw new Error('Only the bundled Signal service endpoints are allowed');
  return host;
}

function validateRelay(value) {
  const url = new URL(value);
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'wss:' && !(url.protocol === 'ws:' && local && location.protocol === 'http:')) {
    throw new Error('Use wss:// for a relay, or ws://localhost while running the UI locally over HTTP');
  }
  if (url.username || url.password || url.hash || url.search) throw new Error('Relay URL must not contain credentials, a fragment, or a query string');
  return url.href;
}

function targetOf(options) {
  const host = validateHost(options.host ?? options.target?.host);
  return { host, url: `https://${host}/`, wsUrl: `wss://${host}${PROVISIONING_PATH}` };
}

async function bounded(options, work) {
  const start = performance.now();
  const events = [];
  const evidence = {};
  const cleanups = [];
  const controller = new AbortController();
  const timeoutMs = Number(options.timeoutMs ?? 10000);
  const limit = Number.isFinite(timeoutMs) ? Math.max(1000, Math.min(timeoutMs, 30000)) : 10000;
  let phase = 'setup';
  let timedOut = false;
  const emit = (level, message, extra = {}) => {
    if (controller.signal.aborted) return;
    const event = { level, phase, stage: phase, message, ...extra };
    events.push(event);
    try { options.onEvent?.(event); } catch { /* A log renderer must not break a probe. */ }
  };
  const externalAbort = () => controller.abort(options.signal?.reason ?? new DOMException('Probe cancelled', 'AbortError'));
  if (options.signal?.aborted) externalAbort();
  else options.signal?.addEventListener('abort', externalAbort, { once: true });
  const timer = setTimeout(() => { timedOut = true; controller.abort(new DOMException('Probe timed out', 'TimeoutError')); }, limit);
  let abortListener;
  const aborted = new Promise((_resolve, reject) => {
    abortListener = () => reject(controller.signal.reason ?? new DOMException('Probe cancelled', 'AbortError'));
    if (controller.signal.aborted) abortListener();
    else controller.signal.addEventListener('abort', abortListener, { once: true });
  });
  const ctx = {
    signal: controller.signal,
    emit,
    setPhase(value) { phase = value; },
    setEvidence(value) { Object.assign(evidence, value); },
    defer(fn) { cleanups.push(fn); },
    check() { controller.signal.throwIfAborted(); },
  };
  try {
    const result = await Promise.race([Promise.resolve().then(() => { ctx.check(); return work(ctx); }), aborted]);
    return { ok: true, status: 'success', outcome: 'success', ...result, durationMs: Math.round(performance.now() - start), events };
  } catch (error) {
    const outcome = timedOut ? 'timeout' : controller.signal.aborted ? 'cancelled' : 'failure';
    const text = detail(error);
    const relayCause = evidence.wispClose;
    const summary = timedOut ? `No result within ${limit / 1000}s`
      : outcome === 'cancelled' ? 'Probe cancelled'
      : relayCause && relayCause.reasonCode !== 0x02
        ? `Relay reported ${relayCause.label.toLowerCase()} (${relayCause.reasonHex}); ${text}`
        : text;
    emit(outcome === 'cancelled' ? 'info' : 'error', summary);
    return {
      ok: false, status: outcome, outcome,
      summary,
      details: { phase, error: text, ...evidence, ...(relayCause ? {
        interpretation: `The relay sent Wisp CLOSE ${relayCause.reasonHex} for stream ${relayCause.streamId}. This preserves the relay-reported failure class alongside the WASM error; it does not independently establish the underlying cause or Signal availability.`,
      } : phase === 'browser-https' || phase === 'browser-websocket' ? {
        interpretation: 'The browser does not expose enough detail to distinguish certificate, DNS, network, Origin, or CORS policy failures. This is not evidence that Signal itself is offline.',
      } : {}) },
      durationMs: Math.round(performance.now() - start), events,
    };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', externalAbort);
    controller.signal.removeEventListener('abort', abortListener);
    for (const cleanup of cleanups.reverse()) {
      try { Promise.resolve(cleanup()).catch(() => {}); } catch { /* Best-effort teardown. */ }
    }
  }
}

export function probeDirectHttps(options = {}) {
  return bounded(options, async ctx => {
    const { host, url } = targetOf(options);
    ctx.setPhase('browser-https');
    ctx.emit('info', `GET ${url} using native browser fetch`);
    const response = await fetch(url, { method: 'GET', mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error', signal: ctx.signal });
    ctx.defer(() => response.body?.cancel());
    ctx.emit('success', `Readable HTTP ${response.status} response from ${host}`);
    return {
      summary: `Browser received HTTP ${response.status}`,
      details: { host, httpStatus: response.status, transport: 'Native browser HTTPS', interpretation: 'Any readable HTTP response confirms this transport path. It does not establish a Signal messaging session.' },
    };
  });
}

export function probeDirectWebSocket(options = {}) {
  return bounded(options, async ctx => {
    const { host, wsUrl } = targetOf(options);
    if (!provisioningHosts.has(host)) throw new Error('Provisioning WebSocket is tested only on Signal chat endpoints');
    ctx.setPhase('browser-websocket');
    ctx.emit('info', `Opening ${wsUrl} with the native WebSocket API`);
    const socket = new WebSocket(wsUrl);
    socket.binaryType = 'arraybuffer';
    ctx.defer(() => socket.close(1000, 'Diagnostic complete'));
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', () => reject(new Error('Browser WebSocket failed; certificate, network, and policy details are opaque')), { once: true });
      socket.addEventListener('close', event => reject(new Error(`Browser WebSocket closed before a result (code ${event.code})`)), { once: true });
    });
    ctx.check();
    ctx.emit('success', 'Native browser WebSocket upgrade completed');
    return { summary: 'Browser WebSocket upgrade completed', details: { host, transport: 'Native browser WSS', websocketUpgrade: true, interpretation: 'Upgrade only. No authenticated session, QR code, or account was created.' } };
  });
}

async function epoxy(ctx) {
  ctx.setPhase('wasm');
  ctx.emit('info', 'Loading local Epoxy TLS/WebAssembly transport');
  if (!modulePromise) {
    modulePromise = import(new URL('../vendor/epoxy/epoxy.js', import.meta.url).href).then(async mod => {
      await mod.default({ module_or_path: new URL('../vendor/epoxy/epoxy.wasm', import.meta.url) });
      return mod;
    }).catch(error => { modulePromise = undefined; throw new Error(`Epoxy assets could not load. Run npm run build to prepare local vendor assets. ${detail(error)}`); });
  }
  const mod = await modulePromise;
  ctx.check();
  const roots = await Promise.all(['signal', 'signal-ed25519'].map(async name => {
    const response = await fetch(new URL(`../certs/${name}.pem`, import.meta.url), { signal: ctx.signal, credentials: 'omit', cache: 'force-cache' });
    if (!response.ok) throw new Error(`Bundled Signal trust root ${name} could not load (HTTP ${response.status})`);
    const text = await response.text();
    if (text.length > 10000 || !text.startsWith('-----BEGIN CERTIFICATE-----')) throw new Error(`Invalid bundled Signal root ${name}`);
    return text;
  }));
  ctx.check();
  ctx.emit('info', `Epoxy ${mod.info?.version ?? '2.1.20-1'} ready; certificate validation remains enabled`);
  return { mod, roots };
}

function wispTransport(relayUrl, ctx) {
  const active = new Set();
  ctx.defer(() => {
    for (const session of [...active]) {
      session.end(new Error('Diagnostic transport closed'));
      session.socket.close(1000, 'Diagnostic complete');
    }
    active.clear();
  });
  return async () => {
    ctx.check();
    ctx.setPhase('relay');
    ctx.emit('info', `Connecting Wisp v1 byte relay ${relayUrl}`);
    const socket = new WebSocket(relayUrl);
    socket.binaryType = 'arraybuffer';
    let readerController;
    let ended = false;
    let session;
    const end = error => {
      if (ended) return;
      ended = true;
      active.delete(session);
      if (error) readerController?.error(error);
      else readerController?.close();
    };
    const read = new ReadableStream({
      start(controller) { readerController = controller; },
      cancel() { socket.close(1000, 'Stream cancelled'); end(); },
    });
    session = { socket, end };
    active.add(session);
    socket.addEventListener('message', event => {
      if (ended) return;
      if (!(event.data instanceof ArrayBuffer) || event.data.byteLength > 1024 * 1024) {
        end(new Error('Invalid or oversized Wisp relay frame'));
        socket.close(1009, 'Invalid relay frame');
        return;
      }
      const frame = new Uint8Array(event.data);
      if (frame.length === 6 && frame[0] === 0x04) {
        const streamId = new DataView(event.data).getUint32(1, true);
        const reasonCode = frame[5];
        const reasonHex = `0x${reasonCode.toString(16).padStart(2, '0')}`;
        const label = WISP_CLOSE_REASONS[reasonCode] ?? 'Unknown Wisp close reason';
        ctx.setEvidence({ wispClose: { streamId, reasonCode, reasonHex, label } });
        ctx.emit(reasonCode === 0x02 ? 'info' : 'error', `Relay Wisp CLOSE: stream ${streamId}, ${reasonHex} — ${label}`);
      }
      readerController.enqueue(event.data);
    });
    socket.addEventListener('close', event => end(event.code === 1000 ? undefined : new Error(`Relay disconnected (code ${event.code})`)));
    socket.addEventListener('error', () => end(new Error('Relay WebSocket failed; check relay URL, TLS and allowed Origin')));
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', () => reject(new Error('Could not open the configured relay WebSocket')), { once: true });
      socket.addEventListener('close', event => reject(new Error(`Relay closed during connect (code ${event.code})`)), { once: true });
    });
    ctx.check();
    ctx.emit('success', 'Relay WebSocket connected; forwarding TLS bytes with Wisp v1');
    ctx.setPhase('upstream');
    const write = new WritableStream({
      async write(chunk) {
        ctx.check();
        if (socket.readyState !== WebSocket.OPEN) throw new Error('Relay is not connected');
        while (socket.bufferedAmount > 1024 * 1024) {
          await new Promise(resolve => setTimeout(resolve, 10));
          ctx.check();
          if (socket.readyState !== WebSocket.OPEN) throw new Error('Relay disconnected during write');
        }
        socket.send(chunk);
      },
      close() { socket.close(1000, 'Wisp closed'); end(); },
      abort() { socket.close(1000, 'Wisp aborted'); end(); },
    });
    return { read, write };
  };
}

async function clientFor(options, ctx) {
  const target = targetOf(options);
  const relayUrl = validateRelay(options.relayUrl);
  const { mod, roots } = await epoxy(ctx);
  const settings = new mod.EpoxyClientOptions();
  settings.wisp_v2 = false;
  settings.udp_extension_required = false;
  settings.redirect_limit = 0;
  settings.header_limit = 100;
  settings.user_agent = 'Twang/0.1 diagnostics';
  settings.pem_files = roots;
  settings.disable_certificate_validation = false;
  const client = new mod.EpoxyClient(wispTransport(relayUrl, ctx), settings);
  // Close the outer sockets in the same cleanup turn, let their rejected reads
  // unwind Rust futures, then release the wasm-bindgen handle.
  ctx.defer(() => { setTimeout(() => { try { client.free(); } catch { /* A pending borrowed future still owns its reference. */ } }, 0); });
  return { ...target, client, mod, relayUrl };
}

export function probeRelayTls(options = {}) {
  return bounded(options, async ctx => {
    const { host, client, relayUrl } = await clientFor(options, ctx);
    ctx.setPhase('tls');
    ctx.emit('info', `Negotiating TLS with ${host}:443 inside WebAssembly`);
    // Epoxy awaits rustls's connector.connect handshake before returning this stream.
    const stream = await client.connect_tls(`${host}:443`);
    ctx.defer(() => { stream.read.cancel().catch(() => {}); stream.write.abort().catch(() => {}); });
    ctx.check();
    ctx.emit('success', 'TLS handshake, hostname and certificate-chain validation completed');
    return { summary: 'Browser-side TLS handshake verified', details: { host, relayUrl, tlsVerified: true, transport: 'WASM rustls → Wisp byte relay → Signal TCP 443', trustPolicy: TRUST_POLICY, interpretation: 'TLS reachability only. No HTTP request or Signal account operation was sent. TLS version, ALPN and leaf certificate are not exposed by this Epoxy API.' } };
  });
}

export function probeRelayHttps(options = {}) {
  return bounded(options, async ctx => {
    const { host, url, client, relayUrl } = await clientFor(options, ctx);
    ctx.setPhase('tls-http');
    ctx.emit('info', `GET ${url} over browser-side TLS`);
    const response = await client.fetch(url, { method: 'GET', redirect: 'manual', headers: { Accept: '*/*' } });
    ctx.defer(() => response.body?.cancel());
    ctx.check();
    ctx.emit('success', `Validated TLS connection returned HTTP ${response.status}`);
    return { summary: `Browser-side TLS reached HTTP ${response.status}`, details: { host, relayUrl, tlsVerified: true, httpStatus: response.status, transport: 'WASM HTTPS via byte relay', trustPolicy: TRUST_POLICY, interpretation: 'Any HTTP status confirms transport reachability. A 401, 403 or 404 at / does not mean Signal is offline. No credentials were used.' } };
  });
}

export function probeRelayProvisioning(options = {}) {
  return bounded(options, async ctx => {
    const host = validateHost(options.host ?? options.target?.host);
    if (!provisioningHosts.has(host)) throw new Error('Provisioning is tested only on Signal chat endpoints');
    const { wsUrl, client, mod, relayUrl } = await clientFor(options, ctx);
    ctx.setPhase('provisioning');
    ctx.emit('info', `Opening ${wsUrl} through browser-side TLS`);
    let inner;
    let resolveAddress;
    let rejectAddress;
    const addressPromise = new Promise((resolve, reject) => { resolveAddress = resolve; rejectAddress = reject; });
    // Attach a handler immediately; connect_websocket can reject before this promise is awaited.
    addressPromise.catch(() => {});
    const pendingFrames = [];
    let settled = false;
    let frameCount = 0;
    const process = async input => {
      if (settled || ctx.signal.aborted) return;
      if (++frameCount > 8) throw new Error('Too many provisioning frames for a diagnostic probe');
      if (!(input instanceof Uint8Array) && !(input instanceof ArrayBuffer)) throw new Error('Expected a binary Signal provisioning frame');
      if (input.byteLength > MAX_BINARY) throw new Error('Signal provisioning frame exceeds 64 KiB diagnostic limit');
      const message = decodeWebSocketMessage(input);
      if (message.type !== 'request' || message.verb !== 'PUT' || message.path !== '/v1/address') {
        if (message.type === 'request') await inner.send(encodeResponse(message.id, 400, 'Diagnostic only').buffer);
        throw new Error('Received an unexpected Signal provisioning message; no envelope was processed');
      }
      const address = decodeProvisioningAddress(message.body);
      await inner.send(encodeResponse(message.id).buffer);
      settled = true;
      ctx.emit('success', 'Received and acknowledged a Signal provisioning address');
      resolveAddress(address);
    };
    const fail = error => { if (!settled) { settled = true; rejectAddress(error instanceof Error ? error : new Error(detail(error))); } };
    const handlers = new mod.EpoxyHandlers(
      () => ctx.emit('success', 'Inner Signal WebSocket upgrade completed'),
      () => fail(new Error('Signal WebSocket closed before delivering a provisioning address')),
      error => fail(new Error(`Signal WebSocket error: ${detail(error)}`)),
      input => {
        if (settled || ctx.signal.aborted) return;
        if (!(input instanceof Uint8Array) && !(input instanceof ArrayBuffer)) {
          fail(new Error('Expected a binary Signal provisioning frame'));
          return;
        }
        if (input.byteLength > MAX_BINARY || pendingFrames.length >= 8) {
          fail(new Error('Provisioning data exceeds the diagnostic limit'));
          return;
        }
        if (!inner) { pendingFrames.push(input); return; }
        process(input).catch(fail);
      },
    );
    inner = await client.connect_websocket(handlers, wsUrl, [], {});
    ctx.defer(() => inner.close(1000, 'Diagnostic complete'));
    ctx.check();
    for (const frame of pendingFrames) await process(frame);
    const address = await addressPromise;
    return { summary: 'Signal provisioning address received', details: { host, relayUrl, tlsVerified: true, websocketUpgrade: true, provisioningAddress: address, transport: 'Signal WebSocket protobuf inside browser-side TLS', trustPolicy: TRUST_POLICY, interpretation: 'A temporary unauthenticated provisioning address was received and acknowledged, then the connection was closed. No keypair, QR code, linked device, account, or message session was created.' } };
  });
}

export function runProbe(options) {
  const probes = {
    https: probeDirectHttps, 'direct-https': probeDirectHttps,
    websocket: probeDirectWebSocket, 'direct-websocket': probeDirectWebSocket,
    'relay-tls': probeRelayTls, 'relay-https': probeRelayHttps,
    'relay-websocket': probeRelayProvisioning, 'relay-provisioning': probeRelayProvisioning,
  };
  const probe = probes[options.mode];
  if (!probe) return Promise.resolve({ ok: false, outcome: 'failure', status: 'failure', summary: 'Unknown diagnostic mode', details: {}, durationMs: 0, events: [] });
  return probe(options);
}
