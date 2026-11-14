export const SIGNAL_ENDPOINTS = Object.freeze([
  { id: 'chat', host: 'chat.signal.org', label: 'Chat', description: 'Signal chat service', provisioning: true },
  { id: 'grpc', host: 'grpc.chat.signal.org', label: 'Chat / HTTP 2', description: 'Current native chat transport', provisioning: true },
  { id: 'storage', host: 'storage.signal.org', label: 'Storage', description: 'Encrypted account storage', provisioning: false },
  { id: 'cdn', host: 'cdn.signal.org', label: 'CDN 0', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdn2', host: 'cdn2.signal.org', label: 'CDN 2', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdn3', host: 'cdn3.signal.org', label: 'CDN 3', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdsi', host: 'cdsi.signal.org', label: 'Contact discovery', description: 'HTTPS root only; no discovery requests', provisioning: false },
  { id: 'svr2', host: 'svr2.signal.org', label: 'Secure recovery 2', description: 'HTTPS root only; no recovery requests', provisioning: false },
  { id: 'svrb', host: 'svrb.signal.org', label: 'Secure recovery B', description: 'HTTPS root only; no recovery requests', provisioning: false },
]);
const hosts = new Set(SIGNAL_ENDPOINTS.map(endpoint => endpoint.host));
const provisioningHosts = new Set(SIGNAL_ENDPOINTS.filter(endpoint => endpoint.provisioning).map(endpoint => endpoint.host));
export const TRUST_POLICY = 'TLS and certificate validation are managed by the browser. Static pages cannot open raw TCP sockets, override certificate trust, or perform an independent TLS handshake.';
const PROVISIONING_PATH = '/v1/websocket/provisioning/';

function detail(error) {
  if (error instanceof Error) return error.message;
  return String(error ?? 'Unknown error');
}

function validateHost(host) {
  if (!hosts.has(host)) throw new Error('Only the bundled Signal service endpoints are allowed');
  return host;
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
    const summary = timedOut ? 'No result within timeout' : outcome === 'cancelled' ? 'Probe cancelled' : text;
    emit(outcome === 'cancelled' ? 'info' : 'error', summary);
    return {
      ok: false, status: outcome, outcome, summary,
      details: { phase, error: text, ...evidence,
        interpretation: 'The browser cannot distinguish certificate, DNS, network, Origin, or CORS failures. This is not evidence that Signal itself is offline.' },
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

export function runProbe(options) {
  const probes = {https: probeDirectHttps, 'direct-https': probeDirectHttps, websocket: probeDirectWebSocket, 'direct-websocket': probeDirectWebSocket};
  const probe = probes[options.mode];
  if (!probe) return Promise.resolve({ok:false, status:'failure', outcome:'failure', summary:'Unsupported browser diagnostic mode', details:{}, durationMs:0, events:[]});
  return probe(options);
}
