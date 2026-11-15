export const SIGNAL_ENDPOINTS = Object.freeze([
  { id: 'chat', host: 'chat.signal.org', label: 'Chat', description: 'Signal chat service', provisioning: true },
  { id: 'grpc', host: 'grpc.chat.signal.org', label: 'Chat / HTTP 2', description: 'Current native chat transport', provisioning: false },
  { id: 'storage', host: 'storage.signal.org', label: 'Storage', description: 'Encrypted account storage', provisioning: false },
  { id: 'cdn', host: 'cdn.signal.org', label: 'CDN 0', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdn2', host: 'cdn2.signal.org', label: 'CDN 2', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdn3', host: 'cdn3.signal.org', label: 'CDN 3', description: 'Encrypted attachments', provisioning: false },
  { id: 'cdsi', host: 'cdsi.signal.org', label: 'Contact discovery', description: 'HTTPS root only; no discovery requests', provisioning: false },
  { id: 'svr2', host: 'svr2.signal.org', label: 'Secure recovery 2', description: 'HTTPS root only; no recovery requests', provisioning: false },
  { id: 'svrb', host: 'svrb.signal.org', label: 'Secure recovery B', description: 'HTTPS root only; no recovery requests', provisioning: false },
]);
export const TRUST_POLICY = 'The browser validates the outer WebSocket TLS to proxy.twang.chat. WebAssembly validates the inner Signal TLS certificate and hostname. The proxy forwards encrypted bytes and sees connection metadata, but does not receive Signal TLS keys. Diagnostics create no account or device link.';

function detail(error) {
  if (error instanceof Error) return error.message;
  return String(error ?? 'Unknown error');
}

export async function bounded(options, work) {
  const start = performance.now();
  const events = [];
  const evidence = {};
  const cleanups = [];
  const controller = new AbortController();
  const timeoutMs = Number(options.timeoutMs ?? 10000);
  const limit = Number.isFinite(timeoutMs) ? Math.max(1000, Math.min(timeoutMs, 30000)) : 10000;
  let phase = 'setup';
  let timedOut = false;
  let finalized = false;
  const cleanup = fn => {
    try { Promise.resolve(fn()).catch(() => {}); } catch { /* Best-effort teardown. */ }
  };
  const emit = (level, message, extra = {}) => {
    if (controller.signal.aborted || finalized) return;
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
    defer(fn) { if (finalized) cleanup(fn); else cleanups.push(fn); },
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
        interpretation: phase === 'proxy-websocket' ? 'The browser hides outer WebSocket network and certificate failure details. This is not evidence that Signal itself is offline.' : 'This probe did not establish the requested transport. Inspect the recorded phase and error; a failure does not prove Signal is offline.' },
      durationMs: Math.round(performance.now() - start), events,
    };
  } finally {
    finalized = true;
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', externalAbort);
    controller.signal.removeEventListener('abort', abortListener);
    for (const fn of cleanups.reverse()) cleanup(fn);
  }
}
