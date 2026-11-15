// Minimal RFC 6455 transport on a verified Epoxy TLS stream. This deliberately
// avoids Epoxy's separate WebSocket sender, which stalled in browser fixtures.
// https://www.rfc-editor.org/rfc/rfc6455 (sections 4.1, 5, 7)
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_HEADER = 16384;
const MAX_MESSAGE = 1024 * 1024;
const RESERVED = new Set(['host', 'connection', 'upgrade', 'sec-websocket-key',
  'sec-websocket-version', 'sec-websocket-protocol', 'sec-websocket-extensions']);
const bytes = data => data instanceof Uint8Array ? data : data instanceof ArrayBuffer
  ? new Uint8Array(data) : ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : null;
const base64 = value => btoa(String.fromCharCode(...value));
const abortReason = signal => signal?.reason ?? new DOMException('Connection cancelled', 'AbortError');

function frame(opcode, data) {
  const extra = data.length < 126 ? 0 : data.length < 65536 ? 2 : 8;
  const output = new Uint8Array(2 + extra + 4 + data.length);
  output[0] = 0x80 | opcode;
  output[1] = 0x80 | (extra === 0 ? data.length : extra === 2 ? 126 : 127);
  const view = new DataView(output.buffer);
  if (extra === 2) view.setUint16(2, data.length);
  if (extra === 8) view.setBigUint64(2, BigInt(data.length));
  const mask = crypto.getRandomValues(new Uint8Array(4));
  output.set(mask, 2 + extra);
  for (let i = 0; i < data.length; i++) output[6 + extra + i] = data[i] ^ mask[i % 4];
  return output;
}

function closePayload(code, reason) {
  const text = encoder.encode(reason);
  if (text.length > 123) throw new Error('WebSocket close reason is too long');
  if (!Number.isInteger(code) || !((code >= 1000 && code <= 1014 && ![1004, 1005, 1006].includes(code)) ||
    (code >= 3000 && code < 5000)))
    throw new Error('Invalid WebSocket close code');
  const data = new Uint8Array(2 + text.length);
  new DataView(data.buffer).setUint16(0, code);
  data.set(text, 2);
  return data;
}

export async function openSignalWebSocket(client, input, {
  signal, headers = {}, onMessage = () => {}, onClose = () => {},
  timeoutMs = 15000, maxMessage = MAX_MESSAGE,
} = {}) {
  const url = new URL(input);
  if (url.protocol !== 'wss:' || url.username || url.password || url.hash)
    throw new Error('Signal WebSocket requires a WSS URL without credentials or fragment');
  if (!Number.isInteger(maxMessage) || maxMessage < 1 || maxMessage > MAX_MESSAGE)
    throw new Error('Invalid WebSocket message bound');
  const custom = [];
  for (const [name, value] of Object.entries(headers)) {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || RESERVED.has(name.toLowerCase()) ||
      typeof value !== 'string' || /[^\x20-\x7e]/.test(value))
      throw new Error('Invalid or reserved WebSocket header');
    custom.push(`${name}: ${value}\r\n`);
  }
  signal?.throwIfAborted();
  let reader, writer, finished = false, upgraded = false, pending = new Uint8Array(), writes = Promise.resolve(), queuedWrites = 0;
  let settleClosed, rejectStopped;
  const closed = new Promise(resolve => { settleClosed = resolve; });
  const stopped = new Promise((_resolve, reject) => { rejectStopped = reject; });
  stopped.catch(() => {});
  const finish = (code = 1006, reason = 'Connection closed', error) => {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
    rejectStopped(error ?? new Error(reason));
    try { reader?.cancel().catch(() => {}); } catch {}
    try { writer?.abort().catch(() => {}); } catch {}
    const result = { code, reason, ...(error ? { error } : {}) };
    settleClosed(result);
    try { onClose(result); } catch { /* UI callbacks cannot hold sockets open. */ }
  };
  const abort = () => finish(1006, 'Connection cancelled', abortReason(signal));
  const timer = setTimeout(() => finish(1006, 'WebSocket upgrade timed out',
    new DOMException('WebSocket upgrade timed out', 'TimeoutError')), Math.min(30000, Math.max(1000, timeoutMs)));
  signal?.addEventListener('abort', abort, { once: true });
  const race = promise => Promise.race([promise, stopped]);
  const write = payload => {
    if (queuedWrites + payload.length > Math.max(MAX_HEADER, maxMessage * 2)) return Promise.reject(new Error('WebSocket write queue limit exceeded'));
    queuedWrites += payload.length;
    writes = writes.then(() => {
      if (finished) throw new Error('WebSocket is closed');
      return writer.write(payload);
    }).finally(() => { queuedWrites -= payload.length; });
    writes.catch(() => {});
    return race(writes);
  };
  async function readAtLeast(length) {
    while (pending.length < length) {
      const { done, value } = await race(reader.read());
      if (done) throw new Error('Unexpected EOF in Signal WebSocket stream');
      const chunk = bytes(value);
      if (!chunk || pending.length + chunk.length > maxMessage + MAX_HEADER)
        throw new Error('WebSocket receive buffer limit exceeded');
      const next = new Uint8Array(pending.length + chunk.length);
      next.set(pending); next.set(chunk, pending.length); pending = next;
    }
  }
  function take(length) {
    const value = pending.slice(0, length);
    pending = pending.slice(length);
    return value;
  }
  try {
    const connection = Promise.resolve(client.connect_tls(`${url.hostname}:${url.port || 443}`));
    connection.then(stream => {
      if (finished) {
        stream.read.cancel().catch(() => {}); stream.write.abort().catch(() => {});
      }
    }, () => {});
    const stream = await race(connection);
    reader = stream.read.getReader(); writer = stream.write.getWriter();
    const key = base64(crypto.getRandomValues(new Uint8Array(16)));
    const expectedAccept = base64(new Uint8Array(await crypto.subtle.digest('SHA-1', encoder.encode(key + GUID))));
    const request = `GET ${url.pathname || '/'}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n${custom.join('')}\r\n`;
    if (encoder.encode(request).length > MAX_HEADER) throw new Error('WebSocket request headers too large');
    await write(encoder.encode(request));
    let boundary = -1;
    while (boundary < 0) {
      await readAtLeast(pending.length + 1);
      for (let i = 0; i + 3 < pending.length; i++) {
        if (pending[i] === 13 && pending[i + 1] === 10 && pending[i + 2] === 13 && pending[i + 3] === 10) {
          boundary = i + 4; break;
        }
      }
      if ((boundary < 0 && pending.length > MAX_HEADER) || boundary > MAX_HEADER)
        throw new Error('WebSocket response headers too large');
    }
    const lines = decoder.decode(take(boundary)).split('\r\n');
    if (!/^HTTP\/1\.1 101(?: |$)/.test(lines.shift())) throw new Error('Signal WebSocket upgrade was rejected');
    const received = new Map();
    for (const line of lines) {
      if (!line) continue;
      const colon = line.indexOf(':');
      if (colon < 1 || /^[ \t]/.test(line)) throw new Error('Malformed WebSocket upgrade headers');
      const name = line.slice(0, colon).toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (received.has(name)) throw new Error('Duplicate WebSocket upgrade header');
      received.set(name, value);
    }
    if (received.get('upgrade')?.toLowerCase() !== 'websocket' ||
      !received.get('connection')?.toLowerCase().split(',').map(x => x.trim()).includes('upgrade') ||
      received.get('sec-websocket-accept') !== expectedAccept || received.has('sec-websocket-extensions') ||
      received.has('sec-websocket-protocol')) throw new Error('Invalid Signal WebSocket upgrade response');
    clearTimeout(timer); upgraded = true;
    const socket = {
      closed,
      send(data) {
        if (!upgraded || finished) return Promise.reject(new Error('WebSocket is closed'));
        const payload = typeof data === 'string' ? encoder.encode(data) : bytes(data);
        if (!payload || payload.length > maxMessage) return Promise.reject(new Error('Invalid or oversized WebSocket message'));
        return write(frame(typeof data === 'string' ? 1 : 2, payload));
      },
      async close(code = 1000, reason = 'Link session ended') {
        if (finished) return closed;
        const payload = closePayload(code, reason);
        let deadline;
        try { await Promise.race([write(frame(8, payload)), new Promise(resolve => {
          deadline = setTimeout(resolve, 250);
        })]); } catch {} finally { clearTimeout(deadline); }
        finish(code, reason);
        return closed;
      },
    };
    void (async () => {
      let opcode, fragments = [], length = 0, frameCount = 0;
      try {
        while (!finished) {
          if (++frameCount > 4096) throw new Error('WebSocket session frame limit exceeded');
          await readAtLeast(2);
          const first = pending[0], second = pending[1];
          const final = !!(first & 0x80), kind = first & 15;
          if (first & 0x70 || second & 0x80 || ![0, 1, 2, 8, 9, 10].includes(kind))
            throw new Error('Invalid server WebSocket frame');
          let size = second & 127, header = 2;
          if (size === 126) {
            await readAtLeast(4); header = 4;
            size = new DataView(pending.buffer, pending.byteOffset).getUint16(2);
            if (size < 126) throw new Error('Noncanonical WebSocket frame length');
          } else if (size === 127) {
            await readAtLeast(10); header = 10;
            const big = new DataView(pending.buffer, pending.byteOffset).getBigUint64(2);
            if (big < 65536n || big > BigInt(maxMessage)) throw new Error('Invalid WebSocket frame length');
            size = Number(big);
          }
          if (size > maxMessage || (kind >= 8 && (!final || size > 125)))
            throw new Error('Oversized or fragmented WebSocket control frame');
          await readAtLeast(header + size); take(header); const payload = take(size);
          if (kind === 8) {
            if (payload.length === 1) throw new Error('Invalid WebSocket close frame');
            const code = payload.length ? new DataView(payload.buffer).getUint16(0) : 1000;
            const reason = payload.length ? decoder.decode(payload.subarray(2)) : 'Peer closed';
            if (payload.length) closePayload(code, reason);
            try { await write(frame(8, payload)); } catch {}
            finish(code, reason); return;
          }
          if (kind === 9) { await write(frame(10, payload)); continue; }
          if (kind === 10) continue;
          if (kind === 0 ? opcode === undefined : opcode !== undefined)
            throw new Error('Invalid WebSocket continuation sequence');
          if (kind) opcode = kind;
          length += payload.length;
          if (length > maxMessage) throw new Error('WebSocket message limit exceeded');
          fragments.push(payload);
          if (fragments.length > 1024) throw new Error('WebSocket fragment limit exceeded');
          if (final) {
            const message = new Uint8Array(length);
            let offset = 0;
            for (const fragment of fragments) { message.set(fragment, offset); offset += fragment.length; }
            await onMessage(opcode === 1 ? decoder.decode(message) : message);
            opcode = undefined; fragments = []; length = 0;
          }
        }
      } catch (error) { finish(1006, 'Signal WebSocket stream failed', error); }
    })();
    return socket;
  } catch (error) {
    finish(1006, 'Signal WebSocket could not open', error);
    throw error;
  }
}
