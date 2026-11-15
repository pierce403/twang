import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createWebSocketTransport, PROXY_ENDPOINT, PROXY_PROTOCOL, probeProxyTls } from '../app/proxy-transport.mjs';

function frame(type, id, body = []) {
  const bytes = new Uint8Array(5 + body.length);
  bytes[0] = type;
  new DataView(bytes.buffer).setUint32(1, id, true);
  bytes.set(body, 5);
  return bytes;
}
function connect(host = 'chat.signal.org', port = 443) {
  return frame(1, 1, [1, port & 255, port >> 8, ...new TextEncoder().encode(host)]);
}
class Socket extends EventTarget {
  static created = [];
  constructor(url, protocol) {
    super();
    this.url = url; this.protocol = protocol; this.bufferedAmount = 0;
    this.readyState = 0; this.sent = [];
    Socket.created.push(this);
    queueMicrotask(() => { if (this.readyState !== 0) return;
      this.readyState = 1; this.dispatchEvent(new Event('open')); });
  }
  send(data) { this.sent.push(new Uint8Array(data)); }
  close() { this.readyState = 3; this.dispatchEvent(new Event('close')); }
}
async function setup(t, options = {}) {
  Socket.created = [];
  const transport = createWebSocketTransport({ WebSocketImpl: Socket, ...options });
  const { read, write } = await transport();
  const reader = read.getReader();
  reader.closed.catch(() => {});
  const writer = write.getWriter();
  writer.closed.catch(() => {});
  t.after(() => transport.close());
  return { reader, writer, transport };
}
test('fixed endpoint negotiates raw TLS protocol and never forwards Wisp CONNECT', async t => {
  const { reader, writer } = await setup(t);
  assert.equal(new Uint8Array((await reader.read()).value)[0], 3);
  await writer.write(connect());
  const socket = Socket.created[0];
  assert.equal(socket.url, PROXY_ENDPOINT);
  assert.equal(socket.protocol, PROXY_PROTOCOL);
  assert.equal(socket.sent.length, 0);
  const payload = new Uint8Array([0x16, 3, 3, 0, 1, 8]);
  await writer.write(frame(2, 1, payload));
  assert.deepEqual(socket.sent[0], payload);
  const incoming = new Event('message');
  incoming.data = payload.buffer;
  socket.dispatchEvent(incoming);
  assert.deepEqual(new Uint8Array((await reader.read()).value), frame(2, 1, payload));
});
test('destination allowlist and TLS-only port are checked before WebSocket creation', async t => {
  for (const destination of [connect('example.com'), connect('chat.signal.org', 80)]) {
    const { writer } = await setup(t);
    await assert.rejects(writer.write(destination), /allowlisted Signal/);
    assert.equal(Socket.created.length, 0);
  }
});
test('oversized TLS writes split into bounded binary frames with no extra bytes', async t => {
  const { writer } = await setup(t);
  await writer.write(connect());
  const payload = new Uint8Array(128 * 1024).map((_, index) => index % 251);
  await writer.write(frame(2, 1, payload));
  const chunks = Socket.created[0].sent;
  assert.equal(chunks.length, 8);
  assert.ok(chunks.every(chunk => chunk.length === 16384));
  assert.deepEqual(Uint8Array.from(chunks.flatMap(chunk => [...chunk])), payload);
});
test('text and oversized incoming frames close transport', async t => {
  for (const data of ['invalid', new ArrayBuffer(65537)]) {
    const { writer, reader } = await setup(t);
    await reader.read();
    await writer.write(connect());
    const incoming = new Event('message'); incoming.data = data;
    Socket.created[0].dispatchEvent(incoming);
    await assert.rejects(reader.read(), /non-binary or oversized/);
    assert.equal(Socket.created[0].readyState, 3);
  }
});
test('receive queues are bounded when consumer stops reading', async t => {
  const { writer, reader } = await setup(t);
  await reader.read();
  await writer.write(connect());
  const socket = Socket.created[0];
  for (let i = 0; i < 17; i++) {
    const incoming = new Event('message'); incoming.data = new ArrayBuffer(65536);
    socket.dispatchEvent(incoming);
  }
  await assert.rejects(reader.read(), /receive buffer limit/);
  assert.equal(socket.readyState, 3);
});
test('abort closes open tunnel and rejects further input', async t => {
  const controller = new AbortController();
  const { writer, reader } = await setup(t, { signal: controller.signal });
  await reader.read();
  await writer.write(connect());
  controller.abort(new Error('cancelled'));
  await assert.rejects(reader.read(), /cancelled/);
  await assert.rejects(writer.write(frame(2, 1, [7])), /cancelled/);
  assert.equal(Socket.created[0].readyState, 3);
});
test('production probe rejects unknown target before loading WASM or networking', async () => {
  const result = await probeProxyTls({ host: 'example.com' });
  assert.equal(result.ok, false);
  assert.match(result.summary, /Only bundled Signal/);
});
test('proxy endpoints reject plaintext remote URLs and embedded credentials', () => {
  for (const endpoint of ['ws://example.com/v1/tls-tunnel', 'wss://user:pass@example.com/x', 'wss://example.com/x?target=host'])
    assert.throws(() => createWebSocketTransport({ endpoint }), /WSS endpoint/);
});
test('missing negotiated protocol fails closed and closes socket', async t => {
  class Unversioned extends Socket { constructor(...args) { super(...args); this.protocol = ''; } }
  const { writer, reader } = await setup(t, { WebSocketImpl: Unversioned });
  await reader.read();
  await assert.rejects(writer.write(connect()), /did not negotiate/);
  await assert.rejects(reader.read(), /did not negotiate/);
  assert.equal(Socket.created[0].readyState, 3);
});
test('pre-cancelled transport never opens a connection', async () => {
  const controller = new AbortController(); controller.abort(new Error('cancelled'));
  Socket.created = [];
  const transport = createWebSocketTransport({ signal: controller.signal, WebSocketImpl: Socket });
  await assert.rejects(transport(), /cancelled/);
  assert.equal(Socket.created.length, 0);
});
