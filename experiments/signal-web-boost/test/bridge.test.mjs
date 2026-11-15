import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import WebSocket, { createWebSocketStream } from 'ws';
import { createBridge } from '../server.mjs';

async function setup(t, options = {}, onConnection = s => s.pipe(s)) {
  const upstream = net.createServer(onConnection);
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const bridge = createBridge({ host: '127.0.0.1', port: upstream.address().port, ...options });
  await new Promise(resolve => bridge.server.listen(0, '127.0.0.1', resolve));
  const port = bridge.server.address().port;
  t.after(async () => { await bridge.close(); await new Promise(r => upstream.close(r)); });
  return { port, bridge };
}
function websocket(port, path = '/v1/tls-tunnel', protocols = ['signal-tls-v1']) {
  return new WebSocket(`ws://127.0.0.1:${port}${path}`, protocols);
}
test('native TLS records survive fragmented initial reads byte for byte', { timeout: 3000 }, async t => {
  const { port } = await setup(t);
  const socket = net.connect(port, '127.0.0.1');
  t.after(() => socket.destroy());
  await once(socket, 'connect');
  const payload = Buffer.from([0x16, 3, 3, 0, 4, 1, 2, 3, 4]);
  const received = [];
  socket.on('data', data => received.push(data));
  socket.write(payload.subarray(0, 1));
  await once(socket, 'data');
  const next = once(socket, 'data');
  socket.write(payload.subarray(1));
  await next;
  assert.deepEqual(Buffer.concat(received), payload);
});
test('browser binary frames unwrap to a fixed upstream stream', { timeout: 3000 }, async t => {
  const { port } = await setup(t);
  const ws = websocket(port);
  t.after(() => ws.terminate());
  await once(ws, 'open');
  assert.equal(ws.protocol, 'signal-tls-v1');
  const payload = Buffer.from([0x16, 3, 3, 0, 4, 0, 255, 7, 8]);
  const reply = once(ws, 'message');
  ws.send(payload);
  const [actual, binary] = await reply;
  assert.equal(binary, true);
  assert.deepEqual(actual, payload);
});
test('wrong path, target query, and missing protocol are rejected', { timeout: 3000 }, async t => {
  const { port } = await setup(t);
  for (const [path, protocols] of [['/else', ['signal-tls-v1']],
    ['/v1/tls-tunnel?host=example.com', ['signal-tls-v1']], ['/v1/tls-tunnel', []]]) {
    const ws = websocket(port, path, protocols);
    const error = await new Promise(resolve => ws.once('error', resolve));
    assert.match(error.message, /400/);
  }
});
test('text and oversized frames close the tunnel', { timeout: 3000 }, async t => {
  const { port } = await setup(t);
  for (const payload of ['not binary', Buffer.alloc(65537)]) {
    const ws = websocket(port);
    await once(ws, 'open');
    const closed = once(ws, 'close');
    ws.send(payload);
    await closed;
  }
});
test('slow prefaces time out and release sessions', { timeout: 3000 }, async t => {
  const { port } = await setup(t, { handshakeTimeout: 50, maxSessions: 1 });
  const socket = net.connect(port, '127.0.0.1');
  await once(socket, 'connect');
  await once(socket, 'close');
  const ws = websocket(port);
  await once(ws, 'open');
  ws.terminate();
});
test('upstream failure closes browser connection', { timeout: 3000 }, async t => {
  const { port } = await setup(t, {}, socket => socket.destroy());
  const ws = websocket(port);
  await once(ws, 'open');
  await once(ws, 'close');
});
test('session cap and invalid prefaces fail closed', { timeout: 3000 }, async t => {
  const { port } = await setup(t, { maxSessions: 1 });
  const first = net.connect(port, '127.0.0.1');
  t.after(() => first.destroy());
  await once(first, 'connect');
  const second = net.connect(port, '127.0.0.1');
  await once(second, 'close');
  const closed = once(first, 'close');
  first.write('POST / HTTP/1.1\r\n\r\n');
  await closed;
});
test('HTTP headers are size bounded', { timeout: 3000 }, async t => {
  const { port } = await setup(t);
  const socket = net.connect(port, '127.0.0.1');
  socket.resume();
  await once(socket, 'connect');
  const closed = once(socket, 'close');
  socket.write('GET /v1/tls-tunnel HTTP/1.1\r\nX-Test: ' + 'x'.repeat(9000) + '\r\n\r\n');
  await closed;
});
test('TLS in browser role validates endpoint through opaque WS bridge', { timeout: 5000 }, async t => {
  const dir = mkdtempSync(join(tmpdir(), 'twang-bridge-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  const cert = readFileSync(join(dir, 'cert.pem'));
  const endpoint = tls.createServer({ key: readFileSync(join(dir, 'key.pem')), cert }, s => s.pipe(s));
  await new Promise(resolve => endpoint.listen(0, '127.0.0.1', resolve));
  const bridge = createBridge({ host: '127.0.0.1', port: endpoint.address().port });
  await new Promise(resolve => bridge.server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await bridge.close(); await new Promise(r => endpoint.close(r)); });
  const native = tls.connect({ host: '127.0.0.1', port: bridge.server.address().port,
    servername: 'localhost', ca: cert });
  await once(native, 'secureConnect');
  assert.equal(native.authorized, true);
  native.destroy();
  const ws = websocket(bridge.server.address().port);
  await once(ws, 'open');
  const stream = createWebSocketStream(ws);
  const secured = tls.connect({ socket: stream, servername: 'localhost', ca: cert });
  secured.on('error', () => {});
  t.after(() => secured.destroy());
  await once(secured, 'secureConnect');
  assert.equal(secured.authorized, true);
  const reply = once(secured, 'data');
  secured.write('inner TLS remains end to end');
  assert.equal((await reply)[0].toString(), 'inner TLS remains end to end');
  secured.destroy();
  const badWs = websocket(bridge.server.address().port);
  await once(badWs, 'open');
  const rejected = tls.connect({ socket: createWebSocketStream(badWs), servername: 'localhost' });
  const error = await new Promise(resolve => rejected.once('error', resolve));
  assert.match(error.message, /self.signed certificate/i);
  rejected.destroy();
});
