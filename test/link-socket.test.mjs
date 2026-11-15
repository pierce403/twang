import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import { Duplex } from 'node:stream';
import { once } from 'node:events';
import { openSignalWebSocket } from '../app/link-socket.mjs';
import { startFixtures } from './e2e/fixtures.mjs';

const encode = text => new TextEncoder().encode(text);
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
function serverFrame(opcode, payload = new Uint8Array(), final = true) {
  const data = typeof payload === 'string' ? encode(payload) : payload;
  const extra = data.length < 126 ? 0 : data.length < 65536 ? 2 : 8;
  const frame = new Uint8Array(2 + extra + data.length);
  frame[0] = (final ? 128 : 0) | opcode; frame[1] = extra ? extra === 2 ? 126 : 127 : data.length;
  if (extra === 2) new DataView(frame.buffer).setUint16(2, data.length);
  if (extra === 8) new DataView(frame.buffer).setBigUint64(2, BigInt(data.length));
  frame.set(data, 2 + extra); return frame;
}
function clientPayload(frame) {
  let length = frame[1] & 127, offset = 2;
  assert.ok(frame[1] & 128, 'Client frames must be masked');
  if (length === 126) { length = new DataView(frame.buffer).getUint16(2); offset = 4; }
  if (length === 127) { length = Number(new DataView(frame.buffer).getBigUint64(2)); offset = 10; }
  const mask = frame.subarray(offset, offset + 4);
  return Uint8Array.from(frame.subarray(offset + 4), (value, index) => value ^ mask[index % 4]);
}
function fixture(response) {
  let controller, request;
  const sent = [];
  const client = { async connect_tls(authority) {
    assert.equal(authority, 'chat.signal.org:443');
    return {
      read: new ReadableStream({ start(value) { controller = value; } }),
      write: new WritableStream({ write(data) {
        if (!request) {
          request = new TextDecoder().decode(data);
          const key = request.match(/Sec-WebSocket-Key: (.+)\r\n/)[1];
          const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
          const normal = `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`;
          controller.enqueue(encode(response ? response(normal) : normal));
        } else sent.push(new Uint8Array(data));
      } }),
    };
  } };
  return { client, sent, push: value => controller.enqueue(value), get request() { return request; } };
}

test('raw socket validates upgrade and sends masked binary ACK frames', async t => {
  const f = fixture();
  const socket = await openSignalWebSocket(f.client, 'wss://chat.signal.org/v1/websocket/provisioning/', {
    headers: { Authorization: 'Basic local-fixture-only' },
  });
  t.after(() => socket.close());
  assert.match(f.request, /^GET \/v1\/websocket\/provisioning\/ HTTP\/1.1\r\n/);
  assert.match(f.request, /Authorization: Basic local-fixture-only/);
  const data = new Uint8Array([0, 255, 8, 128]);
  await socket.send(data);
  assert.equal(f.sent[0][0], 0x82); assert.deepEqual(clientPayload(f.sent[0]), data);
  await socket.send('text');assert.equal(f.sent[1][0], 0x81);
});
test('wrong status, wrong accept, extensions and duplicate upgrade headers fail closed', async () => {
  for (const alter of [text => text.replace('101', '200'), text => text.replace(/Accept: [^\r]+/, 'Accept: invalid'),
    text => text.replace('\r\n\r\n', '\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n'),
    text => text.replace('\r\n\r\n', '\r\nUpgrade: websocket\r\n\r\n')]) {
    await assert.rejects(openSignalWebSocket(fixture(alter).client, 'wss://chat.signal.org/'), /upgrade/i);
  }
});
test('fragmented binary messages retain order with interleaved ping and masked pong', async t => {
  const f = fixture(), received = [];
  const socket = await openSignalWebSocket(f.client, 'wss://chat.signal.org/', { onMessage: data => received.push(data) });
  t.after(() => socket.close());
  f.push(serverFrame(2, new Uint8Array([0, 255]), false));
  f.push(serverFrame(9, new Uint8Array([9])));
  f.push(serverFrame(0, new Uint8Array([8, 128])));
  await tick();
  assert.deepEqual(received, [new Uint8Array([0, 255, 8, 128])]);
  assert.equal(f.sent[0][0], 0x8a);assert.deepEqual(clientPayload(f.sent[0]), new Uint8Array([9]));
});
test('malformed masked server frames, continuation, UTF8 and oversized messages close sockets', async () => {
  for (const frame of [new Uint8Array([0x82, 0x80, 0, 0, 0, 0]), serverFrame(0, 'invalid'),
    serverFrame(1, new Uint8Array([0xff])), serverFrame(2, new Uint8Array(17))]) {
    const f = fixture();const socket = await openSignalWebSocket(f.client, 'wss://chat.signal.org/', { maxMessage: 16 });
    f.push(frame);const ended = await socket.closed;
    assert.equal(ended.code, 1006);assert.ok(ended.error);
  }
});
test('abort closes pending reads and rejects further sends', async () => {
  const f = fixture(), abort = new AbortController();let closed = 0;
  const socket = await openSignalWebSocket(f.client, 'wss://chat.signal.org/', { signal: abort.signal, onClose: () => closed++ });
  abort.abort();await socket.closed;
  await assert.rejects(socket.send(new Uint8Array([1])), /closed/);assert.equal(closed, 1);
});
test('reserved or injected headers are rejected before TLS is opened', async () => {
  for (const headers of [{ Host: 'example.com' }, { Authorization: 'x\r\nHost: evil' }, { 'Bad Name': 'x' }]) {
    await assert.rejects(openSignalWebSocket({ connect_tls() { throw Error('Must not connect'); } },
      'wss://chat.signal.org/', { headers }), /header/);
  }
});
test('real certificate-validated TLS fixture upgrades and receives client binary frames', { timeout: 10000 }, async t => {
  const fixtures = await startFixtures();t.after(() => fixtures.close());
  const config = await (await fetch(new URL('config', fixtures.url))).json();
  const clients = new Set();t.after(() => { for (const client of clients) client.destroy(); });
  const client = { async connect_tls(authority) {
    assert.equal(authority, `localhost:${config.tlsPort}`);
    const socket = tls.connect({ host: '127.0.0.1', port: config.tlsPort, ca: config.cert, servername: 'localhost' });
    clients.add(socket); socket.on('error', () => {});socket.once('close', () => clients.delete(socket));
    await once(socket, 'secureConnect');assert.equal(socket.authorized, true);
    const { readable, writable } = Duplex.toWeb(socket);return { read: readable, write: writable };
  } };
  const received = [];let finish;
  const echoed = new Promise(resolve => { finish = resolve; });
  const socket = await openSignalWebSocket(client, `wss://localhost:${config.tlsPort}/v1/websocket/provisioning/`, {
    headers: { 'X-Twang-Fixture': 'browser' }, onMessage: data => { received.push(data);if (received.length === 2) finish(); },
  });
  t.after(() => socket.close());
  const payload = new Uint8Array([8, 200, 0, 255]);await socket.send(payload);
  await echoed;assert.deepEqual(received[1], payload);
  await socket.close();
});
