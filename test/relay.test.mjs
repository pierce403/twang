import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { WebSocket } from 'ws';
import { createRelayServer, packet, isPublicAddress, SIGNAL_HOSTS } from '../relay/server.mjs';

const ORIGIN = 'http://localhost:5173';
async function until(predicate) {
  const deadline = Date.now() + 2000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('Timed out waiting for local test event');
    await new Promise(resolve => setImmediate(resolve));
  }
}
class FakeSocket extends EventEmitter {
  constructor({ autoDrain = true } = {}) {
    super();
    this.writes = [];
    this.callbacks = [];
    this.destroyed = false;
    this.autoDrain = autoDrain;
    queueMicrotask(() => { if (!this.destroyed) this.emit('connect'); });
  }
  setNoDelay() {}
  setTimeout() {}
  write(bytes, callback) {
    this.writes.push(Buffer.from(bytes));
    if (this.autoDrain) queueMicrotask(() => callback());
    else this.callbacks.push(callback);
    return false;
  }
  drain() { for (const callback of this.callbacks.splice(0)) callback(); }
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    queueMicrotask(() => this.emit('close', false));
  }
}
function connectPacket(id, host = 'chat.signal.org', port = 443, type = 1) {
  const bytes = Buffer.alloc(3 + Buffer.byteLength(host));
  bytes[0] = type;
  bytes.writeUInt16LE(port, 1);
  bytes.write(host, 3);
  return packet(1, id, bytes);
}
async function fixture(t, options = {}) {
  const sockets = [];
  const destinations = [];
  const relay = createRelayServer({
    connect: destination => {
      destinations.push(destination);
      const socket = new FakeSocket(options.fakeOptions);
      sockets.push(socket);
      return socket;
    },
    ...options,
  });
  const address = await relay.listen(0);
  const url = `ws://127.0.0.1:${address.port}/wisp/`;
  t.after(() => relay.close());
  return { relay, sockets, destinations, url, address };
}
async function peer(t, url, origin = ORIGIN) {
  const socket = new WebSocket(url, { origin });
  const inbox = [];
  const waiting = [];
  socket.on('message', data => {
    const bytes = Buffer.from(data);
    if (waiting.length) waiting.shift()(bytes);
    else inbox.push(bytes);
  });
  const next = () => inbox.length ? Promise.resolve(inbox.shift()) : new Promise(resolve => waiting.push(resolve));
  await once(socket, 'open');
  t.after(() => socket.terminate());
  return { socket, next };
}

test('relay starts with Wisp v1 credits and forwards opaque TLS bytes unchanged', async t => {
  const { url, sockets, destinations } = await fixture(t);
  const { socket, next } = await peer(t, url);
  const hello = await next();
  assert.equal(hello[0], 3);
  assert.equal(hello.readUInt32LE(1), 0);
  assert.equal(hello.readUInt32LE(5), 64);
  socket.send(connectPacket(1));
  const encrypted = Buffer.from([0x16, 0x03, 0x03, 0, 4, 7, 8, 9, 10]);
  socket.send(packet(2, 1, encrypted));
  await until(() => sockets[0]?.writes.length === 1);
  assert.equal(destinations[0].host, 'chat.signal.org');
  assert.equal(destinations[0].port, 443);
  assert.equal(typeof destinations[0].lookup, 'function');
  assert.deepEqual(sockets[0].writes, [encrypted]);
  sockets[0].emit('data', encrypted);
  const returned = await next();
  assert.equal(returned[0], 2);
  assert.equal(returned.readUInt32LE(1), 1);
  assert.deepEqual(returned.subarray(5), encrypted);
});

test('host, port and UDP allowlist rejections never create an outbound socket', async t => {
  const { url, destinations } = await fixture(t);
  const { socket, next } = await peer(t, url);
  await next();
  for (const [id, host, port, type] of [
    [1, 'example.com', 443, 1], [2, 'chat.signal.org.evil.test', 443, 1],
    [3, '127.0.0.1', 443, 1], [4, 'chat.signal.org', 80, 1],
    [5, 'chat.signal.org', 443, 2], [6, 'CHAT.signal.org.', 443, 1],
  ]) {
    socket.send(connectPacket(id, host, port, type));
    const result = await next();
    assert.equal(result[0], 4);
    assert.equal(result.readUInt32LE(1), id);
    assert.equal(result[5], 0x48);
  }
  assert.equal(destinations.length, 0);
});

test('private, reserved and mapped DNS destinations are rejected', () => {
  for (const ip of ['127.0.0.1', '10.2.3.4', '172.16.5.2', '192.168.1.1',
    '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '192.0.2.1',
    '::1', '::ffff:127.0.0.1', 'fc00::1', 'fe80::1', '2001:db8::1', 'not-an-ip']) {
    assert.equal(isPublicAddress(ip), false, ip);
  }
  assert.equal(isPublicAddress('13.248.212.111'), true);
  assert.equal(isPublicAddress('2600:9000:a507:ab6d:4ce3:2f58:25d7:9cbf'), true);
  assert.ok(SIGNAL_HOSTS.includes('grpc.chat.signal.org'));
});

test('unapproved and missing browser Origin cannot upgrade', async t => {
  const { url, destinations } = await fixture(t);
  for (const origin of ['https://evil.example', undefined]) {
    const socket = new WebSocket(url, origin ? { origin } : {});
    await assert.rejects(once(socket, 'open'), /403/);
  }
  assert.equal(destinations.length, 0);
});

test('malformed binary packets close the websocket and clean up TCP streams', async t => {
  const { url, sockets } = await fixture(t);
  const { socket, next } = await peer(t, url);
  await next();
  socket.send(connectPacket(1));
  await until(() => sockets.length === 1);
  const closed = once(socket, 'close');
  socket.send(Buffer.from([1, 2]));
  const [code] = await closed;
  assert.equal(code, 1002);
  assert.equal(sockets[0].destroyed, true);
});

test('malformed CONNECT is refused without dialing', async t => {
  const { url, destinations } = await fixture(t);
  const { socket, next } = await peer(t, url);
  await next();
  socket.send(packet(1, 1, Buffer.from([1, 187, 1, 0xff])));
  const invalid = await next();
  assert.equal(invalid[0], 4);
  assert.equal(invalid[5], 0x41);
  assert.equal(destinations.length, 0);
});

test('flow control replenishes only after a full window has drained', async t => {
  const { url, sockets } = await fixture(t, { windowSize: 2, fakeOptions: { autoDrain: false } });
  const { socket, next } = await peer(t, url);
  assert.equal((await next()).readUInt32LE(5), 2);
  socket.send(connectPacket(7));
  socket.send(packet(2, 7, Buffer.from('a')));
  socket.send(packet(2, 7, Buffer.from('b')));
  await until(() => sockets[0]?.writes.length === 2);
  assert.deepEqual(sockets[0].writes.map(bytes => bytes.toString()), ['a', 'b']);
  sockets[0].drain();
  const refill = await next();
  assert.equal(refill[0], 3);
  assert.equal(refill.readUInt32LE(1), 7);
  assert.equal(refill.readUInt32LE(5), 2);
  socket.send(packet(2, 7, Buffer.from('c')));
  await until(() => sockets[0]?.writes.length === 3);
  assert.equal(sockets[0].writes[2].toString(), 'c');
});

test('a peer exceeding its advertised window is disconnected from the destination', async t => {
  const { url, sockets } = await fixture(t, { windowSize: 1, fakeOptions: { autoDrain: false } });
  const { socket, next } = await peer(t, url);
  await next();
  socket.send(connectPacket(1));
  socket.send(packet(2, 1, Buffer.from('first')));
  socket.send(packet(2, 1, Buffer.from('over-credit')));
  const result = await next();
  assert.equal(result[0], 4);
  assert.equal(result[5], 0x49);
  assert.equal(sockets[0].writes.length, 1);
  assert.equal(sockets[0].destroyed, true);
});

test('stream count cap refuses extra streams and client CLOSE destroys its socket', async t => {
  const { url, sockets } = await fixture(t, { maxStreams: 1 });
  const { socket, next } = await peer(t, url);
  await next();
  socket.send(connectPacket(1));
  socket.send(connectPacket(2));
  assert.equal((await next())[5], 0x49);
  assert.equal(sockets.length, 1);
  socket.send(packet(4, 1, Buffer.from([2])));
  await until(() => sockets[0]?.destroyed);
  assert.equal(sockets[0].destroyed, true);
});

test('text frames and unsupported client packet types are rejected', async t => {
  const { url } = await fixture(t);
  for (const [payload, expected] of [['not binary', 1003], [packet(3, 1, Buffer.alloc(4)), 1002]]) {
    const { socket, next } = await peer(t, url);
    await next();
    const closed = once(socket, 'close');
    socket.send(payload);
    assert.equal((await closed)[0], expected);
  }
});

test('health reports restricted byte relay and permits only configured browser origins', async t => {
  const { address } = await fixture(t);
  const url = `http://127.0.0.1:${address.port}/health`;
  const response = await fetch(url, { headers: { Origin: ORIGIN } });
  assert.equal(response.headers.get('access-control-allow-origin'), ORIGIN);
  const result = await response.json();
  assert.equal(result.tlsTermination, false);
  assert.equal(result.port, 443);
  assert.deepEqual(result.hosts, SIGNAL_HOSTS);
  assert.equal((await fetch(url, { headers: { Origin: 'https://evil.example' } })).status, 403);
});
