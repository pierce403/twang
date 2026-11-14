import { createServer } from 'node:http';
import { createConnection, BlockList, isIP } from 'node:net';
import { lookup } from 'node:dns';
import { pathToFileURL } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';

// Signal-only Wisp v1 TCP subset. TLS stays end-to-end in the browser's WASM.
export const SIGNAL_HOSTS = Object.freeze([
  'chat.signal.org', 'grpc.chat.signal.org', 'storage.signal.org',
  'cdn.signal.org', 'cdn2.signal.org', 'cdn3.signal.org',
  'cdsi.signal.org', 'svr2.signal.org', 'svrb.signal.org',
]);
export const DEFAULT_ORIGINS = Object.freeze([
  'https://twang.chat', 'http://localhost:5173', 'http://127.0.0.1:5173',
  'http://localhost:8787', 'http://127.0.0.1:8787',
]);
const BLOCKED = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
  ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
]) BLOCKED.addSubnet(address, prefix, 'ipv4');
const V6_GLOBAL = new BlockList();
V6_GLOBAL.addSubnet('2000::', 3, 'ipv6');
BLOCKED.addSubnet('2001:db8::', 32, 'ipv6');
BLOCKED.addSubnet('2001::', 32, 'ipv6');
BLOCKED.addSubnet('2002::', 16, 'ipv6');

export function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) return !BLOCKED.check(address, 'ipv4');
  if (family === 6) return V6_GLOBAL.check(address, 'ipv6') && !BLOCKED.check(address, 'ipv6');
  return false;
}

// Pin each connection to a validated DNS result. Never allow private, loopback,
// link-local or special-use addresses even if a permitted hostname resolves there.
export function publicLookup(hostname, options, callback) {
  lookup(hostname, { all: true, verbatim: true }, (error, records) => {
    if (error) return callback(error);
    const addresses = records.filter(record => isPublicAddress(record.address));
    if (!addresses.length) return callback(Object.assign(new Error('DNS returned no public address'), { code: 'EPERM' }));
    if (options?.all) return callback(null, addresses);
    const family = options?.family;
    const record = addresses.find(item => !family || item.family === family);
    if (!record) return callback(Object.assign(new Error('No public address for requested family'), { code: 'ENOTFOUND' }));
    callback(null, record.address, record.family);
  });
}

export function packet(type, streamId, payload = Buffer.alloc(0)) {
  const frame = Buffer.allocUnsafe(5 + payload.length);
  frame[0] = type;
  frame.writeUInt32LE(streamId, 1);
  payload.copy(frame, 5);
  return frame;
}
const continuePacket = (id, credits) => {
  const payload = Buffer.allocUnsafe(4);
  payload.writeUInt32LE(credits);
  return packet(3, id, payload);
};
function failureReason(error) {
  return ({ ENOTFOUND: 0x42, EAI_AGAIN: 0x42, ETIMEDOUT: 0x43, ECONNREFUSED: 0x44, EPERM: 0x48 })[error?.code] ?? 0x03;
}

export function createRelayServer({
  origins = DEFAULT_ORIGINS,
  connect = options => createConnection(options),
  windowSize = 64,
  maxConnections = 16,
  maxStreams = 4,
  maxPayload = 64 * 1024,
  maxBufferedBytes = 1024 * 1024,
  connectTimeoutMs = 15_000,
  idleTimeoutMs = 30_000,
  sessionTimeoutMs = 120_000,
} = {}) {
  const allowedOrigins = new Set(origins);
  const allowedHosts = new Set(SIGNAL_HOSTS);
  const server = createServer((request, response) => {
    const origin = request.headers.origin;
    if (origin && !allowedOrigins.has(origin)) {
      response.writeHead(403).end('Origin not allowed');
      return;
    }
    const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
    if (origin) Object.assign(headers, { 'Access-Control-Allow-Origin': origin, Vary: 'Origin' });
    if (request.method === 'GET' && request.url === '/health') {
      response.writeHead(200, headers).end(JSON.stringify({
        service: 'twang-byte-relay', protocol: 'wisp-v1-tcp-subset',
        hosts: SIGNAL_HOSTS, port: 443, tlsTermination: false,
      }));
    } else response.writeHead(404, headers).end(JSON.stringify({ error: 'Not found' }));
  });
  const wss = new WebSocketServer({ noServer: true, maxPayload, perMessageDeflate: false });
  server.on('upgrade', (request, socket, head) => {
    const reject = (status, reason) => socket.end(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    if (request.url !== '/wisp/') return reject(404, 'Not Found');
    if (!allowedOrigins.has(request.headers.origin)) return reject(403, 'Forbidden');
    if (wss.clients.size >= maxConnections) return reject(503, 'Service Unavailable');
    wss.handleUpgrade(request, socket, head, websocket => wss.emit('connection', websocket, request));
  });
  wss.on('connection', websocket => {
    const streams = new Map();
    const send = frame => {
      if (websocket.readyState !== WebSocket.OPEN) return false;
      if (websocket.bufferedAmount > maxBufferedBytes) {
        disconnect(1008, 'Relay receive buffer limit');
        return false;
      }
      websocket.send(frame, { binary: true });
      return true;
    };
    const closeStream = (id, reason, notify = true) => {
      const stream = streams.get(id);
      if (stream) {
        streams.delete(id);
        clearTimeout(stream.timer);
        stream.socket.destroy();
      }
      if (notify) send(packet(4, id, Buffer.from([reason])));
    };
    const closeAll = () => {
      clearTimeout(sessionTimer);
      for (const id of [...streams.keys()]) closeStream(id, 2, false);
    };
    const disconnect = (code, reason) => { closeAll(); websocket.close(code, reason); };
    const sessionTimer = setTimeout(() => disconnect(1008, 'Diagnostic session time limit'), sessionTimeoutMs);
    sessionTimer.unref();
    websocket.on('close', closeAll);
    websocket.on('error', closeAll);
    send(continuePacket(0, windowSize));
    websocket.on('message', (data, isBinary) => {
      if (!isBinary) return disconnect(1003, 'Binary Wisp frames required');
      const frame = Buffer.from(data);
      if (frame.length < 5) return disconnect(1002, 'Truncated Wisp frame');
      const type = frame[0];
      const id = frame.readUInt32LE(1);
      if (id === 0) return disconnect(1002, 'Stream zero is reserved');
      if (type === 1) {
        if (streams.has(id)) return disconnect(1002, 'Duplicate stream identifier');
        if (frame.length < 9 || frame.length > 261) return closeStream(id, 0x41);
        let hostname;
        try { hostname = new TextDecoder('utf-8', { fatal: true }).decode(frame.subarray(8)).toLowerCase(); }
        catch { return closeStream(id, 0x41); }
        const port = frame.readUInt16LE(6);
        if (frame[5] !== 1 || port !== 443 || !allowedHosts.has(hostname)) return closeStream(id, 0x48);
        if (streams.size >= maxStreams) return closeStream(id, 0x49);
        let socket;
        try { socket = connect({ host: hostname, port, lookup: publicLookup, autoSelectFamily: true }); }
        catch (error) { return closeStream(id, failureReason(error)); }
        const stream = { socket, credits: windowSize, pending: 0, pendingBytes: 0, timer: null, connected: false };
        streams.set(id, stream);
        stream.timer = setTimeout(() => closeStream(id, 0x43), connectTimeoutMs);
        stream.timer.unref();
        socket.setNoDelay?.(true);
        socket.setTimeout?.(idleTimeoutMs);
        socket.once('connect', () => { stream.connected = true; clearTimeout(stream.timer); });
        socket.on('timeout', () => closeStream(id, stream.connected ? 0x47 : 0x43));
        socket.on('error', error => { if (streams.get(id) === stream) closeStream(id, failureReason(error)); });
        socket.on('close', hadError => { if (streams.get(id) === stream) closeStream(id, hadError ? 0x03 : 0x02); });
        socket.on('data', chunk => {
          // Keep Wisp frames bounded regardless of the TCP read chunk size.
          for (let offset = 0; offset < chunk.length; offset += maxPayload - 5) {
            if (!send(packet(2, id, chunk.subarray(offset, offset + maxPayload - 5)))) break;
          }
        });
      } else if (type === 2) {
        const stream = streams.get(id);
        if (!stream) return closeStream(id, 0x41);
        if (stream.credits <= 0) return closeStream(id, 0x49);
        const payload = frame.subarray(5);
        if (stream.pendingBytes + payload.length > maxBufferedBytes) return closeStream(id, 0x49);
        stream.credits -= 1;
        stream.pending += 1;
        stream.pendingBytes += payload.length;
        stream.socket.write(payload, error => {
          if (streams.get(id) !== stream) return;
          stream.pending -= 1;
          stream.pendingBytes -= payload.length;
          if (error) return closeStream(id, failureReason(error));
          // Replenish only after the entire advertised window has been received
          // and drained. This avoids granting credit for still-in-flight packets.
          if (stream.credits === 0 && stream.pending === 0) {
            stream.credits = windowSize;
            send(continuePacket(id, windowSize));
          }
        });
      } else if (type === 4) {
        if (frame.length !== 6) return disconnect(1002, 'Invalid close frame');
        closeStream(id, frame[5], false);
      } else return disconnect(1002, 'Unsupported client packet type');
    });
  });
  return {
    server,
    wss,
    listen: (port = 8788, host = '127.0.0.1') => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => { server.off('error', reject); resolve(server.address()); });
    }),
    close: async () => {
      for (const websocket of wss.clients) websocket.terminate();
      await new Promise(resolve => wss.close(resolve));
      if (server.listening) await new Promise(resolve => server.close(resolve));
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const origins = process.env.TWANG_ALLOWED_ORIGINS?.split(',').map(origin => origin.trim()).filter(Boolean) ?? DEFAULT_ORIGINS;
  const port = Number(process.env.TWANG_RELAY_PORT ?? 8788);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('TWANG_RELAY_PORT must be a valid TCP port');
  const relay = createRelayServer({ origins });
  const address = await relay.listen(port, process.env.TWANG_RELAY_HOST ?? '127.0.0.1');
  console.log(`Twang byte relay: http://${address.address}:${address.port}/health`);
  console.log(`Wisp v1 TCP endpoint: ws://${address.address}:${address.port}/wisp/`);
  console.log(`Allowed origins: ${origins.join(', ')}`);
  console.log('Destinations: fixed Signal host allowlist on TCP443; inner TLS is never terminated.');
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => { await relay.close(); process.exit(0); });
}
