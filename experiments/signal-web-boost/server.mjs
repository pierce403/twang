import net from 'node:net';
import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { WebSocketServer } from 'ws';

// Receives plaintext AFTER the stock proxy's outer TLS termination. The bytes
// inside the tunnel are still Signal TLS. No arbitrary destinations are accepted:
// both transports go to nginx-relay's existing SNI allowlist.
export function createBridge({ host = 'nginx-relay', port = 4433,
  maxSessions = 256, handshakeTimeout = 10_000, idleTimeout = 120_000 } = {}) {
  const sessions = new Set();
  const timers = new WeakMap();
  const httpServer = http.createServer({ maxHeaderSize: 8192 }, (_req, res) => {
    res.writeHead(404, { 'Connection': 'close', 'Content-Length': '0' });
    res.end();
  });
  httpServer.headersTimeout = handshakeTimeout;
  httpServer.requestTimeout = handshakeTimeout;
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024,
    perMessageDeflate: false, handleProtocols: protocols =>
      protocols.has('signal-tls-v1') ? 'signal-tls-v1' : false });

  function connect(client) {
    const upstream = net.createConnection({ host, port });
    const close = () => { client.destroy(); upstream.destroy(); };
    client.on('error', close);
    upstream.on('error', close);
    client.on('close', () => upstream.destroy());
    upstream.on('close', () => client.destroy());
    upstream.setTimeout(idleTimeout, close);
    return upstream;
  }

  httpServer.on('upgrade', (req, client, head) => {
    clearTimeout(timers.get(client));
    const protocols = (req.headers['sec-websocket-protocol'] || '')
      .split(',').map(value => value.trim());
    if (req.url !== '/v1/tls-tunnel' || !protocols.includes('signal-tls-v1')) {
      client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    // No cookies, authorization, target header, or target URL is consumed here.
    // Origin is intentionally unrestricted: this public Signal-only tunnel is
    // usable by independent static clients. Origin would not authenticate callers.
    wss.handleUpgrade(req, client, head, ws => {
      const upstream = connect(client);
      const close = () => { ws.terminate(); upstream.destroy(); };
      ws.on('error', close);
      ws.on('close', () => upstream.destroy());
      upstream.on('close', () => ws.terminate());
      ws.on('message', (data, binary) => {
        if (!binary) { close(); return; }
        if (!upstream.write(data)) ws.pause();
        if (upstream.writableLength > 256 * 1024) close();
      });
      upstream.on('drain', () => ws.resume());
      upstream.on('data', data => {
        upstream.pause();
        ws.send(data, { binary: true }, error => {
          if (error) close(); else upstream.resume();
        });
      });
    });
  });

  const server = net.createServer(client => {
    if (sessions.size >= maxSessions) { client.destroy(); return; }
    sessions.add(client);
    client.on('close', () => sessions.delete(client));
    // Avoid logging IPs, headers, frames, TLS records, or connection targets.
    client.on('error', () => {});
    const timeout = setTimeout(() => client.destroy(), handshakeTimeout);
    timers.set(client, timeout);
    timeout.unref();
    client.on('close', () => clearTimeout(timeout));
    client.once('data', first => {
      client.pause();
      if (first[0] === 0x16) {
        // TLS ClientHello, including one fragmented into single-byte TCP reads.
        clearTimeout(timeout);
        const upstream = connect(client);
        upstream.write(first);
        client.pipe(upstream).pipe(client);
        client.resume();
      } else if (first[0] === 0x47) {
        // HTTP GET WebSocket upgrade. Let Node parse bounded HTTP headers.
        httpServer.emit('connection', client);
        client.unshift(first);
        client.resume();
      } else {
        client.destroy();
      }
    });
  });
  // We deliberately manage connection lifetimes, including the pre-HTTP sniff.
  return { server, close: () => {
    for (const client of sessions) client.destroy();
    wss.close();
    return new Promise(resolve => server.close(resolve));
  } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { server } = createBridge();
  server.listen(4433, '0.0.0.0');
}
