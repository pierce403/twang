import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, extname, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WebSocketServer, createWebSocketStream } from 'ws';

const root = fileURLToPath(new URL('../../', import.meta.url));
const listen = (server, port = 0, host = '127.0.0.1') => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(port, host, () => { server.off('error', reject); resolve(); });
});

// Test-only server. Its arbitrary local destinations and CA are never shipped
// in dist/, and neither is accessible through production app configuration.
export async function startFixtures({ port = 0, host = '127.0.0.1' } = {}) {
  const temp = await mkdtemp(join(tmpdir(), 'twang-browser-tls-'));
  const deployedHeaders = (await readFile(join(root, 'public/_headers'), 'utf8'))
    .split('\n').map(line => line.match(/^\s+([\w-]+):\s*(.*)$/)).filter(Boolean);
  const sockets = new Set();
  let opened = 0;
  const track = socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    return socket;
  };
  try {
    const openssl = args => execFileSync('openssl', args, { stdio: 'ignore' });
    openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', join(temp, 'ca-key.pem'), '-out', join(temp, 'ca.pem'),
      '-days', '1', '-subj', '/CN=Twang local test CA',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', join(temp, 'key.pem'), '-out', join(temp, 'leaf.csr'), '-subj', '/CN=localhost']);
    await writeFile(join(temp, 'leaf.ext'), 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
    openssl(['x509', '-req', '-in', join(temp, 'leaf.csr'), '-CA', join(temp, 'ca.pem'),
      '-CAkey', join(temp, 'ca-key.pem'), '-CAcreateserial', '-out', join(temp, 'cert.pem'),
      '-days', '1', '-extfile', join(temp, 'leaf.ext')]);
    const cert = await readFile(join(temp, 'ca.pem'), 'utf8');
    const innerHttp = http.createServer((_req, res) => {
      res.writeHead(418, { 'Content-Type': 'text/plain', 'Connection': 'close' });
      res.end('fixture response');
    });
    const innerWebSocket = new WebSocketServer({ noServer: true, perMessageDeflate: false });
    let lastUpgrade;
    const innerState = { messages: 0, errors: [] };
    innerHttp.on('upgrade', (req, socket, head) => {
      lastUpgrade = { path: req.url, fixtureHeader: req.headers['x-twang-fixture'] };
      // HTTP clients may use absolute-form request targets. Route by parsed
      // pathname just as an application HTTP router would.
      if (new URL(req.url, 'https://localhost').pathname !== '/v1/websocket/provisioning/' || req.headers['x-twang-fixture'] !== 'browser') {
        socket.destroy(); return;
      }
      innerWebSocket.handleUpgrade(req, socket, head, ws => {
        ws.on('error', error => innerState.errors.push(error.message));
        ws.on('message', (data, binary) => { innerState.messages++; ws.send(data, { binary }); });
        ws.send(new Uint8Array([0, 255, 7, 128, 0]), { binary: true });
        socket.resume();
      });
    });
    const endpoint = tls.createServer({ key: await readFile(join(temp, 'key.pem')),
      cert: await readFile(join(temp, 'cert.pem')) }, socket => {
      socket.once('data', first => {
        if (first[0] === 0x47) {
          socket.pause();
          innerHttp.emit('connection', socket);
          socket.unshift(first);
          socket.resume();
        } else { socket.write(first); socket.pipe(socket); }
      });
    });
    endpoint.on('connection', track);
    endpoint.on('tlsClientError', () => {});
    await listen(endpoint);
    const tlsPort = endpoint.address().port;
    const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024,
      perMessageDeflate: false, handleProtocols: protocols =>
        protocols.has('signal-tls-v1') ? 'signal-tls-v1' : false });
    const web = http.createServer(async (req, res) => {
      try {
        // Exercise the production headers, substituting only the test loopback
        // WS origin for the production WSS origin. No unsafe-inline or eval.
        for (const [, name, value] of deployedHeaders) res.setHeader(name,
          name.toLowerCase() === 'content-security-policy'
            ? value.replace('wss://proxy.twang.chat', `ws://${req.headers.host} wss://${req.headers.host}`)
            : value);
        res.setHeader('Cache-Control', 'no-store');
        const url = new URL(req.url, 'http://localhost');
        if (url.pathname === '/__e2e__/config') {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ cert, tlsPort, endpoint: '/__e2e__/tunnel' }));
          return;
        }
        if (url.pathname === '/__e2e__/stats') {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ opened, active: wss.clients.size, lastUpgrade, innerState }));
          return;
        }
        if (url.pathname === '/__e2e__/') {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end('<!doctype html><meta charset="utf-8"><title>Twang browser TLS tests</title><h1>Twang browser TLS tests</h1><p>Local fixtures only. No Signal connection is attempted.</p><pre id="results">Running…</pre><script type="module" src="/test/e2e/runner.mjs"></script>');
          return;
        }
        const fixture = url.pathname === '/test/e2e/runner.mjs' || url.pathname === '/test/e2e/browser-suite.mjs';
        const base = fixture ? root : join(root, 'dist');
        const file = resolve(base, '.' + decodeURIComponent(url.pathname));
        if (!file.startsWith(resolve(base) + sep)) { res.writeHead(403).end(); return; }
        const body = await readFile(file);
        const type = { '.mjs': 'text/javascript', '.js': 'text/javascript', '.wasm': 'application/wasm', '.pem': 'text/plain', '.css': 'text/css', '.html': 'text/html' }[extname(file)] || 'application/octet-stream';
        res.setHeader('Content-Type', type);
        res.end(body);
      } catch { res.writeHead(404).end(); }
    });
    web.on('connection', track);
    web.on('upgrade', (req, socket, head) => {
      if (!['/__e2e__/tunnel', '/__e2e__/stall'].includes(req.url) ||
        !req.headers['sec-websocket-protocol']?.split(',').map(x => x.trim()).includes('signal-tls-v1')) {
        socket.destroy(); return;
      }
      wss.handleUpgrade(req, socket, head, ws => {
        opened++;
        ws.on('error', () => {});
        if (req.url === '/__e2e__/stall') return; // Deliberately never answers TLS.
        const upstream = track(net.connect(tlsPort, '127.0.0.1'));
        const stream = createWebSocketStream(ws);
        stream.on('error', () => upstream.destroy());
        upstream.on('error', () => ws.terminate());
        upstream.once('close', () => ws.terminate());
        stream.once('close', () => upstream.destroy());
        stream.pipe(upstream).pipe(stream);
      });
    });
    await listen(web, port, host);
    let closed = false;
    return {
      url: `http://127.0.0.1:${web.address().port}/__e2e__/`,
      async close() {
        if (closed) return;
        closed = true;
        for (const ws of wss.clients) ws.terminate();
        for (const ws of innerWebSocket.clients) ws.terminate();
        for (const socket of sockets) socket.destroy();
        await Promise.all([new Promise(r => web.close(r)), new Promise(r => endpoint.close(r))]);
        wss.close();
        innerWebSocket.close();
        await rm(temp, { recursive: true, force: true });
      },
    };
  } catch (error) {
    for (const socket of sockets) socket.destroy();
    await rm(temp, { recursive: true, force: true });
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const option = name => { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; };
  const fixtures = await startFixtures({ port: Number(option('--port') || 0), host: option('--host') || '127.0.0.1' });
  console.log(`Open browser tests: ${fixtures.url}`);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => { await fixtures.close(); process.exit(0); });
}
