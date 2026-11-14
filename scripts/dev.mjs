import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import './build.mjs';
import { createRelayServer } from '../relay/server.mjs';

const root = path.resolve(fileURLToPath(new URL('../dist/', import.meta.url)));
const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
};
const port = Number(arg('--port') || process.env.PORT || 5173);
const host = arg('--host') || process.env.HOST || '127.0.0.1';
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid development port');
const allowedOrigins = process.env.TWANG_ALLOWED_ORIGINS?.split(',').map(value => value.trim()).filter(Boolean)
  || [`http://localhost:${port}`, `http://127.0.0.1:${port}`, 'https://twang.chat'];
const relay = createRelayServer({origins:allowedOrigins});
const types = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.js':'text/javascript; charset=utf-8','.wasm':'application/wasm','.svg':'image/svg+xml','.pem':'text/plain; charset=utf-8','.json':'application/json; charset=utf-8'};
const server = http.createServer(async (request, response) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'HEAD'].includes(request.method)) {response.writeHead(405); response.end(); return;}
  let pathname;
  try { pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname); }
  catch {response.writeHead(400); response.end('Bad request'); return;}
  const file = path.resolve(root, `.${pathname === '/' ? '/index.html' : pathname}`);
  if (!file.startsWith(`${root}${path.sep}`)) {response.writeHead(403); response.end(); return;}
  try {
    if (!(await stat(file)).isFile()) throw new Error('Not a file');
    const data = await readFile(file);
    response.setHeader('Content-Type', types[path.extname(file)] || 'application/octet-stream');
    response.writeHead(200);
    response.end(request.method === 'HEAD' ? undefined : data);
  } catch {response.writeHead(404); response.end('Not found');}
});
server.on('upgrade', (request, socket, head) => relay.server.emit('upgrade', request, socket, head));
server.listen(port, host, () => console.log(`Twang: http://${host}:${port} (Wisp relay at /wisp/)`));
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
  if (closing) return;
  closing = true;
  await relay.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
});
