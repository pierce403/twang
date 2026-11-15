import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { createCipheriv, createDecipheriv, createHmac, createPublicKey,
  diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep, extname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WebSocketServer, createWebSocketStream } from 'ws';

const root = fileURLToPath(new URL('../../', import.meta.url));
const dist = join(root, 'dist');
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const listen = (server, port = 0, host = '127.0.0.1') => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(port, host, () => { server.off('error', reject); resolve(); });
});
const varint = input => {
  let value = BigInt(input); const parts = [];
  do { const byte = Number(value & 127n); value >>= 7n; parts.push(byte | (value ? 128 : 0)); } while (value);
  return Buffer.from(parts);
};
const field = (id, input) => {
  if (typeof input === 'number' || typeof input === 'bigint') return Buffer.concat([varint(id * 8), varint(input)]);
  const value = typeof input === 'string' ? Buffer.from(input) : Buffer.from(input);
  return Buffer.concat([varint(id * 8 + 2), varint(value.length), value]);
};
const fields = value => {
  const data = Buffer.from(value); let offset = 0; const values = new Map();
  const integer = () => { let value = 0n, shift = 0n; for (;;) { assert.ok(offset < data.length && shift < 70n); const byte = data[offset++]; value |= BigInt(byte & 127) << shift; if (!(byte & 128)) return value; shift += 7n; } };
  while (offset < data.length) {
    const tag = integer(), id = Number(tag >> 3n), kind = Number(tag & 7n);
    assert.ok(!values.has(id));
    if (kind === 0) values.set(id, integer());
    else { assert.equal(kind, 2); const size = Number(integer()); assert.ok(size <= data.length - offset); values.set(id, data.subarray(offset, offset + size)); offset += size; }
  }
  return values;
};
const request = (id, path, body) => Buffer.concat([field(1, 1), field(2,
  Buffer.concat([field(1, 'PUT'), field(2, path), field(3, body), field(4, id)]))]);
const rawPublic = key => key.export({ format: 'der', type: 'spki' }).subarray(-32);
const publicFromSignal = value => createPublicKey({ format: 'der', type: 'spki',
  key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(value).subarray(1)]) });

// This fixture is a fake primary phone and a fake Signal service, never an
// account registration service. Production client files are served unchanged;
// test-only bootstrap rewires the outer WebSocket and serves a fixture CA.
export async function startLinkingFixture({ port = 0, host = '127.0.0.1', failRegistration = false } = {}) {
  const temp = await mkdtemp(join(tmpdir(), 'twang-linking-test-'));
  const tracked = new Set();
  const track = socket => { tracked.add(socket); socket.on('error', () => {}); socket.once('close', () => tracked.delete(socket)); };
  const openssl = args => execFileSync('openssl', args, { stdio: 'ignore' });
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(temp, 'ca-key.pem'), '-out', join(temp, 'ca.pem'),
    '-days', '1', '-subj', '/CN=Twang linking test CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
  openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(temp, 'key.pem'), '-out', join(temp, 'leaf.csr'), '-subj', '/CN=chat.signal.org']);
  await writeFile(join(temp, 'leaf.ext'), 'subjectAltName=DNS:chat.signal.org\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  openssl(['x509', '-req', '-in', join(temp, 'leaf.csr'), '-CA', join(temp, 'ca.pem'), '-CAkey', join(temp, 'ca-key.pem'), '-CAcreateserial',
    '-out', join(temp, 'leaf.pem'), '-days', '1', '-extfile', join(temp, 'leaf.ext')]);
  const ca = await readFile(join(temp, 'ca.pem'));
  const identity = generateKeyPairSync('x25519');
  const identityPrivate = identity.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
  const profile = randomBytes(32), salt = randomBytes(16), aci = randomUUID(), address = randomUUID();
  const code = 'local-fixture-provision-code';
  const addressId = 9007199254740995n, messageId = addressId + 1n;
  const registration = deferred(), confirmation = deferred();
  const state = { requests: [], acks: [], registration: undefined, pairingUrl: undefined, failure: undefined, secrets: { identity: identityPrivate.toString('base64'), profile: profile.toString('base64') } };
  let provisionSocket;
  const api = https.createServer({ key: await readFile(join(temp, 'key.pem')), cert: await readFile(join(temp, 'leaf.pem')) }, async (req, res) => {
    const path = new URL(req.url, 'https://chat.signal.org').pathname;
    state.requests.push({ method: req.method, path });
    if (req.method !== 'PUT' || path !== '/v1/devices/link') { res.writeHead(404).end(); return; }
    try {
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; assert.ok(size < 65536); chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks));
      const authorization = Buffer.from((req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString();
      assert.ok(authorization.startsWith(aci + ':'));
      assert.ok(authorization.slice(aci.length + 1).length >= 20);
      assert.equal(body.verificationCode, code);
      assert.equal(body.accountAttributes.fetchesMessages, true);
      assert.equal(body.accountAttributes.capabilities.storage, false);
      assert.equal(body.accountAttributes.capabilities.attachmentBackfill, false);
      assert.equal(body.accountAttributes.capabilities.spqr, true);
      assert.ok(body.accountAttributes.registrationId > 0 && body.accountAttributes.registrationId < 16384);
      assert.equal(Buffer.from(body.aciSignedPreKey.publicKey, 'base64').length, 33);
      assert.equal(Buffer.from(body.aciSignedPreKey.signature, 'base64').length, 64);
      assert.equal(Buffer.from(body.aciPqLastResortPreKey.publicKey, 'base64').length, 1569);
      assert.equal(Buffer.from(body.aciPqLastResortPreKey.signature, 'base64').length, 64);
      assert.ok(!JSON.stringify(body).includes(identityPrivate.toString('base64')));
      assert.ok(!JSON.stringify(body).includes(profile.toString('base64')));
      const encryptedName = fields(Buffer.from(body.accountAttributes.name, 'base64'));
      const secret = diffieHellman({ privateKey: identity.privateKey, publicKey: publicFromSignal(encryptedName.get(1)) });
      const cipherSeed = createHmac('sha256', secret).update('cipher').digest();
      const cipherKey = createHmac('sha256', cipherSeed).update(encryptedName.get(2)).digest();
      const cipher = createDecipheriv('aes-256-ctr', cipherKey, Buffer.alloc(16));
      const name = Buffer.concat([cipher.update(encryptedName.get(3)), cipher.final()]);
      assert.deepEqual(createHmac('sha256', createHmac('sha256', secret).update('auth').digest()).update(name).digest().subarray(0, 16), encryptedName.get(2));
      state.registration = { body, deviceName: name.toString(), password: authorization.slice(aci.length + 1) };
      registration.resolve(state.registration);
      await confirmation.promise;
      res.writeHead(failRegistration ? 403 : 200, { 'Content-Type': 'application/json', 'Connection': 'close' });
      res.end(JSON.stringify(failRegistration ? {} : { deviceId: 2, uuid: aci }));
    } catch (error) {
      state.failure = error.message;
      registration.resolve(undefined);
      res.writeHead(400).end();
    }
  });
  api.on('connection', track);
  const inner = new WebSocketServer({ noServer: true, perMessageDeflate: false });
  api.on('upgrade', (req, socket, head) => {
    state.requests.push({ method: req.method, path: new URL(req.url, 'https://chat.signal.org').pathname });
    if (req.url !== '/v1/websocket/provisioning/') { socket.destroy(); return; }
    inner.handleUpgrade(req, socket, head, ws => {
      provisionSocket = ws;
      ws.on('error', () => {});
      ws.on('message', data => {
        try {
          const frame = fields(data); assert.equal(frame.get(1), 2n);
          const response = fields(frame.get(3)); assert.equal(response.get(2), 200n);
          state.acks.push(response.get(1).toString());
        } catch (error) { state.failure = error.message; }
      });
      ws.send(request(addressId, '/v1/address', field(1, address)));
    });
  });
  await listen(api);
  const raw = new WebSocketServer({ noServer: true, perMessageDeflate: false, handleProtocols: protocols => protocols.has('signal-tls-v1') ? 'signal-tls-v1' : false });
  const headers = (await readFile(join(dist, '_headers'), 'utf8')).split('\n').map(line => line.match(/^\s+([\w-]+):\s*(.*)$/)).filter(Boolean);
  const web = http.createServer(async (req, res) => {
    try {
      for (const [, name, value] of headers) res.setHeader(name, name.toLowerCase() === 'content-security-policy'
        ? value.replace('wss://proxy.twang.chat', `wss://proxy.twang.chat ws://${req.headers.host}`) : value);
      res.setHeader('Cache-Control', 'no-store');
      const pathname = new URL(req.url, 'http://localhost').pathname;
      if (pathname === '/__linking__/provision') {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        await provision(Buffer.concat(chunks).toString()); res.end('ok'); return;
      }
      if (pathname === '/__linking__/confirm') { confirmation.resolve(); res.end('ok'); return; }
      if (pathname === '/__linking__/state') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ requests: state.requests, acks: state.acks, registration: Boolean(state.registration), failure: state.failure })); return; }
      if (pathname === '/__linking__/boot.mjs') { res.setHeader('Content-Type', 'text/javascript'); res.end(bootstrap); return; }
      if (pathname === '/certs/signal.pem') { res.setHeader('Content-Type', 'text/plain'); res.end(ca); return; }
      const file = resolve(dist, '.' + decodeURIComponent(pathname === '/' ? '/index.html' : pathname));
      if (!file.startsWith(resolve(dist) + sep)) { res.writeHead(403).end(); return; }
      let body = await readFile(file);
      if (pathname === '/' || pathname === '/index.html') body = Buffer.from(body.toString().replace('src="./app/main.mjs"', 'src="/__linking__/boot.mjs"'));
      res.setHeader('Content-Type', { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.wasm': 'application/wasm', '.css': 'text/css', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json', '.png': 'image/png' }[extname(file)] || 'text/plain');
      res.end(body);
    } catch { res.writeHead(404).end(); }
  });
  web.on('connection', track);
  web.on('upgrade', (req, socket, head) => {
    if (req.url !== '/__linking__/tunnel') { socket.destroy(); return; }
    raw.handleUpgrade(req, socket, head, ws => {
      const upstream = net.connect(api.address().port, '127.0.0.1'); track(upstream);
      const stream = createWebSocketStream(ws);
      stream.on('error', () => upstream.destroy());
      upstream.on('error', () => ws.terminate());
      upstream.once('close', () => ws.terminate());
      stream.once('close', () => upstream.destroy());
      stream.pipe(upstream).pipe(stream);
    });
  });
  async function provision(input) {
    const uri = new URL(input); assert.equal(uri.protocol, 'sgnl:'); assert.equal(uri.hostname, 'linkdevice');
    assert.equal(uri.searchParams.get('uuid'), address); assert.equal(uri.searchParams.get('capabilities'), 'nopni,nopni2');
    const receiverPublic = Buffer.from(uri.searchParams.get('pub_key'), 'base64'); assert.equal(receiverPublic.length, 33); assert.equal(receiverPublic[0], 5);
    const sender = generateKeyPairSync('x25519');
    const secret = diffieHellman({ privateKey: sender.privateKey, publicKey: publicFromSignal(receiverPublic) });
    const key = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(32), Buffer.from('TextSecure Provisioning Message'), 64));
    const plaintext = Buffer.concat([field(2, identityPrivate), field(4, code), field(6, profile), field(8, aci), field(19, salt)]);
    const iv = randomBytes(16), cipher = createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
    const authenticated = Buffer.concat([Buffer.from([1]), iv, cipher.update(plaintext), cipher.final()]);
    const body = Buffer.concat([authenticated, createHmac('sha256', key.subarray(32)).update(authenticated).digest()]);
    assert.ok(provisionSocket); state.pairingUrl = input;
    provisionSocket.send(request(messageId, '/v1/message', Buffer.concat([field(1, Buffer.concat([Buffer.from([5]), rawPublic(sender.publicKey)])), field(2, body)])));
    plaintext.fill(0); secret.fill(0); key.fill(0);
  }
  const bootstrap = `
// Dedicated local-fixture origin only: remove stale app-shell caches before
// importing client modules. IndexedDB is preserved so linked reload is tested.
for(const name of await caches.keys())if(name.startsWith('twang-static-v1-'))await caches.delete(name);
for(const registration of await navigator.serviceWorker.getRegistrations())if(new URL(registration.scope).origin===location.origin)await registration.unregister();
const NativeWebSocket=globalThis.WebSocket;
globalThis.WebSocket=class extends NativeWebSocket{constructor(url,protocols){if(String(url)!=='wss://proxy.twang.chat/v1/tls-tunnel')throw Error('Unexpected external WebSocket in local linking fixture');super('ws://'+location.host+'/__linking__/tunnel',protocols)}};
Object.defineProperty(navigator,'clipboard',{value:{async writeText(value){window.__fixturePairingUrl=value;const response=await fetch('/__linking__/provision',{method:'POST',body:value});if(!response.ok)throw Error('Fixture provision failed')}}});
await import('/app/main.mjs');
const controls=document.createElement('aside');
controls.className='panel';
const confirm=document.createElement('button');confirm.id='fixture-confirm';confirm.textContent='Confirm local fixture response';
const result=document.createElement('pre');result.id='fixture-result';result.textContent='Local fixture only. Link, then copy the QR URL to simulate a phone scan; confirm here after keys are prepared.';
controls.append(confirm,result);document.body.append(controls);
const snapshot=async()=>{const db=await new Promise((resolve,reject)=>{const request=indexedDB.open('twang-device',1);request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error)});try{return await new Promise((resolve,reject)=>{const tx=db.transaction('vault','readonly'),store=tx.objectStore('vault'),keys=store.getAllKeys(),values=store.getAll();tx.oncomplete=()=>resolve(keys.result.map((key,i)=>({key,extractable:values.result[i]instanceof CryptoKey?values.result[i].extractable:undefined,fields:values.result[i]instanceof CryptoKey?undefined:Object.keys(values.result[i]).sort(),ownerBytes:values.result[i]?.owner?.byteLength})));tx.onerror=()=>reject(tx.error)})}finally{db.close()}};
confirm.addEventListener('click',async()=>{try{const state=await(await fetch('/__linking__/state')).json();if(state.failure)throw Error(state.failure);if(!state.registration)throw Error('Copy the QR URL and wait for registration first');const pending=await snapshot();if(pending.map(x=>x.key).sort().join(',')!=='key,pending'||pending.find(x=>x.key==='key').extractable!==false||pending.find(x=>x.key==='pending').fields.join(',')!=='ciphertext,iv,owner,version'||pending.find(x=>x.key==='pending').ownerBytes!==32)throw Error('Pending encrypted storage assertion failed');await fetch('/__linking__/confirm',{method:'POST'});await new Promise((resolve,reject)=>{const started=Date.now(),timer=setInterval(()=>{if(document.querySelector('#link-status').textContent==='Account linked'){clearInterval(timer);resolve()}else if(Date.now()-started>10000){clearInterval(timer);reject(Error('Linked UI did not appear'))}},25)});const linked=await snapshot();if(linked.map(x=>x.key).sort().join(',')!=='account,key')throw Error('Confirmed storage assertion failed');result.textContent=JSON.stringify({ok:true,pending,linked,requests:state.requests,acks:state.acks,qrCleared:document.querySelector('#link-qr').hidden},null,2);result.dataset.complete='true';result.dataset.passed='true'}catch(error){result.textContent=String(error);result.dataset.complete='true';result.dataset.passed='false'}});
`;
  await listen(web, port, host);
  return { url: `http://127.0.0.1:${web.address().port}/`, state, registration: registration.promise,
    confirm: () => confirmation.resolve(), provision,
    async close() { confirmation.resolve(); for (const ws of [...inner.clients, ...raw.clients]) ws.terminate(); for (const socket of tracked) socket.destroy(); await Promise.all([new Promise(r => api.close(r)), new Promise(r => web.close(r))]); inner.close(); raw.close(); identityPrivate.fill(0); profile.fill(0); salt.fill(0); await rm(temp, { recursive: true, force: true }); },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const option = name => { const at = process.argv.indexOf(name); return at < 0 ? undefined : process.argv[at + 1]; };
  const fixture = await startLinkingFixture({ port: Number(option('--port') || 0), host: option('--host') || '127.0.0.1' });
  console.log(`Linking UI fixture: ${fixture.url}`);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => { await fixture.close(); process.exit(0); });
}
