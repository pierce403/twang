import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {probeDirectHttps,probeDirectWebSocket,runProbe,TRUST_POLICY} from '../app/transport.mjs';
test('HTTPS uses native browser networking without credentials',async()=>{
 const old=globalThis.fetch;
 let called;
 globalThis.fetch=async(url,options)=>{called={url,options};return {status:403,body:{cancel(){}}};};
 try{const r=await probeDirectHttps({host:'chat.signal.org'});assert.equal(r.ok,true);assert.equal(r.details.httpStatus,403);assert.equal(called.options.credentials,'omit');assert.equal(called.options.mode,'cors');assert.equal(called.url,'https://chat.signal.org/');}finally{globalThis.fetch=old;}
});
test('unapproved host is rejected before network',async()=>{
 const r=await probeDirectHttps({host:'example.com'});assert.equal(r.ok,false);
});
test('browser failure is explicitly ambiguous',async()=>{
 const old=globalThis.fetch;globalThis.fetch=async()=>{throw new TypeError('Failed to fetch')};
 try{const r=await probeDirectHttps({host:'chat.signal.org'});assert.equal(r.ok,false);assert.match(r.details.interpretation,/not evidence/);}finally{globalThis.fetch=old;}
});
test('cancelled probe never starts fetch',async()=>{
 const c=new AbortController();c.abort();const r=await probeDirectHttps({host:'chat.signal.org',signal:c.signal});assert.equal(r.status,'cancelled');
});
test('native WSS closes after upgrade without sending messages',async()=>{
 const old=globalThis.WebSocket;let socket;
 globalThis.WebSocket=class extends EventTarget{constructor(url){super();this.url=url;socket=this;queueMicrotask(()=>this.dispatchEvent(new Event('open')))}close(){this.closed=true}};
 try{const r=await probeDirectWebSocket({host:'chat.signal.org'});assert.equal(r.ok,true);assert.equal(socket.closed,true);assert.equal(socket.url,'wss://chat.signal.org/v1/websocket/provisioning/');}finally{globalThis.WebSocket=old;}
});
test('relay modes are unsupported',async()=>assert.equal((await runProbe({mode:'relay-tls'})).ok,false));
test('static UI has no relay or WASM controls',async()=>{
 const h=await readFile(new URL('../public/index.html',import.meta.url),'utf8');assert.doesNotMatch(h,/id="relay-|value="relay"|WebAssembly/);assert.match(h,/cannot open raw TCP/);
 const p=JSON.parse(await readFile(new URL('../package.json',import.meta.url)));assert.equal(p.dependencies,undefined);assert.equal(p.scripts.relay,undefined);assert.match(TRUST_POLICY,/managed by the browser/);
});

