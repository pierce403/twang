import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {X509Certificate} from 'node:crypto';
import {bounded,TRUST_POLICY} from '../app/transport.mjs';
test('already cancelled probes never start network work',async()=>{
 const c=new AbortController();c.abort();let started=false;
 const r=await bounded({signal:c.signal},async()=>{started=true});
 assert.equal(r.status,'cancelled');assert.equal(started,false);
});
test('cancellation releases pending resources and prevents late events',async()=>{
 const c=new AbortController();let ctx;let cleaned=false;
 const result=bounded({signal:c.signal},context=>{
  ctx=context;ctx.defer(()=>{cleaned=true});
  c.abort();return new Promise(()=>{});
 });
 const r=await result;assert.equal(r.status,'cancelled');assert.equal(cleaned,true);
 ctx.emit('success','late success');assert.equal(r.events.length,0);
});
test('failure retains phase and evidence and tears down resources',async()=>{
 let cleaned=false;
 const r=await bounded({},async ctx=>{
  ctx.setPhase('inner-tls');ctx.setEvidence({certificateVerified:false});
  ctx.defer(()=>{cleaned=true});throw new Error('certificate rejected');
 });
 assert.equal(r.ok,false);assert.equal(cleaned,true);assert.equal(r.details.phase,'inner-tls');
 assert.equal(r.details.certificateVerified,false);assert.match(r.details.error,/certificate rejected/);
 assert.doesNotMatch(r.details.interpretation,/CORS/);
});
test('timeout aborts pending work and invokes cleanup',async()=>{
 let cleaned=false;let signal;
 const r=await bounded({timeoutMs:1},async ctx=>{
  signal=ctx.signal;ctx.defer(()=>{cleaned=true});return new Promise(()=>{});
 });
 assert.equal(r.status,'timeout');assert.equal(signal.aborted,true);assert.equal(cleaned,true);
});
test('resources arriving after cancellation are immediately released',async()=>{
 const c=new AbortController();let resume;let cleaned=false;
 const pending=new Promise(resolve=>{resume=resolve});
 const result=bounded({signal:c.signal},async ctx=>{
  await pending;ctx.defer(()=>{cleaned=true});ctx.check();
 });
 await Promise.resolve();c.abort();assert.equal((await result).status,'cancelled');
 resume();await Promise.resolve();assert.equal(cleaned,true);
});
test('static UI uses one fixed proxy and exposes no endpoint editor',async()=>{
 const h=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(h,/id="proxy-endpoint"/);assert.doesNotMatch(h,/<input[^>]+(?:relay|proxy)/);
 const main=await readFile(new URL('../app/main.mjs',import.meta.url),'utf8');
 assert.match(main,/probeProxyTls/);assert.doesNotMatch(main,/probeDirectHttps|probeDirectWebSocket/);
 const p=JSON.parse(await readFile(new URL('../package.json',import.meta.url)));assert.equal(p.scripts.relay,undefined);
 assert.match(TRUST_POLICY,/WebAssembly validates the inner Signal TLS/);
});
test('static deployment permits only the configured network tunnel',async()=>{
 const headers=await readFile(new URL('../public/_headers',import.meta.url),'utf8');
 assert.match(headers,/connect-src 'self' wss:\/\/proxy\.twang\.chat;/);
 assert.match(headers,/'wasm-unsafe-eval'/);assert.doesNotMatch(headers,/'unsafe-eval'|'unsafe-inline'|https:\/\/\*/);
 const config=JSON.parse((await readFile(new URL('../wrangler.jsonc',import.meta.url),'utf8')));
 assert.equal(config.name,'twang');assert.equal(config.main,undefined);assert.equal(config.assets.directory,'./dist');
});
test('bundled Signal CA certificates match the reviewed public fingerprints',async()=>{
 for(const [name,fingerprint] of [
  ['signal','DDB0F92BB95C8D6FD202EA6E8CC5CCD182B544F8CD696F47D580659DDC9DF65A'],
  ['signal-ed25519','2642F1F90B389FED2558D7324CA26D70E750B06F87C595C5DE955E2560821657']
 ]){
  const pem=await readFile(new URL(`../public/certs/${name}.pem`,import.meta.url),'utf8');
  const cert=new X509Certificate(pem);
  assert.equal(cert.fingerprint256.replaceAll(':',''),fingerprint);assert.equal(cert.ca,true);
  assert.doesNotMatch(pem,/PRIVATE KEY/);
 }
});

