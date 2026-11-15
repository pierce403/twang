import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createCipheriv,createHmac,createPublicKey,diffieHellman,generateKeyPairSync,hkdfSync} from 'node:crypto';
import {generateRegistrationKeys} from '../app/link-crypto.mjs';
import {startLink,LinkError,decodeFields,decodeProvisionMessage,decodeProvisionRequest,
  encodeProvisionResponse,createLinkUrl,base64} from '../app/link-protocol.mjs';

const ACI='a1111111-1111-4111-8111-111111111111';
const PNI='b2222222-2222-4222-8222-222222222222';
const utf8=new TextEncoder();
const concat=(...parts)=>Uint8Array.from(parts.flatMap(part=>[...part]));
const vint=input=>{let value=BigInt(input);const result=[];do{let byte=Number(value&127n);value>>=7n;if(value)byte|=128;result.push(byte)}while(value);return Uint8Array.from(result)};
const field=(id,value)=>typeof value==='bigint'||typeof value==='number'?concat(vint(id*8),vint(value)):(()=>{const b=typeof value==='string'?utf8.encode(value):value;return concat(vint(id*8+2),vint(b.length),b)})();
const key=new Uint8Array(32).fill(42);
const publicKey=concat(new Uint8Array([5]),key);
const request=(path,body,id=0xffffffffffffffffn)=>concat(field(1,1),field(2,concat(field(1,'PUT'),field(2,path),field(3,body),field(4,id))));
function provision({pni=true,fields=[]}={}){
 return concat(field(2,key),field(4,'secret-link-code'),field(6,key),field(8,ACI),field(13,key),
  ...(pni?[field(3,'+15555550123'),field(10,PNI),field(12,key)]:[field(19,new Uint8Array(16).fill(1))]),...fields);
}
const registrationKeys=()=>({registrationId:423,identityPublic:publicKey,
 signedPreKey:{keyId:1,publicKey,signature:new Uint8Array(64).fill(4)},
 pqLastResortPreKey:{keyId:1,publicKey:concat(new Uint8Array([8]),new Uint8Array(1568)),signature:new Uint8Array(64).fill(5)},
 signedPreKeyRecord:new Uint8Array([1,2,3]),pqLastResortPreKeyRecord:new Uint8Array([4,5,6])});
function harness({pni=true,status=200,result={deviceId:2,uuid:ACI},saveError=false,stall=false,invalidEnvelope=false,fetchError=false,pendingError=false}={}){
 const states=[],acks=[],requests=[],saved=[],pending=[];let closed=0,freed=0,cleared=0;
 const dependencies={
  generateProvisioningKeypair:async()=>({publicKey,privateKey:{fake:true}}),
  decryptProvisioningEnvelope:async()=>provision({pni}),
  generateRegistrationKeys:async()=>registrationKeys(),
  encryptDeviceName:async()=>({ephemeralPublic:publicKey,syntheticIv:new Uint8Array(16),ciphertext:new Uint8Array([7])}),
  createProxyClient:async ctx=>{ctx.defer(()=>freed++);return{client:{fetch:async(url,options)=>{
   assert.equal(pending.length,1,'Keys must be durable before the registration request');
   if(fetchError)throw new Error('network disconnected');
   requests.push({url,options});return{status,json:async()=>result,body:{cancel:async()=>{}}};
  }}}},
  openSignalWebSocket:async(_client,url,options)=>{
   assert.equal(url,'wss://chat.signal.org/v1/websocket/provisioning/');
   queueMicrotask(()=>options.onMessage(request('/v1/address',field(1,'opaque-session-address'))));
   return{send:async data=>{
    const frame=decodeFields(data);const response=decodeFields(frame.get(3));acks.push(response);
    if(acks.length===1&&!stall)queueMicrotask(()=>options.onMessage(request('/v1/message',
     invalidEnvelope?new Uint8Array([1]):concat(field(1,publicKey),field(2,new Uint8Array(65))),3n)));
   },close:async()=>{closed++}};
  },
  savePendingAccount:async account=>{if(pendingError)throw new Error('quota');pending.push(account)},
  clearPendingAccount:async()=>{pending.length=0;cleared++},
  saveAccount:async account=>{if(saveError)throw new Error('quota');saved.push(account);pending.length=0},
 };
 return{dependencies,states,acks,requests,saved,pending,get cleared(){return cleared},get closed(){return closed},get freed(){return freed}};
}
test('QR links an existing account without advertising history transfer',()=>{
 const url=new URL(createLinkUrl('opaque-session-address',publicKey));
 assert.equal(url.protocol,'sgnl:');assert.equal(url.hostname,'linkdevice');
 assert.equal(url.searchParams.get('pub_key'),base64(publicKey));
 assert.equal(url.searchParams.get('capabilities'),'nopni,nopni2');
 assert.doesNotMatch(url.href,/backup|register/);
});
test('protobuf request IDs remain uint64 when acknowledged',()=>{
 const r=decodeProvisionRequest(request('/v1/address',field(1,'opaque')));
 assert.equal(r.id,0xffffffffffffffffn);
 assert.equal(decodeFields(decodeFields(encodeProvisionResponse(r.id)).get(3)).get(1),r.id);
});
test('malformed, truncated, duplicate and wrong-wire provisioning input is rejected',()=>{
 for(const value of [new Uint8Array([0]),new Uint8Array([10,255]),concat(field(8,ACI),field(8,ACI)),new Uint8Array([15])])
  assert.throws(()=>decodeProvisionMessage(value));
 assert.throws(()=>decodeProvisionRequest(request('/v1/address',new Uint8Array()).subarray(0,5)));
 assert.throws(()=>decodeProvisionMessage(provision({pni:false,fields:[field(19,new Uint8Array(1))]})));
});
test('complete enrollment uploads signed ACI/PNI keys and saves only after confirmation',async()=>{
 const h=harness();
 const account=await startLink({deviceName:'Twang',onState:state=>h.states.push(state)},h.dependencies);
 assert.equal(account.deviceId,2);assert.equal(h.saved.length,1);
 assert.deepEqual(h.states.map(state=>state.state),['preparing','waiting','authorizing','linked']);
 assert.equal(h.acks.length,2);assert.equal(h.requests.length,1);
 const {url,options}=h.requests[0];
 assert.equal(url,'https://chat.signal.org/v1/devices/link');assert.equal(options.method,'PUT');
 const [username,secret]=atob(options.headers.Authorization.slice(6)).split(':');
 assert.equal(username,ACI);assert.equal(secret,account.password);
 const body=JSON.parse(options.body);
 assert.equal(body.verificationCode,'secret-link-code');assert.equal(body.accountAttributes.fetchesMessages,true);
 assert.equal(body.accountAttributes.capabilities.spqr,true);assert.equal(body.accountAttributes.pniRegistrationId,423);
 for(const id of ['aciSignedPreKey','pniSignedPreKey','aciPqLastResortPreKey','pniPqLastResortPreKey']){
  assert.equal(body[id].keyId,1);assert.equal(typeof body[id].publicKey,'string');assert.equal(typeof body[id].signature,'string');
 }
 assert.equal(account.aciPreKeys.signedPreKeyRecord,'AQID');
 assert.equal(account.aciPreKeys.pqLastResortPreKeyRecord,'BAUG');
 assert.doesNotMatch(JSON.stringify(h.states),/secret-link-code|aciIdentityPrivate|profileKey|password/);
 assert.equal(h.closed,1);assert.equal(h.freed,1);
});
test('phone-number-free enrollment omits all PNI keys and registration ID',async()=>{
 const h=harness({pni:false});const account=await startLink({},h.dependencies);
 const body=JSON.parse(h.requests[0].options.body);
 assert.equal(body.pniSignedPreKey,undefined);assert.equal(body.pniPqLastResortPreKey,undefined);
 assert.equal(body.accountAttributes.pniRegistrationId,undefined);assert.equal(account.pni,undefined);
 assert.equal(account.authCredentialSalt,base64(new Uint8Array(16).fill(1)));
});
test('rejected registration does not persist or report a linked account',async()=>{
 const h=harness({status:403});
 await assert.rejects(startLink({onState:state=>h.states.push(state)},h.dependencies),error=>error instanceof LinkError&&error.code==='rejected_code');
 assert.equal(h.saved.length,0);assert.equal(h.states.some(state=>state.state==='linked'),false);
 assert.equal(h.pending.length,0);assert.equal(h.cleared,1);
 assert.equal(h.closed,1);assert.equal(h.freed,1);
});
test('invalid primary device ID never becomes a linked account',async()=>{
 const h=harness({result:{deviceId:1}});
 await assert.rejects(startLink({},h.dependencies),error=>error.code==='invalid_confirmation'&&error.registered===true);
 assert.equal(h.saved.length,0);
});
test('storage failure after registration is explicitly marked and never reports success',async()=>{
 const h=harness({saveError:true});
 await assert.rejects(startLink({onState:state=>h.states.push(state)},h.dependencies),error=>{
  assert.equal(error.code,'storage_failed');assert.equal(error.registered,true);assert.equal(error.deviceId,2);
  assert.equal(error.accountRecord.aci,ACI);assert.doesNotMatch(JSON.stringify(error),/password|aciIdentityPrivate/);return true;
 });
 assert.equal(h.states.some(state=>state.state==='linked'),false);
});
test('cancelling a displayed QR closes its socket and leaves storage empty',async()=>{
 const h=harness({stall:true});const controller=new AbortController();
 const linking=startLink({signal:controller.signal,onState:state=>{if(state.state==='waiting')controller.abort()}},h.dependencies);
 await assert.rejects(linking,error=>error.name==='AbortError');
 assert.equal(h.closed,1);assert.equal(h.freed,1);assert.equal(h.saved.length,0);assert.equal(h.requests.length,0);
});
test('malformed encrypted envelope fails before a registration request',async()=>{
 const h=harness({invalidEnvelope:true});
 await assert.rejects(startLink({},h.dependencies),error=>error.code==='invalid_provisioning');
 assert.equal(h.requests.length,0);assert.equal(h.saved.length,0);assert.equal(h.closed,1);
});
test('network uncertainty preserves encrypted pending credentials without reporting linked',async()=>{
 const h=harness({fetchError:true});
 await assert.rejects(startLink({onState:state=>h.states.push(state)},h.dependencies),error=>error.registrationUncertain===true);
 assert.equal(h.pending.length,1);assert.equal(h.saved.length,0);assert.equal(h.cleared,0);
 assert.equal(h.states.some(state=>state.state==='linked'),false);
});
test('failure to save pending keys prevents registration entirely',async()=>{
 const h=harness({pendingError:true});
 await assert.rejects(startLink({},h.dependencies),error=>error.code==='storage_prepare');
 assert.equal(h.pending.length,0);assert.equal(h.requests.length,0);assert.equal(h.saved.length,0);
});
test('cancellation interrupts a stalled WASM load and cleans late resources',async()=>{
 const h=harness();const controller=new AbortController();let resolveClient,cleanupCount=0,started;
 const begun=new Promise(resolve=>{started=resolve});
 h.dependencies.createProxyClient=async ctx=>{
  started();await new Promise(resolve=>{resolveClient=resolve});
  ctx.defer(()=>cleanupCount++);return{client:{}};
 };
 const linking=startLink({signal:controller.signal},h.dependencies);
 await begun;controller.abort();await assert.rejects(linking,error=>error.name==='AbortError');
 resolveClient();await new Promise(resolve=>setTimeout(resolve,0));
 assert.equal(cleanupCount,1);assert.equal(h.requests.length,0);assert.equal(h.pending.length,0);
});
test('malformed confirmed response preserves pending keys and marks registration as accepted',async()=>{
 const h=harness({result:{deviceId:2,uuid:5}});
 await assert.rejects(startLink({},h.dependencies),error=>error.registered===true&&error.registrationUncertain===true);
 assert.equal(h.pending.length,1);assert.equal(h.saved.length,0);
});
test('full encrypted provisioning verifies actual libsignal ACI/PNI signatures and private-key durability',async()=>{
 const lib=await import('@getmaapp/signal-wasm');
 await lib.default({module_or_path:await readFile(new URL('../node_modules/@getmaapp/signal-wasm/signal_wasm_bg.wasm',import.meta.url))});
 const aciPrivate=lib.WasmPrivateKey.generate(),pniPrivate=lib.WasmPrivateKey.generate();
 const aciPublic=aciPrivate.getPublicKey(),pniPublic=pniPrivate.getPublicKey();
 const aciScalar=aciPrivate.serialize(),pniScalar=pniPrivate.serialize();
 const plaintext=concat(field(2,aciScalar),field(12,pniScalar),field(3,'+15555550123'),
  field(4,'server-issued-one-time-code'),field(6,key),field(8,ACI),field(10,PNI),field(13,key));
 let receive;const acknowledgements=[],networkPaths=[];let pending,saved;
 const dependencies={
  generateRegistrationKeys:privateKey=>generateRegistrationKeys(privateKey,{module:lib}),
  createProxyClient:async()=>({client:{fetch:async(url,options)=>{
   networkPaths.push(url);assert.ok(pending,'Private prekey records are saved before server activation');
   assert.equal(acknowledgements.length,2);assert.equal(url,'https://chat.signal.org/v1/devices/link');
   const requestBody=JSON.parse(options.body);
   assert.equal(requestBody.verificationCode,'server-issued-one-time-code');
   assert.equal(requestBody.accountAttributes.capabilities.spqr,true);
   for(const [namespace,identity] of [['aci',aciPublic],['pni',pniPublic]]){
    for(const suffix of ['SignedPreKey','PqLastResortPreKey']){
     const uploaded=requestBody[namespace+suffix];
     const pub=Buffer.from(uploaded.publicKey,'base64'),signature=Buffer.from(uploaded.signature,'base64');
     assert.equal(lib.verifyIdentitySignature(identity,pub,signature),true);
     assert.equal(pub.length,suffix==='SignedPreKey'?33:1569);
     assert.equal(pub[0],suffix==='SignedPreKey'?5:8);
    }
   }
   assert.equal(atob(options.headers.Authorization.slice(6)),`${ACI}:${pending.password}`);
   return{status:200,json:async()=>({uuid:ACI,pni:PNI,deviceId:3})};
  }}}),
  openSignalWebSocket:async(_client,url,options)=>{
   networkPaths.push(url);receive=options.onMessage;
   queueMicrotask(()=>receive(request('/v1/address',field(1,'real-encrypted-fixture-address'),1n)));
   return{send:async message=>acknowledgements.push(decodeFields(decodeFields(message).get(3))),close:async()=>{}};
  },
  savePendingAccount:async record=>{pending=JSON.parse(JSON.stringify(record))},
  clearPendingAccount:async()=>{pending=undefined},
  saveAccount:async record=>{saved=JSON.parse(JSON.stringify(record));pending=undefined},
 };
 try{
  const account=await startLink({deviceName:'Twang fixture',onState:state=>{
   if(state.state!=='waiting')return;
   const browserPublic=Buffer.from(new URL(state.url).searchParams.get('pub_key'),'base64');
   const recipient=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b656e032100','hex'),browserPublic.subarray(1)]),type:'spki',format:'der'});
   const phoneEphemeral=generateKeyPairSync('x25519');
   const secret=diffieHellman({privateKey:phoneEphemeral.privateKey,publicKey:recipient});
   const derived=Buffer.from(hkdfSync('sha256',secret,Buffer.alloc(32),Buffer.from('TextSecure Provisioning Message'),64));
   const iv=Buffer.alloc(16,7),cipher=createCipheriv('aes-256-cbc',derived.subarray(0,32),iv);
   const authenticated=Buffer.concat([Buffer.from([1]),iv,cipher.update(plaintext),cipher.final()]);
   const encrypted=Buffer.concat([authenticated,createHmac('sha256',derived.subarray(32)).update(authenticated).digest()]);
   const phonePublic=Buffer.concat([Buffer.from([5]),phoneEphemeral.publicKey.export({format:'der',type:'spki'}).subarray(-32)]);
   queueMicrotask(()=>receive(request('/v1/message',concat(field(1,phonePublic),field(2,encrypted)),2n)));
  }},dependencies);
  assert.equal(account.deviceId,3);assert.equal(saved.aciIdentityPrivate,base64(aciScalar));
  assert.equal(saved.pniIdentityPrivate,base64(pniScalar));assert.equal(pending,undefined);
  const signedStore=new lib.WasmInMemSignedPreKeyStore(),kyberStore=new lib.WasmInMemKyberPreKeyStore();
  await signedStore.import_signed_pre_key(1,Buffer.from(saved.aciPreKeys.signedPreKeyRecord,'base64'));
  await kyberStore.import_kyber_pre_key(1,Buffer.from(saved.aciPreKeys.pqLastResortPreKeyRecord,'base64'));
  assert.ok((await signedStore.export_signed_pre_key(1)).length>32);
  assert.ok((await kyberStore.export_kyber_pre_key(1)).length>3000);
  signedStore.free();kyberStore.free();
  assert.deepEqual(networkPaths,['wss://chat.signal.org/v1/websocket/provisioning/','https://chat.signal.org/v1/devices/link']);
 }finally{aciPublic.free();pniPublic.free();aciPrivate.free();pniPrivate.free();aciScalar.fill(0);pniScalar.fill(0);plaintext.fill(0)}
});
