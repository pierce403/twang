import { createProxyClient } from './proxy-transport.mjs';
import { openSignalWebSocket } from './link-socket.mjs';
import { generateProvisioningKeypair, decryptProvisioningEnvelope,
  generateRegistrationKeys, encryptDeviceName } from './link-crypto.mjs';

const text = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const MAX_MESSAGE = 65536;
const CHAT = 'https://chat.signal.org';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export class LinkError extends Error {
  constructor(code, message, options = {}) { super(message); this.name = 'LinkError'; this.code = code; Object.assign(this, options); }
}
const bad = () => { throw new LinkError('invalid_provisioning', 'Signal sent an invalid provisioning message. Try linking again.'); };
function bytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  bad();
}
export function base64(value) {
  return btoa(String.fromCharCode(...bytes(value)));
}
function varint(value) {
  let number = BigInt(value);
  if (number < 0n || number > 0xffffffffffffffffn) bad();
  const out = [];
  do { let byte = Number(number & 127n); number >>= 7n; if (number) byte |= 128; out.push(byte); } while (number);
  return Uint8Array.from(out);
}
function concat(parts) {
  const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
function field(number, value) {
  if (typeof value === 'number' || typeof value === 'bigint') return concat([varint(number * 8), varint(value)]);
  const data = typeof value === 'string' ? text.encode(value) : bytes(value);
  return concat([varint(number * 8 + 2), varint(data.length), data]);
}

// Narrow, bounded proto2 codec for Signal's SubProtocol and DeviceMessages.
// Preserve request IDs as uint64 values; do not round them through JS numbers.
export function decodeFields(input, repeated = new Set()) {
  const data = bytes(input);
  if (data.length > MAX_MESSAGE) bad();
  let position = 0;
  const readVarint = () => {
    let value = 0n;
    for (let shift = 0n; shift < 70n; shift += 7n) {
      if (position >= data.length) bad();
      const byte = data[position++];
      if (shift === 63n && byte > 1) bad();
      value |= BigInt(byte & 127) << shift;
      if (!(byte & 128)) return value;
    }
    bad();
  };
  const fields = new Map();
  while (position < data.length) {
    const tag = readVarint();
    const number = Number(tag >> 3n), wire = Number(tag & 7n);
    if (!number || number > 0x1fffffff || (fields.has(number) && !repeated.has(number))) bad();
    let value;
    if (wire === 0) value = readVarint();
    else if (wire === 2) {
      const length = readVarint();
      if (length > BigInt(data.length - position)) bad();
      value = data.slice(position, position + Number(length)); position += Number(length);
    } else if (wire === 1 || wire === 5) {
      const length = wire === 1 ? 8 : 4;
      if (position + length > data.length) bad();
      value = data.slice(position, position + length); position += length;
    } else bad();
    if (!repeated.has(number)) fields.set(number, value);
  }
  return fields;
}
const stringField = (fields, id, required = false) => {
  const value = fields.get(id);
  if (value === undefined && !required) return undefined;
  if (!(value instanceof Uint8Array)) bad();
  const result = decoder.decode(value);
  if (!result || result.length > 4096 || /[\u0000-\u001f]/.test(result)) bad();
  return result;
};
const keyField = (fields, id, length, required = false) => {
  const value = fields.get(id);
  if (value === undefined && !required) return undefined;
  if (!(value instanceof Uint8Array) || value.length !== length) bad();
  return value;
};
function uuidField(fields, stringId, binaryId, required = false) {
  const value = fields.get(binaryId);
  if (value !== undefined) {
    if (!(value instanceof Uint8Array) || value.length !== 16) bad();
    const hex = [...value].map(byte => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  }
  const result = stringField(fields, stringId, required);
  if (result !== undefined && !UUID.test(result)) bad();
  return result?.toLowerCase();
}
export function decodeProvisionMessage(input) {
  const fields = decodeFields(input);
  const aci = uuidField(fields, 8, 17, true), pni = uuidField(fields, 10, 18);
  const number = stringField(fields, 3);
  if (number !== undefined && !/^\+[1-9][0-9]{1,14}$/.test(number)) bad();
  const aciIdentityPrivate = keyField(fields, 2, 32, true);
  const pniIdentityPrivate = keyField(fields, 12, 32);
  if (pni ? (!number || !pniIdentityPrivate) : (pniIdentityPrivate || fields.has(11))) bad();
  const authCredentialSalt = keyField(fields, 19, 16);
  if (!pni && !authCredentialSalt) bad();
  const result = { aci, pni, number,
    provisioningCode: stringField(fields, 4, true), aciIdentityPrivate, pniIdentityPrivate,
    profileKey: keyField(fields, 6, 32, true), masterKey: keyField(fields, 13, 32),
    mediaRootBackupKey: keyField(fields, 16, 32), authCredentialSalt,
    accountEntropyPool: stringField(fields, 15),
    readReceipts: fields.get(7) === 1n };
  return result;
}
export function decodeProvisionRequest(input) {
  const frame = decodeFields(input);
  if (frame.get(1) !== 1n || !(frame.get(2) instanceof Uint8Array)) bad();
  const request = decodeFields(frame.get(2), new Set([5]));
  if (typeof request.get(4) !== 'bigint' || !(request.get(3) instanceof Uint8Array)) bad();
  if (stringField(request, 1, true) !== 'PUT') bad();
  return { id: request.get(4), path: stringField(request, 2, true), body: request.get(3) };
}
export function encodeProvisionResponse(id, status = 200) {
  return concat([field(1, 2), field(3, concat([field(1, id), field(2, status), field(3, status === 200 ? 'OK' : 'Bad request')]))]);
}
export function createLinkUrl(address, publicKey) {
  if (typeof address !== 'string' || !address || address.length > 512 || /[^\x20-\x7e]/.test(address)) bad();
  const key = bytes(publicKey);
  if (key.length !== 33 || key[0] !== 5) bad();
  const params = new URLSearchParams({uuid:address, pub_key:base64(key), capabilities:'nopni,nopni2'});
  return `sgnl://linkdevice?${params}`;
}
function password() { return base64(crypto.getRandomValues(new Uint8Array(16))).replace(/=+$/, ''); }
const STATUS_ERRORS = {
  403: ['rejected_code', 'The linking code expired or was rejected. Generate a new QR code.'],
  409: ['capability_required', 'Signal requires a capability this client could not provide.'],
  411: ['device_limit', 'This Signal account has reached its linked-device limit. Remove a device on your phone first.'],
  422: ['invalid_keys', 'Signal rejected the device registration keys.'],
  429: ['rate_limited', 'Signal rate-limited linking. Wait before trying again.'],
};
const toBase64Optional = value => value === undefined ? undefined : base64(value);
const serializePreKey = key => ({keyId:key.keyId,publicKey:base64(key.publicKey),signature:base64(key.signature)});
function serializeKeys(keys) {
  return {signedPreKey:serializePreKey(keys.signedPreKey),pqLastResortPreKey:serializePreKey(keys.pqLastResortPreKey),
    signedPreKeyRecord:base64(keys.signedPreKeyRecord),pqLastResortPreKeyRecord:base64(keys.pqLastResortPreKeyRecord)};
}

export async function startLink(options = {}, dependencies = {}) {
  const { deviceName = 'Twang', signal: externalSignal, onState = () => {} } = options;
  if (typeof deviceName !== 'string' || !deviceName.trim() || text.encode(deviceName).length > 50)
    throw new LinkError('device_name', 'Choose a device name containing 1–50 UTF-8 bytes.');
  const notify = state => { try { onState(state); } catch { /* UI must not expose or interrupt key handling. */ } };
  const controller = new AbortController();
  const abort = () => controller.abort(externalSignal.reason);
  if (externalSignal?.aborted) abort(); else externalSignal?.addEventListener('abort', abort, { once: true });
  const signal = controller.signal;
  const timeout = setTimeout(() => controller.abort(new LinkError('timeout', 'The linking session expired. Generate a new QR code.')), Math.max(1000, Math.min(options.timeoutMs ?? 180000, 240000)));
  const cleanups = [];
  let finalized = false;
  const cleanup = fn => { try { return Promise.resolve(fn()).catch(() => {}); } catch { return Promise.resolve(); } };
  const withAbort = operation => {
    const promise = Promise.resolve(operation);
    if (signal.aborted) { promise.catch(() => {}); signal.throwIfAborted(); }
    let onAbort;
    const aborted = new Promise((_resolve,reject) => { onAbort=()=>reject(signal.reason);signal.addEventListener('abort',onAbort,{once:true}); });
    return Promise.race([promise,aborted]).finally(()=>signal.removeEventListener('abort',onAbort));
  };
  const context = {signal, emit() {}, setPhase() {}, setEvidence() {},
    check: () => signal.throwIfAborted(), defer: fn => {if(finalized)void cleanup(fn);else cleanups.push(fn)}};
  const createClient = dependencies.createProxyClient ?? createProxyClient;
  const openSocket = dependencies.openSignalWebSocket ?? openSignalWebSocket;
  const makeKeypair = dependencies.generateProvisioningKeypair ?? generateProvisioningKeypair;
  const decrypt = dependencies.decryptProvisioningEnvelope ?? decryptProvisioningEnvelope;
  const makePreKeys = dependencies.generateRegistrationKeys ?? generateRegistrationKeys;
  const makeName = dependencies.encryptDeviceName ?? encryptDeviceName;
  const save = dependencies.saveAccount ?? options.saveAccount ?? (async record => {
    const {saveLinkedAccount} = await import('./account-store.mjs'); return saveLinkedAccount(record);
  });
  const savePending = dependencies.savePendingAccount ?? (async record => {
    const {savePendingAccount} = await import('./account-store.mjs'); return savePendingAccount(record);
  });
  const clearPending = dependencies.clearPendingAccount ?? (async () => {
    const {clearPendingAccount} = await import('./account-store.mjs'); return clearPendingAccount();
  });
  let record, pendingSaved = false, registrationSent = false, serverConfirmed = false;
  try {
    context.check(); notify({state:'preparing'});
    const pair = await withAbort(makeKeypair()); context.check();
    const {client} = await withAbort(createClient(context)); context.check();
    let socket;
    let addressSeen = false, envelopeSeen = false;
    let ready;
    const socketReady = new Promise(resolve => { ready = resolve; });
    const provision = await new Promise(async (resolve, reject) => {
      const onAbort = () => reject(signal.reason);
      signal.addEventListener('abort', onAbort, {once:true});
      context.defer(() => signal.removeEventListener('abort', onAbort));
      let messages = Promise.resolve();
      const receive = data => {
        messages = messages.then(async () => {
          await socketReady; context.check();
          const request = decodeProvisionRequest(data);
          if (request.path === '/v1/address' && !addressSeen && !envelopeSeen) {
            addressSeen = true;
            const address = stringField(decodeFields(request.body),1,true);
            await socket.send(encodeProvisionResponse(request.id)); context.check();
            notify({state:'waiting',url:createLinkUrl(address,pair.publicKey)});
          } else if (request.path === '/v1/message' && addressSeen && !envelopeSeen) {
            envelopeSeen = true;
            const envelope = decodeFields(request.body);
            const publicKey = keyField(envelope,1,33,true), body = envelope.get(2);
            if (!(body instanceof Uint8Array)) bad();
            const plaintext = await withAbort(decrypt(pair.privateKey,{publicKey,body}));
            let message;
            try { message = decodeProvisionMessage(plaintext); } finally { plaintext.fill(0); }
            await socket.send(encodeProvisionResponse(request.id)); context.check();
            resolve(message);
          } else bad();
        }).catch(reject);
      };
      try {
        socket = await withAbort(openSocket(client, `${CHAT.replace('https:','wss:')}/v1/websocket/provisioning/`, {
          signal, onMessage:receive, onClose:() => { if (!envelopeSeen) reject(new LinkError('closed','The provisioning connection closed. Generate a new QR code.')); },
        }).then(value=>{context.defer(()=>value.close(1000,'Linking session complete'));return value}));
        ready();
      } catch (error) { reject(error); }
    });
    context.check(); notify({state:'authorizing'});
    const [aciKeys,pniKeys] = await withAbort(Promise.all([makePreKeys(provision.aciIdentityPrivate),
      provision.pni ? makePreKeys(provision.pniIdentityPrivate) : undefined]));
    context.check();
    record = {schema:1,linkedAt:new Date().toISOString(),deviceName:deviceName.trim(),
      aci:provision.aci,pni:provision.pni,number:provision.number,password:password(),
      registrationId:aciKeys.registrationId,pniRegistrationId:pniKeys?.registrationId,
      aciIdentityPrivate:base64(provision.aciIdentityPrivate),aciIdentityPublic:base64(aciKeys.identityPublic),
      pniIdentityPrivate:toBase64Optional(provision.pniIdentityPrivate),pniIdentityPublic:toBase64Optional(pniKeys?.identityPublic),
      profileKey:base64(provision.profileKey),masterKey:toBase64Optional(provision.masterKey),
      accountEntropyPool:provision.accountEntropyPool,authCredentialSalt:toBase64Optional(provision.authCredentialSalt),
      mediaRootBackupKey:toBase64Optional(provision.mediaRootBackupKey),readReceipts:provision.readReceipts,
      aciPreKeys:serializeKeys(aciKeys),pniPreKeys:pniKeys ? serializeKeys(pniKeys) : undefined};
    const nameParts = await withAbort(makeName(record.deviceName,aciKeys.identityPublic));
    const encryptedDeviceName = base64(concat([field(1,nameParts.ephemeralPublic),field(2,nameParts.syntheticIv),field(3,nameParts.ciphertext)]));
    const body = {verificationCode:provision.provisioningCode,accountAttributes:{
      fetchesMessages:true,name:encryptedDeviceName,registrationId:record.registrationId,
      ...(provision.pni ? {pniRegistrationId:record.pniRegistrationId} : {}),
      capabilities:{spqr:true,usernameChangeSyncMessage:true,optionalPhoneNumber:true,storage:false,attachmentBackfill:false},
    },aciSignedPreKey:record.aciPreKeys.signedPreKey,aciPqLastResortPreKey:record.aciPreKeys.pqLastResortPreKey,
      ...(pniKeys ? {pniSignedPreKey:record.pniPreKeys.signedPreKey,pniPqLastResortPreKey:record.pniPreKeys.pqLastResortPreKey} : {})};
    context.check();
    try { await savePending(record); pendingSaved = true; }
    catch { throw new LinkError('storage_prepare','This browser could not securely save the device keys. No registration was sent.'); }
    context.check();
    registrationSent = true;
    const response = await withAbort(client.fetch(`${CHAT}/v1/devices/link`,{method:'PUT',redirect:'error',credentials:'omit',
      headers:{'Content-Type':'application/json','Authorization':`Basic ${btoa(`${provision.aci}:${record.password}`)}`},body:JSON.stringify(body)}));
    if (response.status !== 200) {
      if (response.status >= 400 && response.status < 500 && response.status !== 408) {
        await clearPending(); pendingSaved = false; registrationSent = false;
      }
      await response.body?.cancel();
      const [code,message] = STATUS_ERRORS[response.status] ?? ['server_error','Signal could not complete device linking. Try again later.'];
      throw new LinkError(code,message,{status:response.status});
    }
    serverConfirmed = true;
    const result = await withAbort(response.json());
    if (!Number.isInteger(result.deviceId) || result.deviceId < 2 || result.deviceId > 127 ||
      (result.uuid !== undefined && (typeof result.uuid !== 'string' || result.uuid.toLowerCase() !== provision.aci)) ||
      (result.pni !== undefined && result.pni !== null && (typeof result.pni !== 'string' || result.pni.toLowerCase() !== provision.pni)))
      throw new LinkError('invalid_confirmation','Signal returned an invalid device confirmation. Check Linked devices on your phone.',{registered:true});
    record.deviceId = result.deviceId;
    try { await save(record); pendingSaved = false; }
    catch {
      const error = new LinkError('storage_failed','The device linked, but this browser could not save its keys. Remove Twang in Linked devices on your phone before trying again.',{registered:true,deviceId:record.deviceId});
      Object.defineProperty(error,'accountRecord',{value:record}); throw error;
    }
    notify({state:'linked',deviceId:record.deviceId,deviceName:record.deviceName,aci:record.aci});
    return record;
  } catch (error) {
    if (pendingSaved && !registrationSent) {
      try { await clearPending(); pendingSaved = false; } catch { /* Keep recoverable encrypted keys. */ }
    }
    if (pendingSaved && registrationSent) {
      const failure = error instanceof LinkError ? error : new LinkError('registration_uncertain',
        serverConfirmed ? 'Signal accepted the device, but finalization could not complete. Check Linked devices on your phone.' :
          'The registration response was interrupted. Device keys were preserved; check Linked devices on your phone before trying again.');
      failure.registrationUncertain = true;
      if (!serverConfirmed) failure.message = 'The registration response could not be confirmed. Device keys were preserved; check Linked devices on your phone before trying again.';
      if (serverConfirmed) failure.registered = true;
      throw failure;
    }
    if (signal.aborted) throw signal.reason ?? new DOMException('Linking cancelled','AbortError');
    if (error instanceof LinkError) throw error;
    throw new LinkError('connection_failed','Device linking could not complete. Check the proxy connection and try again.');
  } finally {
    finalized = true;
    clearTimeout(timeout); externalSignal?.removeEventListener('abort',abort);
    for (const fn of cleanups.reverse()) await cleanup(fn);
  }
}
