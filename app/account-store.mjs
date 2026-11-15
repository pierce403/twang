// Local device credentials never enter reports, service-worker caches, or requests
// to the relay. IndexedDB stores an opaque ciphertext and a non-extractable key.
const DATABASE = 'twang-device';
const STORE = 'vault';
const MAX_RECORD = 512 * 1024;
const AAD = new TextEncoder().encode('twang-linked-account/v1');

function open() {
  if (!globalThis.indexedDB || !globalThis.crypto?.subtle) throw new Error('This browser cannot store linked-device keys');
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onerror = () => reject(new Error('Local account storage could not be opened'));
    request.onblocked = () => reject(new Error('Close other Twang tabs to update local account storage'));
    request.onsuccess = () => {
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
  });
}
function transaction(db, mode, work) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    let value;
    tx.oncomplete = () => resolve(value);
    tx.onabort = tx.onerror = () => reject(new Error('Local account storage transaction failed'));
    work(tx.objectStore(STORE), result => { value = result; });
  });
}
async function keyFor(db) {
  // Generate outside the transaction; a single read/write transaction makes key
  // initialization atomic even when two tabs are opened together.
  const candidate = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return transaction(db, 'readwrite', (store, result) => {
    const get = store.get('key');
    get.onsuccess = () => {
      if (get.result) result(get.result);
      else { store.put(candidate, 'key'); result(candidate); }
    };
  });
}
export async function prepareAccountStorage() {
  const db = await open();
  try { await keyFor(db); } finally { db.close(); }
}
function serialize(record) {
  const text = JSON.stringify(record, (_key, value) => {
    if (value instanceof Uint8Array) return { $twangBytes: Array.from(value) };
    if (value instanceof ArrayBuffer) return { $twangBytes: Array.from(new Uint8Array(value)) };
    return value;
  });
  if (!text || text.length > MAX_RECORD) throw new Error('Invalid linked-device record');
  return new TextEncoder().encode(text);
}
function deserialize(bytes) {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes), (_key, value) => {
    if (value && Object.keys(value).length === 1 && Array.isArray(value.$twangBytes)) {
      if (value.$twangBytes.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new Error('Invalid stored key bytes');
      return new Uint8Array(value.$twangBytes);
    }
    return value;
  });
}
function validate(record) {
  if (!record || typeof record !== 'object' || !Number.isSafeInteger(record.deviceId) ||
      record.deviceId < 2 || typeof record.aci !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(record.aci)) {
    throw new Error('A confirmed linked-device identity is required');
  }
}
function validateCandidate(record) {
  validate({ ...record, deviceId: 2 });
  if (typeof record.password !== 'string' || record.password.length < 16 || record.password.length > 256) throw new Error('Invalid pending device credentials');
}
async function saveRecord(record, name) {
  if (name === 'account') validate(record); else validateCandidate(record);
  const plaintext = serialize(record);
  const db = await open();
  try {
    const key = await keyFor(db);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, plaintext);
    const tagInput = new TextEncoder().encode(`${record.aci}\0${record.password}`);
    let owner;
    try { owner = new Uint8Array(await crypto.subtle.digest('SHA-256', tagInput)); }
    finally { tagInput.fill(0); }
    await transaction(db, 'readwrite', store => {
      const account = store.get('account');
      const pending = store.get('pending');
      pending.onsuccess = () => {
        const existing = pending.result?.owner;
        const matches = existing instanceof Uint8Array && existing.length === owner.length &&
          existing.every((byte, index) => byte === owner[index]);
        if (account.result || (name === 'pending' ? pending.result : !matches)) {
          store.transaction.abort();return;
        }
        store.put({ version: 1, iv, ciphertext, owner }, name);
        if (name === 'account') store.delete('pending');
      };
    });
  } finally { plaintext.fill(0); db.close(); }
}
async function loadRecord(name) {
  const db = await open();
  try {
    const stored = await transaction(db, 'readonly', (store, result) => {
      const get = store.get(name); get.onsuccess = () => result(get.result);
    });
    if (!stored) return null;
    if (stored.version !== 1) throw new Error('Unsupported local account format');
    const key = await transaction(db, 'readonly', (store, result) => {
      const get = store.get('key'); get.onsuccess = () => result(get.result);
    });
    const bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: stored.iv, additionalData: AAD }, key, stored.ciphertext));
    try { const record = deserialize(bytes);if (name === 'account') validate(record);else validateCandidate(record);return record; }
    finally { bytes.fill(0); }
  } catch { throw new Error('Stored device keys could not be decrypted. Remove this device locally and link again.'); }
  finally { db.close(); }
}
export const saveLinkedAccount = record => saveRecord(record, 'account');
export const loadLinkedAccount = () => loadRecord('account');
export const savePendingAccount = record => saveRecord(record, 'pending');
export const loadPendingAccount = () => loadRecord('pending');
export async function clearPendingAccount() {
  const db = await open();
  try { await transaction(db, 'readwrite', store => store.delete('pending')); }
  finally { db.close(); }
}
export async function forgetLinkedAccount() {
  const db = await open();
  try { await transaction(db, 'readwrite', store => store.clear()); }
  finally { db.close(); }
}
export function summarizeLinkedAccount(record) {
  validate(record);
  return { aci: record.aci, deviceId: record.deviceId,
    deviceName: String(record.deviceName || 'Twang').slice(0, 50),
    linkedAt: typeof record.linkedAt === 'string' ? record.linkedAt : undefined };
}
