import { test } from 'node:test';
import assert from 'node:assert/strict';
import 'fake-indexeddb/auto';
import { prepareAccountStorage, saveLinkedAccount, loadLinkedAccount, forgetLinkedAccount, summarizeLinkedAccount,
 savePendingAccount,loadPendingAccount,clearPendingAccount } from '../app/account-store.mjs';
const account = { aci: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', deviceId: 2,
  deviceName: 'Twang', password: 'local-fixture-not-a-real-password',
  identityKey: new Uint8Array([0, 255, 127]), linkedAt: '2026-11-15T00:00:00Z' };
async function saveConfirmed(record) { await savePendingAccount(record);await saveLinkedAccount(record); }
async function rawVault() {
  const request = indexedDB.open('twang-device', 1);
  const db = await new Promise(resolve => { request.onsuccess = () => resolve(request.result); });
  try {
    const tx = db.transaction('vault', 'readonly');
    const keys = tx.objectStore('vault').getAll();
    return await new Promise(resolve => { keys.onsuccess = () => resolve(keys.result); });
  } finally { db.close(); }
}
test('account vault persists encrypted credentials and non-extractable key', async () => {
  await forgetLinkedAccount();
  assert.equal(await loadLinkedAccount(), null);
  await Promise.all([prepareAccountStorage(), prepareAccountStorage()]);
  await saveConfirmed(account);
  assert.deepEqual(await loadLinkedAccount(), account);
  const values = await rawVault();
  assert.equal(JSON.stringify(values).includes(account.password), false);
  const key = values.find(value => value instanceof CryptoKey);
  assert.equal(key.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', key));
  assert.deepEqual(Object.keys(summarizeLinkedAccount(account)).sort(), ['aci', 'deviceId', 'deviceName', 'linkedAt']);
  await forgetLinkedAccount();assert.equal(await loadLinkedAccount(), null);
});
test('vault refuses unconfirmed or primary-device credentials', async () => {
  await assert.rejects(saveLinkedAccount({ ...account, deviceId: 1 }));
  await assert.rejects(saveLinkedAccount({ ...account, aci: 'not-an-aci' }));
});
test('ciphertext tampering cannot produce a linked account', async () => {
  await saveConfirmed(account);
  const request = indexedDB.open('twang-device', 1);
  const db = await new Promise(resolve => { request.onsuccess = () => resolve(request.result); });
  await new Promise((resolve, reject) => {
    const tx = db.transaction('vault', 'readwrite');const store = tx.objectStore('vault');
    const get = store.get('account');
    get.onsuccess = () => {
      const record = get.result;new Uint8Array(record.ciphertext)[0] ^= 1;store.put(record, 'account');
    };
    tx.oncomplete = resolve;tx.onerror = reject;
  });
  db.close();
  await assert.rejects(loadLinkedAccount(), /could not be decrypted/);
  await forgetLinkedAccount();
});
test('pending keys survive uncertainty without claiming a linked device',async()=>{
 await forgetLinkedAccount();
 const {deviceId,...pending}=account;
 await savePendingAccount(pending);
 assert.equal(await loadLinkedAccount(),null);
 assert.deepEqual(await loadPendingAccount(),pending);
 assert.equal(JSON.stringify(await rawVault()).includes(pending.password),false);
 await saveLinkedAccount(account);
 assert.equal(await loadPendingAccount(),null);
 assert.deepEqual(await loadLinkedAccount(),account);
 await assert.rejects(savePendingAccount(pending));await clearPendingAccount();
 assert.equal(await loadPendingAccount(),null);
 assert.deepEqual(await loadLinkedAccount(),account);
 await forgetLinkedAccount();
});
test('two tabs cannot overwrite pending or confirmed device keys',async()=>{
 await forgetLinkedAccount();
 const other={...account,password:'different-fixture-password-12345678'};
 const outcomes=await Promise.allSettled([savePendingAccount(account),savePendingAccount(other)]);
 assert.equal(outcomes.filter(result=>result.status==='fulfilled').length,1);
 const pending=await loadPendingAccount();
 const loser=pending.password===account.password?other:account;
 await assert.rejects(saveLinkedAccount(loser));
 assert.equal((await loadPendingAccount()).password,pending.password);
 await saveLinkedAccount({...pending,deviceId:2});
 await assert.rejects(savePendingAccount(loser));
 await assert.rejects(saveLinkedAccount(loser));
 assert.equal((await loadLinkedAccount()).password,pending.password);
 await forgetLinkedAccount();
});
