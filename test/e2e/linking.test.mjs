import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startLinkingFixture } from './linking-fixture.mjs';

async function waitUntilLinkReady(page) {
  // The HTML fallback can render before module bootstrap and IndexedDB loading.
  // Wait for the initialized UI, not just an enabled fallback button.
  await page.waitForFunction(() =>
    document.querySelector('#link-status')?.textContent === 'Ready to link an existing account' &&
    document.querySelector('#link-start')?.disabled === false);
}

async function vaultSnapshot(page) {
  return page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => { const req = indexedDB.open('twang-device', 1); req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error); });
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction('vault', 'readonly'), store = tx.objectStore('vault');
        const keys = store.getAllKeys(), values = store.getAll();
        tx.oncomplete = () => resolve(keys.result.map((key, i) => {
          const value = values.result[i];
          return value instanceof CryptoKey ? { key, kind: value.type, extractable: value.extractable, algorithm: value.algorithm.name }
            : { key, fields: Object.keys(value).sort(), version: value.version, ivBytes: value.iv?.byteLength, ownerBytes: value.owner?.byteLength,
              ciphertext: Array.from(new Uint8Array(value.ciphertext)) };
        }));
        tx.onerror = () => reject(tx.error);
      });
    } finally { db.close(); }
  });
}

test('existing account links through real browser crypto and survives reload with encrypted local keys', { timeout: 60000 }, async t => {
  const fixture = await startLinkingFixture(); t.after(() => fixture.close());
  const browser = await chromium.launch({ ...(process.env.TWANG_CHROMIUM_PATH ? { executablePath: process.env.TWANG_CHROMIUM_PATH } : {}), args: ['--no-sandbox'] });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(fixture.url);
  await waitUntilLinkReady(page);
  await page.locator('#link-device-name').fill('Twang fixture 蜘蛛');
  await page.locator('#link-start').click();
  const qr = page.locator('#link-qr canvas'); await qr.waitFor({ timeout: 20000 });
  assert.equal(await qr.getAttribute('aria-label'), 'Signal linked-device pairing QR code');
  assert.ok(await qr.evaluate(canvas => canvas.width >= 280 && canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data.some(byte => byte > 0)));
  await page.locator('#link-copy').click();
  let deadline;
  const registration = await Promise.race([fixture.registration, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Browser never sent fixture device link')), 20000); })]).finally(() => clearTimeout(deadline));
  assert.ok(registration, fixture.state.failure);
  assert.equal(registration.deviceName, 'Twang fixture 蜘蛛');
  const pending = await vaultSnapshot(page);
  assert.deepEqual(pending.map(item => item.key).sort(), ['key', 'pending']);
  assert.equal(pending.find(item => item.key === 'key').extractable, false);
  assert.equal(pending.find(item => item.key === 'key').algorithm, 'AES-GCM');
  const encrypted = pending.find(item => item.key === 'pending');
  assert.deepEqual(encrypted.fields, ['ciphertext', 'iv', 'owner', 'version']); assert.equal(encrypted.ivBytes, 12); assert.equal(encrypted.ownerBytes, 32); assert.ok(encrypted.ciphertext.length > 1000);
  for (const secret of [fixture.state.secrets.identity, fixture.state.secrets.profile, registration.password])
    assert.ok(!Buffer.from(encrypted.ciphertext).includes(Buffer.from(secret)), 'Vault record contains plaintext credentials');
  fixture.confirm();
  await page.waitForFunction(() => document.querySelector('#link-status')?.textContent === 'Account linked');
  assert.match(await page.locator('#link-account-summary').textContent(), /Twang fixture 蜘蛛 · linked device 2/);
  assert.equal(await page.locator('#link-qr').isHidden(), true);
  assert.equal(await page.locator('#link-copy').isHidden(), true);
  assert.equal(await page.locator('#link-start').isDisabled(), true);
  const confirmed = await vaultSnapshot(page);
  assert.deepEqual(confirmed.map(item => item.key).sort(), ['account', 'key']);
  assert.deepEqual(fixture.state.acks, ['9007199254740995', '9007199254740996']);
  assert.deepEqual(fixture.state.requests, [{ method: 'GET', path: '/v1/websocket/provisioning/' }, { method: 'PUT', path: '/v1/devices/link' }]);
  const cacheData = await page.evaluate(async () => {
    const output = [];
    for (const name of await caches.keys()) for (const request of await (await caches.open(name)).keys()) {
      const response = await (await caches.open(name)).match(request);
      output.push({ url: request.url, text: /\.(?:m?js|css|html|pem|webmanifest)$/.test(new URL(request.url).pathname) ? await response.text() : '' });
    }
    return output;
  });
  const pairingUrl = fixture.state.pairingUrl;
  assert.ok(!JSON.stringify(cacheData).includes(pairingUrl));
  assert.ok(cacheData.every(item => !/\/v1\/|proxy\.twang|__linking__/.test(item.url)));
  await page.reload();
  await page.waitForFunction(() => document.querySelector('#link-status')?.textContent === 'Account linked');
  assert.match(await page.locator('#link-account-summary').textContent(), /linked device 2/);
  assert.equal(fixture.state.requests.length, 2, 'Reload made extra account or history requests');
  assert.deepEqual(errors, []);
});

test('rejected fixture linking clears pending keys and leaves the browser unlinked', { timeout: 60000 }, async t => {
  const fixture = await startLinkingFixture({ failRegistration: true }); t.after(() => fixture.close());
  const browser = await chromium.launch({ ...(process.env.TWANG_CHROMIUM_PATH ? { executablePath: process.env.TWANG_CHROMIUM_PATH } : {}), args: ['--no-sandbox'] });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(fixture.url);
  await waitUntilLinkReady(page);
  await page.locator('#link-start').click();
  await page.locator('#link-qr canvas').waitFor({ timeout: 20000 });
  await page.locator('#link-copy').click();
  let deadline;
  assert.ok(await Promise.race([fixture.registration, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('No fixture link request')), 20000); })]).finally(() => clearTimeout(deadline)), fixture.state.failure);
  assert.ok((await vaultSnapshot(page)).some(item => item.key === 'pending'));
  fixture.confirm();
  await page.waitForFunction(() => document.querySelector('#link-status')?.textContent === 'Not linked');
  assert.match(await page.locator('#link-error').textContent(), /expired|rejected/i);
  assert.deepEqual((await vaultSnapshot(page)).map(item => item.key), ['key']);
  assert.equal(await page.locator('#link-qr').isHidden(), true);
  assert.equal(await page.locator('#link-start').isDisabled(), false);
  await page.reload();
  await waitUntilLinkReady(page);
  assert.equal(await page.locator('#link-status').textContent(), 'Ready to link an existing account');
  assert.deepEqual(fixture.state.requests.map(item => item.path), ['/v1/websocket/provisioning/', '/v1/devices/link']);
});
