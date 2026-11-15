import { startLink } from './link-protocol.mjs';
import { prepareAccountStorage, loadLinkedAccount, loadPendingAccount, forgetLinkedAccount, summarizeLinkedAccount } from './account-store.mjs';
import { setPwaBusy } from './pwa.mjs';

const $ = id => document.getElementById(id);
let controller;
let pairingUrl;
let view = 0;
let linked = false;
let loading = true;
let pending = false;
let qrGeneration = 0;
function status(text) { $('link-status').textContent = text; }
function clearQr() {
  qrGeneration++;
  pairingUrl = undefined;
  $('link-qr').replaceChildren();
  $('link-qr').hidden = true;
  $('link-copy').hidden = true;
}
function busy(value) {
  setPwaBusy(value, 'link');
  $('link-start').disabled = value || linked || loading || pending;
  $('link-device-name').disabled = value || linked;
  $('link-cancel').hidden = !value;
  $('link-forget').disabled = value;
}
function showAccount(record) {
  const account = summarizeLinkedAccount(record);
  linked = true;
  $('link-account-summary').textContent = `${account.deviceName} · linked device ${account.deviceId}. Keys are stored on this browser. History has not been imported.`;
  $('link-account-summary').hidden = false;
  $('link-forget').hidden = false;
  status('Account linked');
  clearQr();
}
function error(text) {
  $('link-error').textContent = text;
  $('link-error').hidden = false;
}
async function showQr(url, current) {
  const generation = qrGeneration;
  const qr = await import('../vendor/qrcode/qrcode.mjs');
  if (current !== view || generation !== qrGeneration || controller?.signal.aborted) return;
  const canvas = document.createElement('canvas');
  await qr.default.toCanvas(canvas, url, { width: 280, margin: 4,
    errorCorrectionLevel: 'M', color: { dark: '#17131fff', light: '#ffffffff' } });
  if (current !== view || generation !== qrGeneration || controller?.signal.aborted) return;
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', 'Signal linked-device pairing QR code');
  $('link-qr').replaceChildren(canvas);
  $('link-qr').hidden = false;
  pairingUrl = url;
  $('link-copy').hidden = false;
}
$('link-start').addEventListener('click', async () => {
  if (controller || linked || loading) return;
  const deviceName = $('link-device-name').value.trim();
  if (!deviceName || new TextEncoder().encode(deviceName).length > 50) {
    error('Choose a device name of 1–50 UTF-8 bytes.'); return;
  }
  $('link-error').hidden = true;
  clearQr();
  controller = new AbortController();
  const signal = controller.signal;
  const current = ++view;
  busy(true);
  try {
    await prepareAccountStorage();
    await startLink({ deviceName, signal, onState: event => {
      if (current !== view || signal.aborted) return;
      const labels = { preparing: 'Preparing a secure link…', waiting: 'Scan with Signal on your phone',
        authorizing: 'Confirming this device with Signal…', linked: 'Account linked' };
      status(labels[event.state] || 'Connecting to Signal…');
      if (event.state === 'waiting' && event.url) {
        showQr(event.url, current).catch(() => {
          if (current !== view) return;
          error('The pairing QR could not be drawn. Try linking again.');controller?.abort();
        });
      } else if (event.state === 'authorizing') clearQr();
    } }).then(showAccount);
  } catch (failure) {
    clearQr();
    if (failure.registrationUncertain) {
      pending = true;$('link-forget').hidden = false;
      status('Link confirmation interrupted');
      error('Signal may have accepted this device. Check Signal → Settings → Linked devices and unlink Twang before clearing the pending keys and trying again.');
    } else if (failure.registered) {
      pending = true;$('link-forget').hidden = false;
      status('Device accepted; local save failed');
      error('Signal accepted this device, but its keys could not be saved here. Unlink Twang in Signal → Settings → Linked devices before trying again.');
    } else if (signal.aborted) status('Link cancelled');
    else { status('Not linked');error(failure.message || 'The account could not be linked. Try again.'); }
  } finally { controller = undefined;busy(false); }
});
$('link-cancel').addEventListener('click', () => { view++;controller?.abort();clearQr(); });
$('link-copy').addEventListener('click', async () => {
  if (!pairingUrl) return;
  try { await navigator.clipboard.writeText(pairingUrl);status('Pairing link copied'); }
  catch { error('Clipboard access is unavailable. Scan the QR code instead.'); }
});
$('link-forget').addEventListener('click', async () => {
  if (controller || (!linked && !pending)) return;
  if (!window.confirm('Remove the device keys from this browser? Also unlink Twang in Signal → Settings → Linked devices to stop delivery.')) return;
  try {
    await forgetLinkedAccount();linked = false;pending = false;
    $('link-account-summary').hidden = true;$('link-forget').hidden = true;
    $('link-error').hidden = true;status('Ready to link an existing account');busy(false);
  } catch { error('Local keys could not be removed. Try again.'); }
});
Promise.all([loadLinkedAccount(), loadPendingAccount()]).then(([record, candidate]) => {
  if (record) showAccount(record);
  else if (candidate) {
    pending = true;$('link-forget').hidden = false;
    status('Previous link needs review');
    error('A previous device link was interrupted. Check Signal → Settings → Linked devices, unlink Twang if listed, then remove these local keys before trying again.');
  }
  else status('Ready to link an existing account');
}).catch(() => {
  status('Local account unavailable');
  error('Stored keys could not be read. Clear this site’s local data and link again.');
}).finally(() => { loading = false;busy(false); });
busy(false);
