const busyReasons = new Set();
let registration;
let installPrompt;
let reloadRequested = false;
let reloadAvailable = false;

function updateButton() {
  if (typeof document === 'undefined') return;
  const button = document.querySelector('#pwa-update');
  if (!button) return;
  button.hidden = !registration?.waiting && !reloadAvailable;
  button.disabled = busyReasons.size > 0;
  button.title = busyReasons.size ? 'Finish the active connection before updating' : 'Update the app shell';
  button.textContent = registration?.waiting ? 'Update app' : 'Reload app';
}

// Separate reason strings let linking and a diagnostic run overlap safely.
export function setPwaBusy(active, reason = 'app') {
  if (active) busyReasons.add(reason); else busyReasons.delete(reason);
  updateButton();
}

export function canRegisterPwa(location, secureContext) {
  return location.protocol === 'https:' || Boolean(secureContext &&
    location.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname));
}

export async function registerPwa() {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator) ||
      !canRegisterPwa(window.location, window.isSecureContext)) return;
  const install = document.querySelector('#install-app');
  const update = document.querySelector('#pwa-update');
  let hadController = Boolean(navigator.serviceWorker.controller);
  const status = message => {
    const target = document.querySelector('#pwa-status');
    if (target) target.textContent = message;
  };

  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault();
    installPrompt = event;
    if (install) install.hidden = false;
  });
  window.addEventListener('appinstalled', () => {
    installPrompt = undefined;
    if (install) install.hidden = true;
  });
  install?.addEventListener('click', async () => {
    if (!installPrompt) return;
    const prompt = installPrompt;
    installPrompt = undefined;
    install.hidden = true;
    try { await prompt.prompt(); await prompt.userChoice; }
    catch { status('Use your browser menu to install Twang.'); }
  });

  navigator.serviceWorker.addEventListener('message', event => {
    if (event.data?.type === 'TWANG_PWA_STATE_REQUEST')
      event.ports[0]?.postMessage({ busy: busyReasons.size > 0 });
    if (event.data?.type === 'TWANG_PWA_UPDATE_BLOCKED') {
      reloadRequested = false;
      status('Finish active connections in your Twang tabs before updating.');
      updateButton();
    }
  });
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!hadController) { hadController = true; return; }
    if (reloadRequested && !busyReasons.size) window.location.reload();
    else { reloadAvailable = true; updateButton(); }
  });
  update?.addEventListener('click', () => {
    if (busyReasons.size) return;
    if (registration?.waiting) {
      reloadRequested = true;
      registration.waiting.postMessage({ type: 'TWANG_PWA_ACTIVATE' });
    } else if (reloadAvailable) window.location.reload();
  });

  try {
    registration = await navigator.serviceWorker.register('/sw.js', { scope: '/', updateViaCache: 'none' });
    updateButton();
    registration.addEventListener('updatefound', () => {
      const worker = registration.installing;
      worker?.addEventListener('statechange', () => {
        if (worker.state === 'installed') updateButton();
      });
    });
  } catch {
    status('Offline installation is unavailable in this browser. The online app still works.');
  }
}

if (typeof window !== 'undefined') void registerPwa();
