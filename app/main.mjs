import {
  SIGNAL_ENDPOINTS, TRUST_POLICY,
  probeDirectHttps, probeDirectWebSocket,
  probeRelayTls, probeRelayHttps, probeRelayProvisioning,
} from './transport.mjs';

const $ = (selector) => document.querySelector(selector);
const form = $('#probe-form');
const kind = $('#probe-kind');
const relayField = $('#relay-field');
const relayInput = $('#relay-url');
const results = [];
const events = [];
let controller;
let running = false;
let sequence = 0;

const route = () => form.elements.route.value;
const checkedHosts = () => [...form.querySelectorAll('input[name="endpoint"]:checked:not(:disabled)')].map((input) => input.value);
const create = (tag, className, text) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};
const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
relayInput.value = local
  ? `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/wisp/`
  : `wss://${location.host}/wisp/`;

function setEnvironment() {
  $('#secure-label').textContent = window.isSecureContext ? 'Secure context' : 'Insecure context';
  $('#secure-indicator').style.backgroundColor = window.isSecureContext ? '#83a25c' : '#c49755';
  $('#wasm-label').textContent = typeof WebAssembly === 'object' ? 'WebAssembly available' : 'WebAssembly unavailable';
  $('#online-label').textContent = navigator.onLine ? 'Browser reports online' : 'Browser reports offline';
}
setEnvironment();
window.addEventListener('online', setEnvironment);
window.addEventListener('offline', setEnvironment);
$('#trust-policy').textContent = TRUST_POLICY;

function addEndpoint(target, parent) {
  const label = create('label', 'endpoint');
  const input = create('input');
  input.type = 'checkbox';
  input.name = 'endpoint';
  input.value = target.host;
  input.checked = ['chat.signal.org', 'grpc.chat.signal.org'].includes(target.host);
  const info = create('span', 'endpoint-info');
  info.append(create('span', 'endpoint-host', target.host), create('span', 'endpoint-description', target.description || target.label));
  label.append(input, info);
  if (target.provisioning) label.append(create('span', 'endpoint-tag', 'CHAT'));
  parent.append(label);
}
const endpointList = $('#endpoint-list');
SIGNAL_ENDPOINTS.slice(0, 5).forEach((target) => addEndpoint(target, endpointList));
if (SIGNAL_ENDPOINTS.length > 5) {
  const more = create('details', 'more-endpoints');
  more.append(create('summary', '', `More service endpoints (${SIGNAL_ENDPOINTS.length - 5})`));
  SIGNAL_ENDPOINTS.slice(5).forEach((target) => addEndpoint(target, more));
  endpointList.append(more);
}

function updateConfiguration() {
  const useRelay = route() === 'relay';
  relayField.hidden = !useRelay;
  const oldKind = kind.value;
  kind.replaceChildren();
  const options = useRelay
    ? [['tls', 'TLS handshake'], ['https', 'HTTPS response'], ['websocket', 'Provisioning WebSocket']]
    : [['https', 'HTTPS response'], ['websocket', 'Provisioning WebSocket']];
  for (const [value, text] of options) {
    const option = create('option', '', text);
    option.value = value;
    kind.append(option);
  }
  kind.value = options.some(([value]) => value === oldKind) ? oldKind : options[0][0];
  $('#route-help').textContent = useRelay
    ? 'The browser runs the Signal TLS connection in WebAssembly. Your relay only forwards encrypted bytes.'
    : 'Use the browser’s own networking. A failed probe may reflect certificate trust, CORS, or server policy.';
  updateKind();
}
function updateKind() {
  const descriptions = {
    tls: 'Completes a certificate-validated TLS handshake to the selected host. No application request is sent.',
    https: 'Requests the endpoint root. Any readable HTTP status proves that an HTTP response arrived.',
    websocket: 'Opens an unauthenticated provisioning socket, decodes its temporary address, then closes. No device is linked.',
  };
  $('#kind-help').textContent = descriptions[kind.value];
  for (const input of form.querySelectorAll('input[name="endpoint"]')) {
    const target = SIGNAL_ENDPOINTS.find((entry) => entry.host === input.value);
    input.disabled = running || (kind.value === 'websocket' && !target.provisioning);
  }
  updateCount();
}
function updateCount() {
  $('#run-count').textContent = String(checkedHosts().length);
  $('#run').disabled = running || checkedHosts().length === 0;
}
form.addEventListener('change', (event) => {
  if (event.target.name === 'route') updateConfiguration();
  else if (event.target === kind) updateKind();
  else updateCount();
});
updateConfiguration();

function addEvent(event, host = '') {
  const entry = {
    time: new Date().toISOString(),
    host,
    level: event.level || 'info',
    stage: event.stage || event.phase || '',
    message: String(event.message || ''),
    ...(event.details !== undefined ? { details: event.details } : {}),
  };
  events.push(entry);
  if (events.length > 300) events.shift();
  const log = $('#log-entries');
  log.querySelector('.log-placeholder')?.remove();
  const row = create('div', 'log-entry');
  row.dataset.level = entry.level;
  const time = create('time', '', new Date(entry.time).toLocaleTimeString([], {hour12: false}));
  time.dateTime = entry.time;
  row.append(time, create('span', 'log-level', entry.level), create('span', 'log-message', `${host ? `${host} · ` : ''}${entry.message}`));
  log.append(row);
  while (log.childElementCount > 300) log.firstElementChild.remove();
  log.scrollTop = log.scrollHeight;
  $('#event-count').textContent = `${events.length} event${events.length === 1 ? '' : 's'}`;
  $('#clear').disabled = running;
}

function resultCard(record) {
  $('#empty-state')?.remove();
  $('.cleared-state')?.remove();
  const article = create('article', 'result-card');
  article.dataset.state = 'working';
  const top = create('div', 'result-top');
  top.append(create('h3', 'result-host', record.host), create('span', 'pill working', 'Connecting'));
  const meta = create('p', 'result-meta', `${record.route === 'relay' ? 'TLS via relay' : 'Direct browser'} · ${record.kind === 'websocket' ? 'Provisioning WebSocket' : record.kind.toUpperCase()}`);
  article.append(top, meta, create('p', 'result-summary', 'Starting probe…'));
  $('#results').prepend(article);
  return article;
}
function finishCard(card, record) {
  const state = record.result.ok ? 'success' : record.result.status === 'cancelled' ? 'neutral' : /timeout/i.test(record.result.status || '') ? 'timeout' : 'failure';
  card.dataset.state = state;
  const pill = card.querySelector('.pill');
  pill.className = `pill ${state}`;
  pill.textContent = record.result.ok ? 'Connected' : state === 'neutral' ? 'Stopped' : state === 'timeout' ? 'Timed out' : 'Unavailable';
  card.querySelector('.result-summary').textContent = record.result.summary || 'Probe completed without a summary.';
  card.querySelector('.result-meta').append(document.createTextNode(` · ${Math.round(record.result.durationMs || 0)} ms`));
  const detail = create('details', 'result-details');
  detail.append(create('summary', '', 'Inspect evidence'), create('pre', '', JSON.stringify({
    status: record.result.status,
    ...record.result.details,
  }, null, 2)));
  card.append(detail);
}

function validateRelay(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Enter a complete ws:// or wss:// relay URL.'); }
  if (!['ws:', 'wss:'].includes(url.protocol)) throw new Error('The relay must speak WebSocket (ws:// or wss://), not ordinary HTTPS or the stock Signal TLS proxy protocol.');
  if (url.username || url.password || url.search || url.hash) throw new Error('Use a relay URL without credentials, query parameters, or a fragment.');
  if (url.protocol === 'ws:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('Use wss:// for a remote relay. Unencrypted ws:// is limited to local development.');
  return url.href;
}

function setRunning(value) {
  running = value;
  for (const input of form.querySelectorAll('input,select')) input.disabled = value;
  if (!value) updateKind();
  $('#run').disabled = value || checkedHosts().length === 0;
  $('#cancel').hidden = !value;
  $('#clear').disabled = value || (!results.length && !events.length);
  $('#export').disabled = value || !results.length;
  $('#run-state').className = `pill ${value ? 'working' : 'neutral'}`;
  $('#run-state').textContent = value ? 'Running' : 'Complete';
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (running) return;
  $('#form-error').hidden = true;
  const hosts = checkedHosts();
  const settings = {route: route(), kind: kind.value, timeoutMs: Number($('#timeout').value)};
  try {
    if (!hosts.length) throw new Error('Choose at least one endpoint.');
    if (settings.route === 'relay') settings.relayUrl = validateRelay(relayInput.value.trim());
  } catch (error) {
    $('#form-error').textContent = error.message;
    $('#form-error').hidden = false;
    return;
  }
  controller = new AbortController();
  const signal = controller.signal;
  setRunning(true);
  let completed = 0;
  try {
    for (const host of hosts) {
      if (signal.aborted) break;
      const record = {id: ++sequence, host, ...settings, startedAt: new Date().toISOString()};
      const card = resultCard(record);
      $('#results-summary').textContent = `Testing ${completed + 1} of ${hosts.length}: ${host}`;
      const probe = settings.route === 'direct'
        ? settings.kind === 'https' ? probeDirectHttps : probeDirectWebSocket
        : settings.kind === 'tls' ? probeRelayTls : settings.kind === 'https' ? probeRelayHttps : probeRelayProvisioning;
      try {
        record.result = await probe({host, ...settings, signal, onEvent: (entry) => addEvent(entry, host)});
      } catch (error) {
        record.result = {ok:false, status:signal.aborted ? 'cancelled' : 'error', summary:error.message || String(error), details:{name:error.name}, durationMs:0};
        addEvent({level:'error', message:record.result.summary}, host);
      }
      results.push(record);
      if (results.length > 100) {
        results.shift();
        $('#results').lastElementChild?.remove();
      }
      finishCard(card, record);
      completed++;
    }
  } finally {
    const cancelled = signal.aborted;
    controller = undefined;
    setRunning(false);
    $('#run-state').textContent = cancelled ? 'Stopped' : 'Complete';
    const successful = results.slice(-completed).filter((record) => record.result.ok).length;
    $('#results-summary').textContent = `${completed} probe${completed === 1 ? '' : 's'} completed · ${successful} connected${cancelled ? ' · stopped' : ''}`;
  }
});
$('#cancel').addEventListener('click', () => controller?.abort());
$('#clear').addEventListener('click', () => {
  if (running) return;
  results.length = 0;
  events.length = 0;
  $('#results').replaceChildren(create('div', 'cleared-state', 'Results cleared. Ready for another probe.'));
  $('#log-entries').replaceChildren(create('p', 'log-placeholder', 'No network activity yet.'));
  $('#event-count').textContent = '0 events';
  $('#results-summary').textContent = 'Your connection results will appear here.';
  $('#run-state').textContent = 'Ready';
  $('#clear').disabled = true;
  $('#export').disabled = true;
});
$('#export').addEventListener('click', () => {
  const report = {schema:'twang-diagnostics/1', exportedAt:new Date().toISOString(), trustPolicy:TRUST_POLICY, environment:{secureContext:window.isSecureContext, webAssembly:typeof WebAssembly === 'object', online:navigator.onLine, userAgent:navigator.userAgent}, results, events};
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type:'application/json'}));
  const link = create('a');
  link.href = url;
  link.download = `twang-diagnostics-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
