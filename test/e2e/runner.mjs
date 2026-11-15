import { runBrowserSuite } from './browser-suite.mjs';
const output = document.querySelector('#results');
try {
  const config = await (await fetch('/__e2e__/config')).json();
  const endpoint = new URL(config.endpoint, location.href);
  endpoint.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  config.endpoint = endpoint.href;
  const results = await runBrowserSuite(config, partial => {
    output.textContent = JSON.stringify(partial, null, 2);
  });
  output.textContent = JSON.stringify(results, null, 2);
  output.dataset.complete = 'true';
  output.dataset.passed = String(results.every(test => test.ok));
} catch (error) {
  output.textContent = JSON.stringify([{ name: 'Browser suite bootstrap', ok: false, error: String(error?.stack || error) }], null, 2);
  output.dataset.complete = 'true';
  output.dataset.passed = 'false';
}
