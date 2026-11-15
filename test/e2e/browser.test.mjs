import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startFixtures } from './fixtures.mjs';

test('browser WASM TLS over raw WebSocket transport', { timeout: 45000 }, async t => {
  const fixtures = await startFixtures();
  t.after(() => fixtures.close());
  const browser = await chromium.launch({
    ...(process.env.TWANG_CHROMIUM_PATH ? { executablePath: process.env.TWANG_CHROMIUM_PATH } : {}),
    args: ['--no-sandbox'],
  });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(fixtures.url);
  const output = page.locator('#results[data-complete="true"]');
  await output.waitFor({ timeout: 35000 });
  const results = JSON.parse(await output.textContent());
  assert.equal(results.length, 7, 'The complete browser TLS suite must run');
  for (const result of results) await t.test(result.name, () => assert.equal(result.ok, true, result.error));
  assert.deepEqual(errors, [], 'Unexpected unhandled browser errors');
});
