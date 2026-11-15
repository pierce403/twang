# Browser TLS integration tests

These tests run the actual browser WebAssembly TLS implementation through a local
WebSocket bridge into an OpenSSL-generated local TLS endpoint. They verify
2 MiB binary payload integrity, trusted and untrusted certificates, hostname
checks, HTTPS response parsing, inner WebSocket upgrades and received binary messages,
cancellation, and tunnel cleanup. No Signal endpoint is contacted. The fixture
serves production `public/_headers`, substituting only its own WebSocket origin
for the production proxy origin in the Content Security Policy.

From the repository root (Node.js 22.12+, OpenSSL, and Chromium dependencies):

```sh
npm ci
npx playwright install --with-deps chromium
npm run build
npm run test:e2e
```

To use a system Chromium, set `TWANG_CHROMIUM_PATH=/usr/bin/chromium`.
For an interactive browser test page, run `node test/e2e/fixtures.mjs` after the
build and open the printed local URL. The same test suite renders its results
there. Fixture keys are generated in temporary storage and deleted on shutdown;
fixture servers and local CA configuration are never copied into the static app.

The fixture uses plain loopback WebSockets; production outer WSS certificate
validation, Cloudflare networking, full Nginx/Docker operation, and live Signal
interoperability require separate verification.

The old Epoxy inner WebSocket send API stalled in an exploratory test. Twang now
uses its own bounded RFC 6455 implementation over Epoxy's verified raw TLS
stream. The browser suite verifies its masked outbound frames and binary echo.
The raw TLS payload test also verifies bidirectional 2 MiB transfer.

`linking.test.mjs` drives the real UI with an independent local phone/service:
QR generation, encrypted provisioning, actual WASM signed Curve25519/Kyber
prekeys, encrypted pending keys before activation, confirmed storage and reload,
rejected registration cleanup, and no backlog or new-account registration calls.
Only the test server rewrites the fixed outer proxy and serves a fixture CA;
production has no configurable origin or certificate bypass. The fixture refuses
other WebSocket destinations so tests cannot contact a real account.

`pwa.test.mjs` verifies service-worker installation, an offline reload under
production CSP, and explicit updates blocked by a busy second tab. No actual
Signal account is used or linked by these automated tests.

The PWA test shuts down its HTTP origin before reloading and checks that the
cached app initializes while an uncached request fails; browser online-state
metadata is not treated as proof of network reachability.

UI tests must wait for the initialized local-device state, not merely an enabled
HTML button: IndexedDB initialization and module bootstrapping are asynchronous.
Startup linking controls remain disabled until that state is known. PWA update
tests must exercise the real waiting worker and another busy tab; a reload alone
is not proof that the update guard ran.

When waiting for a service-worker registration property, keep the registration
wrapper in the page and poll its property synchronously. In the pinned Playwright
runtime, an async `waitForFunction` predicate can return a truthy Promise before
its false value resolves, ending polling early. Await setup with `evaluate`,
then use a synchronous predicate for the changing state.
