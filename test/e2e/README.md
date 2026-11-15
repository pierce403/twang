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

The app's inner WebSocket diagnostic tests only upgrading the connection.
The fixture additionally checks server-initiated binary reception. Sending
application messages through Epoxy's inner WebSocket API is not covered: an
exploratory send test stalled after upgrading and needs further investigation
before adding account linking or messaging. The raw TLS stream payload test does
verify bidirectional 2 MiB transfer.
