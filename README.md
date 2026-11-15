# Twang · static Signal connection lab

Twang is a static HTML/CSS/JavaScript diagnostic app. It loads a locally bundled
WebAssembly TLS implementation and uses one hardcoded WebSocket endpoint:

`wss://proxy.twang.chat/v1/tls-tunnel` (subprotocol `signal-tls-v1`).

The app has no server runtime, relay URL input, credentials, account registration,
or device linking. Selecting an endpoint and pressing **Run probe** tests a
certificate-validated inner TLS handshake, an HTTPS root response, or a
provisioning WebSocket upgrade. No probes run automatically. Results stay in
memory and can be exported locally.

## Transport and trust

The browser validates outer WSS to the proxy. Epoxy/Rustls in WebAssembly
validates the inner Signal TLS certificate and hostname. Public Signal CA roots
are added to standard WebPKI roots; this is not exclusive Signal CA pinning.
Certificate checks are never disabled. See [certificate provenance](public/certs/README.md)
and [third-party notices](THIRD_PARTY_NOTICES.md).

The proxy forwards encrypted TLS bytes. It can observe client IPs, SNI, timing,
and byte counts and can interrupt connections. It does not terminate Signal TLS
or receive its keys. The web host remains trusted to deliver honest client code.
A successful TLS or HTTP probe is not an authenticated messaging session.

The client adapts Epoxy's internal Wisp stream API locally; no Wisp CONNECT or
framing is sent to the server. Each upstream connection opens a raw binary
WebSocket to the fixed endpoint. The configured proxy must implement the new
protocol; a stock Signal TLS Proxy cannot accept browser WebSockets.

## Build and tests

Node.js 22.12+ and npm are build/test tools only. OpenSSL and Chromium are also
needed for the integration suite:

```sh
npm ci
npm test
npm run build
npx playwright install --with-deps chromium
npm run test:e2e
```

`npm start` serves a local static preview. It forwards no connections. `dist/`
contains the complete deployable app, including the pinned JS/WASM dependency
and public certificates. Runtime requires a modern browser with WebAssembly,
WebSockets, Streams, and a reachable configured proxy. No third-party CDN is
used at runtime. Browser fixture tests and their temporary CA/private keys are
excluded from the static build. See [browser test details](test/e2e/README.md).

## Cloudflare deployment

The app and the byte relay are **separate deployments**. The app's existing
Wrangler configuration is assets-only, with Worker name `twang` and domain
`twang.chat`:

```sh
npm ci
npm test
npm run deploy:check
npm run deploy
```

Proxy source and its Cloudflare configuration live in the fork:
https://github.com/pierce403/Signal-TLS-Proxy/tree/signal-webboost/cloudflare

From that repository, with authorized Cloudflare credentials available:

```sh
cd cloudflare
npm ci
npm test
npm run deploy:check
npm run deploy
```

The proxy Worker is named `signal-webboost` and configures `proxy.twang.chat`.
The app needs no Cloudflare bindings or secrets. Keep deployment credentials
outside both repositories. Cloudflare Workers block outbound TCP to Cloudflare
IP ranges; whether the intended Signal destinations work from the deployed
Worker must be checked live. The diagnostic Worker intentionally bounds sessions,
queues, and cumulative bytes; it is not yet a full attachment-transfer relay.

## Verification status

Local tests exercise routing, byte integrity, certificate/hostname rejection,
cancellation, and bounded transport behavior. Browser fixture results establish
local correctness only. Production Cloudflare deployment and live Signal
interoperability require credentials and a live check; neither is implied by
an offline test or successful build.

The inner WebSocket diagnostic stops after upgrading. An exploratory outbound
WebSocket send stalled in the pinned TLS library; investigate that before adding
linking or messaging. The tested raw TLS stream and HTTPS paths do not depend on
that API. See the browser test notes for the exact coverage and limitation.

The earlier `experiments/signal-web-boost/` snapshot is historical. The fork
above is the canonical proxy implementation. No upstream PR has been opened.
