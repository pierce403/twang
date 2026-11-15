# Twang · static Signal connection lab

Twang is a spider-themed, installable static PWA for linking an existing Signal
account and diagnosing its connection. It uses one hardcoded WebSocket endpoint:

`wss://proxy.twang.chat/v1/tls-tunnel` (subprotocol `signal-tls-v1`).

## Link an existing account

Choose **Link existing account**, then scan the QR from Signal on your phone:
**Settings → Linked devices → Link new device**. Your phone stays the primary
device. Twang never asks for your phone number, a registration SMS, or Signal PIN,
and it does not create a new account. QR capabilities omit history transfer;
there are no backup, backlog, contact-sync, or message-history import requests.

The browser opens Signal's provisioning WebSocket, generates an ephemeral X25519
key, authenticates/decrypts the phone's provisioning envelope, and creates genuine
libsignal XEdDSA-signed Curve25519 and round-3 Kyber1024 prekeys. It then submits
`PUT /v1/devices/link`. Only a confirmed secondary-device ID and successful local
save produce the **Account linked** state. Account linking is implemented; message
sending/receiving and history import are not part of this version.

Device identity keys, prekey records, profile material and the generated password
stay in an encrypted IndexedDB vault, protected by a non-extractable AES-GCM key.
Encrypted pending keys are saved before server activation to survive interrupted
responses. A network-uncertain result never reports success or silently retries;
check Linked devices on the phone before discarding pending local keys. Atomic
vault operations prevent two tabs from replacing each other's pending keys.

**Forget this device** erases local keys. Also unlink Twang on the phone to stop
server delivery. Clearing browser/site data removes this device's local keys.
The origin's application code can access the vault; browser encryption does not
protect it from malicious code served by the same origin.

## Install and use offline

Install from your browser's app menu (or the **Install** button where supported).
The standalone PWA caches only its versioned static shell, local WASM libraries,
icons, and public certificates. It opens offline, while linking and diagnostic
connections require network access. Account credentials, QR URLs, proxy/API
traffic, reports and fixtures never enter service-worker caches.

Updates wait for an explicit **Update app** action and ask every Twang tab whether
linking or diagnostics are active. An active or unresponsive tab blocks activation.

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
WebSockets, Streams, WebCrypto X25519, IndexedDB, and a reachable configured proxy. No third-party CDN is
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
local correctness only. A real browser obtained a live Signal provisioning QR through the configured
proxy on 2026-11-15; the session was cancelled before phone approval. Completed
enrollment is verified against the independent local phone/service fixture.
Final live enrollment still requires scanning and approving from a real primary
phone; an offline test or successful build does not establish that result.

Inner WebSockets use a bounded RFC 6455 implementation over the verified raw
TLS stream. This avoids the previously observed Epoxy WebSocket send stall.
Tests verify client masking, upgrade authentication, fragmentation, control
frames, and bidirectional encrypted browser traffic.

The earlier `experiments/signal-web-boost/` snapshot is historical. The fork
above is the canonical proxy implementation. No upstream PR has been opened.
