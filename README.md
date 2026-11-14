# Twang · Signal connection lab

A diagnostic-first proof of concept for a browser-based Signal client. It tests
Signal service reachability without registering an account or linking a device.

## Run locally

Node.js **22.12 or newer** and npm (the pinned Wrangler CLI requires 22.12+):

```sh
npm ci
npm start
```

Open `http://127.0.0.1:5173`. The development server serves the interface and
attaches the restricted Wisp byte relay at `/wisp/` on the same origin. Choose
**TLS via relay**, then **TLS handshake**, to test the browser's WASM TLS stack.
No network probes run until **Run probe** is pressed.

## Probes

| Path | Probe | What success establishes |
| --- | --- | --- |
| Direct browser | HTTPS response | Native fetch returned a readable HTTP status |
| Direct browser | Provisioning WebSocket | Native browser WSS upgrade completed |
| TLS via relay | TLS handshake | Browser-side rustls completed certificate-chain and hostname validation |
| TLS via relay | HTTPS response | Browser-side TLS received an HTTP response; error HTTP statuses are still transport evidence |
| TLS via relay | Provisioning WebSocket | The server sent a protobuf provisioning address and received its ACK |

The relay only permits the fixed Signal hostname list on TCP 443. Provisioning
probes are limited to the two chat hosts. Each probe has an 8–30 second timeout,
can be stopped, and closes its sockets. Results and bounded event logs stay in
the current tab. **Export JSON** downloads a local diagnostic report.

Browser failures are deliberately ambiguous: native APIs do not reliably expose
whether DNS, certificate validation, CORS, Origin policy, or another network
layer failed. `navigator.onLine` is shown only as a browser-reported hint.

## Transport and trust

The browser loads the pinned `@mercuryworkshop/epoxy-tls@2.1.20-1` WASM build
from same-origin assets. Epoxy runs rustls and its own HTTP/WebSocket stack over
Wisp v1. The Node relay forwards bytes; it never terminates the inner Signal TLS
connection and never receives Signal account credentials.

Signal's RSA and Ed25519 CA roots are bundled from a pinned upstream revision;
see [the certificate provenance](public/certs/README.md). **These are added to
Epoxy's ordinary WebPKI roots. This PoC does not enforce exclusive Signal CA
pinning.** Certificate verification is always enabled. The current transport
API does not expose leaf certificates, negotiated TLS version, or ALPN, so the
UI does not invent these details.

`npm run build` copies the installed, pinned Epoxy files into `dist/vendor/`.
The wasm-bindgen helper is extracted unchanged from its embedded data URL into
a same-origin module; there is no runtime CDN dependency. Upstream AGPL-3.0-only
license text is preserved alongside the generated assets.

## Static hosting and the relay

The tracked `wrangler.jsonc` publishes the **static interface only** using
Worker name **`twang`**, `assets.directory = "./dist"`, and no Worker script.
It contains no account IDs, zone IDs, routes, custom-domain changes, bindings,
or secrets. Cloudflare account/domain setup is managed separately.

From a fresh checkout:

```sh
npm ci
npm test
npm run deploy:check
```

`deploy:check` builds the site and runs the pinned Wrangler **dry run**. It does
not publish a Worker or change Cloudflare resources. The actual deployment
command, to run from the separately configured Cloudflare account, is:

```sh
npm run deploy
```

This is exactly `npm run build && wrangler deploy`, with Wrangler **4.162.0**
pinned in `devDependencies` and the lockfile. In Workers Builds, set the build
command to `npm run build` and the deploy command to `npx wrangler deploy` after
dependency installation; the local pinned Wrangler will be used. Normal
authenticated Cloudflare access is required for deployment, but no Cloudflare
credentials belong in this repository.

For static-only hosting elsewhere, run `npm run build` and serve `dist/`. For
Cloudflare Pages instead of Workers Assets, use build command `npm run build`
and output directory `dist`; the Wrangler file targets Workers Assets.
`_headers` supplies the CSP and response headers on hosts that support that
format. Ensure `.wasm` is served as `application/wasm`. The static site needs no
Node server after it has been built; browsers need ES modules, WebAssembly,
WebSockets, and Web Streams.

Static hosting alone cannot open raw TCP connections. Run `npm run relay` on a
separate Node host, terminate HTTPS/WebSockets in front of it, and enter its
`wss://…/wisp/` URL in the interface. See [relay configuration](relay/README.md).
The included relay uses Node's `node:net`/`node:dns` APIs and is **not deployed by
Wrangler**. It requires separate hosting as written. Porting a relay to Workers
would be a different implementation; it is outside this deployment.

On the relay host, install runtime dependencies only and bind behind a reverse
proxy on the same machine:

```sh
npm ci --omit=dev
TWANG_ALLOWED_ORIGINS=https://twang.chat \
  TWANG_RELAY_HOST=127.0.0.1 TWANG_RELAY_PORT=8788 npm run relay
```

The reverse proxy should expose HTTPS/WSS and forward `/wisp/` to
`http://127.0.0.1:8788/wisp/`. Allow the relay's DNS resolution and outbound TCP
443 to the bundled Signal hosts. No Signal account credentials are required.

The default configured public Origin is `https://twang.chat`; explicitly add
other preview origins with `TWANG_ALLOWED_ORIGINS` when needed. Origin checks
are a browser safeguard, not authentication against arbitrary non-browser
clients; keep the relay private or behind access controls for anything beyond
a bounded personal PoC.

The **stock Signal TLS proxy is not a Wisp relay**. It expects nested TLS,
without the outer WebSocket framing used here. This version connects through
the included byte relay to the standard Signal service hosts, rather than
accepting arbitrary Signal proxy URLs.

## Verification

```sh
npm test
npm run build
```

Tests cover Wisp framing/flow control, host/port/Origin restrictions, malformed
traffic, cleanup, and bounded Signal protobuf parsing/ACKs. Offline tests do
not establish current live Signal interoperability. A successful provisioning
address test against the real service is the next useful gate.

## Scope

No Signal identity keys, linking QR codes, authenticated sessions, registration,
messages, contact discovery, recovery requests, groups, or calls. No service
worker caches during this diagnostic stage. This is an unofficial experiment;
the web host still controls the application code delivered to the browser.

## Sources

- [Signal TLS proxy](https://signal.org/blog/run-a-proxy/)
- [Signal service endpoints and roots](https://github.com/signalapp/libsignal/blob/8be00c282001caa3585d18de0f044c6d500348ab/rust/net/src/env.rs)
- [Signal provisioning schema](https://github.com/signalapp/Signal-Desktop/blob/848443afc3fcc74a0e127ba4f4d8554b95da856e/protos/SignalService.proto)
- [Epoxy transport](https://github.com/MercuryWorkshop/epoxy-tls)
- [Wisp protocol](https://github.com/MercuryWorkshop/wisp-protocol)
