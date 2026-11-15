# Third-party components

- **Signal WASM** (`@getmaapp/signal-wasm` 0.6.6), AGPL-3.0-only. Third-party
  browser bindings to Signal's libsignal 0.101.0; used for XEdDSA signatures,
  round-3 Kyber1024 prekeys, and durable private prekey records. The build copies
  the pinned package's JS/WASM and license unchanged to `vendor/signal/`.
  Source: https://github.com/getmaapp/signal-wasm
- **qrcode** 1.5.4, MIT. Bundled locally into an ES module to draw the pairing QR.
  Source: https://github.com/soldair/node-qrcode
- **fake-indexeddb** 6.2.4, Apache-2.0. Account-vault test tooling only.
  Source: https://github.com/dumbmatter/fakeIndexedDB
- **esbuild** 0.28.1, MIT. Build tooling only.
  Source: https://github.com/evanw/esbuild

- **Epoxy TLS** (`@mercuryworkshop/epoxy-tls` 2.1.20-1), MercuryWorkshop,
  AGPL-3.0-only. The build copies its browser JavaScript, WebAssembly, license,
  and version metadata from the pinned npm package. The embedded helper module
  is extracted unchanged to a same-origin file. Upstream source:
  https://github.com/MercuryWorkshop/epoxy-tls
- **Signal public CA certificates**, Signal Messenger, LLC. Copied from the
  AGPL-3.0-only libsignal source revision documented in
  [public/certs/README.md](public/certs/README.md). These files contain public
  certificates only, not private keys.
- **Playwright** 1.62.1, Microsoft, Apache-2.0. Browser test tooling only.
  Source: https://github.com/microsoft/playwright
- **ws** 8.21.0, MIT. Local test fixtures only.
  Source: https://github.com/websockets/ws
- **Wrangler** 4.162.0, Cloudflare, MIT/Apache-2.0. Development/deployment tool
  only. Source: https://github.com/cloudflare/workers-sdk

Dependency licenses and transitive notices remain in their installed packages.
The generated static bundle preserves Epoxy's license alongside its files.
