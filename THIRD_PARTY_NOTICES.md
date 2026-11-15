# Third-party components

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
