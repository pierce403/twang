# Signal service trust roots

These public CA certificates are copied without modification from
[`signalapp/libsignal@8be00c282001caa3585d18de0f044c6d500348ab`](https://github.com/signalapp/libsignal/tree/8be00c282001caa3585d18de0f044c6d500348ab/rust/net/res)
and PEM encoded. They contain no private keys.

| File | SHA-256 certificate fingerprint | Expires (UTC) |
| --- | --- | --- |
| signal.pem | DDB0F92BB95C8D6FD202EA6E8CC5CCD182B544F8CD696F47D580659DDC9DF65A | 2032-01-24 |
| signal-ed25519.pem | 2642F1F90B389FED2558D7324CA26D70E750B06F87C595C5DE955E2560821657 | 2036-06-16 |

The pinned Epoxy build **adds these roots to its standard WebPKI roots**. This
diagnostic therefore validates the certificate chain and hostname, but does not
enforce Signal-only CA pinning. Certificate validation is never disabled.

Upstream certificate configuration: `rust/net/src/certs.rs`. Upstream source is
licensed AGPL-3.0-only; copyright Signal Messenger, LLC.
