# Experimental browser transport for Signal TLS Proxy

This is a proposed operator-installed compatibility patch, not an official Signal
feature. It is separate from Twang's deployed static browser diagnostics. No
Cloudflare service is needed. An unmodified proxy cannot accept this transport.

## Source inspection

Inspected all tracked files in signalapp/Signal-TLS-Proxy at commit
`6442976870fc73ae296b20b1ad6df8725e988072` (2026-11-02):

- `data/nginx-terminate/nginx.conf`: public 443 is a TLS-terminating **stream**
  proxy. Its HTTP block only serves port 80 ACME challenges and otherwise 404s.
- `data/nginx-relay/nginx.conf`: reads inner TLS SNI and selects a fixed upstream
  list, with unknown names sent to a deny upstream. The staging variant changes
  the destination environment, not the transport.
- `docker-compose.yml`, `init-certificate.sh`, and README contain no HTTP CONNECT,
  WebSocket upgrade, browser tunnel, or alternate transport switch.

There is no hidden browser-compatible transport in this revision. The repository
is mostly deployment configuration rather than a custom proxy implementation.

## Compatibility approach

The one-line Nginx patch sends decrypted outer-TLS bytes through a small sidecar
before the existing `nginx-relay:4433`. Certificates and public listeners stay in
the existing Nginx container. Both native and browser traffic still go through
Nginx's unchanged Signal SNI allowlist:

| Input after outer TLS | Adapter action |
| --- | --- |
| TLS handshake record (`0x16`) | Forward every byte to the existing relay |
| HTTP GET | Parse bounded headers; accept only the versioned WebSocket endpoint |
| Other input | Close |

The browser opens `wss://PROXY/v1/tls-tunnel` with WebSocket subprotocol
`signal-tls-v1`. Each **binary** message contains a chunk of an inner TLS stream;
message boundaries have no TLS significance. WASM must validate Signal's
certificate and hostname and perform the inner TLS handshake. The browser then
runs Signal's application protocol inside that TLS session. This adapter is not
a Wisp server; it has no host selection, stream multiplexing, or address headers.
The client TLS library must support this byte-stream transport or be adapted.

No Signal keys, authentication, account state, storage, or application parsing
belongs in the adapter. It forwards to exactly one internal destination. The
existing Nginx relay chooses a Signal host from the inner ClientHello. A claimed
target in the URL cannot change that destination. WebSocket cookies and
authorization headers are neither used nor forwarded. All web origins are
intentionally accepted so independent static clients can use the same public
Signal-only proxy; Origin is not authentication or an abuse control.

This removes the Twang operator from the connection path: users choose any
**patched** Signal proxy. That proxy remains in the path throughout the session
and can observe IPs, timing, sizes, and inner SNI, as with a native proxy session.
TLS verification must never be disabled. Honest delivered client code remains
part of the web application's trust boundary.

## Try on a disposable proxy deployment

Use a host with Docker Compose and the official proxy's existing certificate
setup. The patch adds a Node.js 24 sidecar with pinned `ws` 8.18.3; it publishes
no extra port. Run these from an official proxy checkout. Replace the source
path below with the absolute path to this experiment:

```sh
cp -R /path/to/twang/experiments/signal-web-boost ./web-boost
git apply --check web-boost/proxy.patch
git apply web-boost/proxy.patch
docker compose -f docker-compose.yml -f web-boost/compose.yml up -d --build
```

The original `./init-certificate.sh` is still required for a fresh official proxy.
Use the Compose overlay for subsequent updates as well. The patch was checked
against the exact upstream revision above; recheck future upstream versions.
Docker's Node base tag is not digest-pinned in this prototype.

Rollback the one-line Nginx change and recreate the original services:

```sh
git apply -R web-boost/proxy.patch
docker compose -f docker-compose.yml up -d --force-recreate --remove-orphans
```

## Local verification

Node.js 22.12+ and OpenSSL are required:

```sh
cd experiments/signal-web-boost
npm ci --ignore-scripts
npm test
```

Tests cover fragmented native prefaces, binary round trips, rejected paths and
target parameters, protocol negotiation, text and size rejection, handshake
timeouts, session and header limits, upstream failures, and real TLS sessions
through both transports, including rejection of an untrusted certificate. The
TLS tests use a temporary local CA certificate. Test keys stay in
temporary storage and are deleted. This TLS test uses Node in the client role;
it is not a browser/WASM or live Signal interoperability test.

Bounded sessions (256), 8 KiB HTTP headers, 64 KiB incoming WebSocket messages,
bounded pending writes, stream backpressure, handshake and idle timeouts, no
compression, and no application logging are implemented. These are prototype
limits, not a complete production abuse-control policy. Idle tunnels close after
120 seconds without upstream socket activity; clients must reconnect or use
application-level keepalives. HTTP/2 extended CONNECT is not implemented.

**Not yet verified:** the complete Docker/Nginx/certificate path, stock Android
and iOS client regressions, browser/WASM integration, actual Signal handshakes,
long-running sessions, and load behavior. No deployment was performed.
Recognizing HTTP after outer TLS also gives active probers a new observable
behavior compared with the stock proxy; review that censorship-resistance
tradeoff before proposing upstream adoption.

## Sources

- https://github.com/signalapp/Signal-TLS-Proxy/tree/6442976870fc73ae296b20b1ad6df8725e988072
- https://signal.org/blog/run-a-proxy/

`proxy.patch` modifies MIT-licensed upstream configuration. The upstream license
is reproduced in `UPSTREAM_LICENSE`. New experiment source is MIT-licensed under
`LICENSE`. The npm dependency includes its own MIT license.
