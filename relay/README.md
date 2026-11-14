# Twang diagnostic byte relay

`node relay/server.mjs` starts an HTTP/WebSocket service on `127.0.0.1:8788`.

This is a separate **Node.js 22.12+** runtime, not part of the static Wrangler
deployment. Install with `npm ci --omit=dev`; start with `npm run relay`.
The host needs DNS and outbound TCP 443. For public access, terminate HTTPS/WSS
in a reverse proxy and forward `/wisp/` to the loopback service. The UI's relay
URL must point to that WSS endpoint; the static `twang.chat` host alone does not
provide a relay.

- Health: `http://127.0.0.1:8788/health`
- Wisp: `ws://127.0.0.1:8788/wisp/`
- Browser Epoxy options: `wisp_v2 = false`, `udp_extension_required = false`

This is a restricted **Wisp v1 TCP subset**, based on the [v1.2 protocol](https://github.com/MercuryWorkshop/wisp-protocol/blob/v1/protocol.md). Generic Wisp supports UDP; this relay intentionally refuses it. Only the fixed Signal hostnames in `SIGNAL_HOSTS` and TCP port 443 are accepted. It does not perform TLS: the browser's WASM connects and verifies the inner Signal TLS session.

Requests must carry an exact allowed browser Origin. The defaults include `https://twang.chat` and the local development origins on ports 5173 and 8787. Configure a different deployment through the comma-separated `TWANG_ALLOWED_ORIGINS` environment variable. Configure listening using `TWANG_RELAY_PORT` and `TWANG_RELAY_HOST`; loopback is the default. Serve the public endpoint through a TLS reverse proxy for browser `wss://` connections.

Each permitted hostname is resolved immediately before connecting, and all accepted addresses must be public global addresses. The validated address is passed to the socket so a second DNS lookup cannot change the destination. The relay also caps simultaneous connections and streams, frame sizes, queued bytes, connection timeouts, idle time and total diagnostic session time. Origin checks do not authenticate non-browser clients; deploy behind access/rate controls if that is needed for an Internet-facing relay.

`createRelayServer(options)` returns `{ server, wss, listen, close }`. Its injectable `connect` option allows tests to exercise framing and buffering without making a Signal connection. Run the offline checks with `node --test test/relay.test.mjs`.

This relay uses direct outbound TCP. An environment that requires an outbound HTTP proxy or restricts network destinations may refuse those connections. Such a failure is a relay-network result, not evidence that Signal rejected browser TLS.
