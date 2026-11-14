# Twang · static browser connection lab

Static HTML/CSS/JavaScript diagnostics. No relay, backend service, Wisp transport,
WebAssembly TLS stack, credentials, account registration or device linking.

## Browser limitations
Only native browser fetch and WebSocket APIs are used. Browsers manage TLS and
certificate trust. Static pages cannot open raw TCP sockets, add trust roots,
bypass CORS/Origin restrictions, or speak the stock Signal TLS proxy protocol.
Failed probes are ambiguous, not proof that Signal is offline.
HTTPS probes request an allowlisted endpoint root with credentials omitted.
A readable HTTP status is evidence of a response, not a messaging session.
WebSocket probes test an upgrade at a Signal chat endpoint and close immediately.
No network probes run until Run probe is pressed. Timeouts, cancellation, bounded
event logs and local JSON export remain available.

## Develop and test
Node.js 22.12+ and npm are needed only for tooling:
    npm ci
    npm test
    npm start
The local preview server serves static files only; it forwards no connections.
For ordinary hosting, serve the generated dist/ directory with any static host.

## Automatic Cloudflare deployment
Production branch: main. Build: npm run build. Deploy: npx wrangler deploy.
wrangler.jsonc serves dist/ with Worker name twang and custom domain twang.chat.
There is no Worker script or server runtime. Wrangler is a development dependency.
Do not place Cloudflare credentials in the repository.
npm run deploy:check builds assets and runs a Wrangler dry run.
npm run deploy publishes them. Tests use mocked browser APIs and do not
establish live Signal interoperability.
