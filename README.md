# reverse-proxy

This repository runs a Node.js edge proxy on ports `443` and `80`. Public port `443` is now an SNI-aware TCP router: standard HTTPS traffic is handed into the in-process HTTPS reverse proxy, while TURN/TLS traffic for `webrtc-turns.gdmn.app` is passed through as raw TLS to its localhost upstream.

## Runtime And Deployment Baseline

- Package manager: `npm` via `package-lock.json`
- Runtime entrypoint: `npm start` or `node src/index.js`
- Host routing expectation: the proxy loads host mappings from a root-level `hosts.json` file and hot reloads that file while the process keeps running
- Container runtime expectation: `Dockerfile` uses `node:25-alpine`, copies `hosts.json` and `src/`, installs production dependencies, and starts `node src/index.js`
- Listener expectation: the process binds directly to `80` and `443`
- TLS expectation: manual certificates can exist at `ssl/<domain>/<domain>.crt`, `.key`, and `.ca-bundle`, and should be mounted at runtime rather than baked into the image
- Upstream expectation proven by this repo: most routed backends are localhost HTTP services, and `webrtc-turns.gdmn.app` is a raw TLS passthrough route to `localhost:5349`

## TLS Certificate Sources

- A valid manual certificate bundle under `ssl/<domain>/` remains the first-priority source and continues to work for the matching domain and any subdomain covered by that certificate.
- If a manual certificate folder exists but the bundle is incomplete or invalid, the proxy logs that manual load failure and falls back to the managed certificate path for TLS-terminated hosts.
- Let's Encrypt is used only for TLS-terminated hostnames that do not have valid manual coverage from `ssl/`.
- ACME-managed certificates are stored separately under `acme-data/certificates/<domain>/` by default so user-provided files in `ssl/` stay untouched.
- If a manual certificate later appears for a hostname that was previously using Let's Encrypt, the manual certificate wins on the next registry reload.
- Changes under `ssl/` are not watched live. They are picked up on startup and any later registry reload that happens while the process is running.
- Hosts configured as `tls-passthrough` are excluded from certificate issuance and renewal.

## Let's Encrypt HTTP-01

- Port `80` still redirects normal traffic to HTTPS.
- The only exception is `/.well-known/acme-challenge/*`, which is served directly for active HTTP-01 challenges.
- Automatic issuance and renewal are enabled only when `REVERSE_PROXY_ACME_EMAIL` is set or `REVERSE_PROXY_ACME_ENABLED=true` is configured together with an email address.

## Host Config

The proxy does not hardcode its public host list anymore. It loads routes from `hosts.json` at the repository root and watches that file for changes.

- Add `"$schema": "./hosts.schema.json"` at the top of `hosts.json` to get editor validation and completion against the checked-in schema file.
- Host keys must already be normalized: lowercase, no port, and no leading `www.`.
- `mode` defaults to `http-proxy`.
- `protocol` is used for `http-proxy` targets and may be `http:` or `https:`.
- `upstreamHost` is optional for `http-proxy` targets. When set, the proxy sends that hostname as the upstream `Host` header and, for `protocol: "https:"`, as the upstream TLS SNI name.
- `ws:` and `wss:` are not config values. WebSocket upgrades still use `mode: "http-proxy"`; `protocol: "http:"` means plain WebSocket to the upstream, while `protocol: "https:"` means TLS-secured WebSocket to the upstream.
- `tls-passthrough` targets are routed as raw TLS on port `443` and are excluded from TLS termination and ACME issuance.
- Optional per-target overrides: `connectTimeoutMs`, `upstreamTimeoutMs`.

Example `hosts.json`:

```json
{
	"$schema": "./hosts.schema.json",
	"chatgpt-proxy.gdmn.app": {
		"host": "localhost",
		"port": 3002,
		"protocol": "http:",
		"mode": "http-proxy"
	},
	"alemaro.team": {
		"host": "localhost",
		"port": 3003,
		"protocol": "http:",
		"mode": "http-proxy"
	},
	"socket-server.gdmn.app": {
		"host": "localhost",
		"port": 3030,
		"protocol": "http:",
		"mode": "http-proxy"
	},
	"api.example.com": {
		"host": "203.0.113.10",
		"port": 443,
		"protocol": "https:",
		"upstreamHost": "origin.example.net",
		"mode": "http-proxy"
	},
	"webrtc-turns.gdmn.app": {
		"host": "localhost",
		"port": 5349,
		"mode": "tls-passthrough"
	}
}
```

The proxy still normalizes a leading `www.` prefix before route lookup.

## Reliability Controls

The reverse proxy now applies explicit lifecycle controls to proxied HTTP requests, HTTP upgrade traffic, and TURN/TLS passthrough tunnels:

- Explicit upstream response timeout with `REVERSE_PROXY_UPSTREAM_TIMEOUT_MS`
- Host-specific upstream timeout budget for `chatgpt-proxy.gdmn.app` with `REVERSE_PROXY_CHATGPT_PROXY_TIMEOUT_MS`
- Explicit upstream connect timeout with `REVERSE_PROXY_CONNECT_TIMEOUT_MS`
- Bounded in-process concurrency with `REVERSE_PROXY_MAX_PARALLEL_REQUESTS`
- Structured request logging with request IDs and lifecycle outcome data via `/_reverse_proxy_log`
- Request correlation headers that preserve caller, edge, and upstream request IDs separately
- Downstream disconnect propagation so upstream requests are aborted when the client disappears
- Deterministic `502`, `503`, and `504` responses for proxy-generated failures
- Structured passthrough tunnel logging for TURN/TLS connections

### Environment Variables

- `REVERSE_PROXY_UPSTREAM_TIMEOUT_MS`: idle timeout for proxied upstream requests and upgrade sockets. Default: `900000`
- `REVERSE_PROXY_CHATGPT_PROXY_TIMEOUT_MS`: host-specific idle timeout for `chatgpt-proxy.gdmn.app` when that route does not define its own `upstreamTimeoutMs`. Default: `930000`
- `REVERSE_PROXY_CONNECT_TIMEOUT_MS`: timeout while connecting to an upstream target. Default: `10000`
- `REVERSE_PROXY_MAX_PARALLEL_REQUESTS`: maximum concurrent proxied HTTP requests, upgrade tunnels, or TURN/TLS passthrough tunnels before the relevant path rejects or closes new work. Default: `256`
- `REVERSE_PROXY_INBOUND_TIMEOUT_MS`: inbound server timeout for client connections. Default: `900000`
- `REVERSE_PROXY_LOG_BUFFER_LENGTH`: in-memory structured log depth exposed through `/_reverse_proxy_log`. Default: `500`
- `REVERSE_PROXY_ACME_ENABLED`: explicitly enable or disable automatic Let's Encrypt management. Default: enabled when `REVERSE_PROXY_ACME_EMAIL` is set, otherwise disabled.
- `REVERSE_PROXY_ACME_EMAIL`: contact email used when creating or reusing the Let's Encrypt ACME account.
- `REVERSE_PROXY_ACME_TERMS_OF_SERVICE_AGREED`: whether ACME account registration should agree to the CA terms. Default: `true`
- `REVERSE_PROXY_ACME_DIRECTORY_URL`: ACME directory URL. Default: Let's Encrypt production.
- `REVERSE_PROXY_ACME_RENEWAL_WINDOW_DAYS`: renew managed certificates this many days before expiry. Default: `30`
- `REVERSE_PROXY_ACME_RENEW_CHECK_INTERVAL_MS`: interval between renewal checks. Default: `43200000`
- `REVERSE_PROXY_ACME_MANAGED_CERT_DIR`: base directory for ACME-managed certificates. Default: `acme-data/certificates`
- `REVERSE_PROXY_ACME_ACCOUNT_KEY_PATH`: file path for the persisted ACME account private key. Default: `acme-data/account.key`
- `REVERSE_PROXY_ACME_PREFERRED_CHAIN`: optional preferred chain name passed to the ACME client.
- `REVERSE_PROXY_ACME_SKIP_CHALLENGE_VERIFICATION`: disable the ACME client's internal HTTP-01 pre-verification. Default: `false`

### Example .env

Use Let's Encrypt staging first, then switch `REVERSE_PROXY_ACME_DIRECTORY_URL` to production after the first successful issuance.

```dotenv
REVERSE_PROXY_ACME_ENABLED=true
REVERSE_PROXY_ACME_EMAIL=ops@example.com
REVERSE_PROXY_ACME_TERMS_OF_SERVICE_AGREED=true
REVERSE_PROXY_ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory
REVERSE_PROXY_ACME_RENEWAL_WINDOW_DAYS=30
REVERSE_PROXY_ACME_RENEW_CHECK_INTERVAL_MS=43200000
REVERSE_PROXY_ACME_MANAGED_CERT_DIR=acme-data/certificates
REVERSE_PROXY_ACME_ACCOUNT_KEY_PATH=acme-data/account.key
```

### Docker Run Example

This example keeps manual certificates under `ssl/`, stores Let's Encrypt account and managed certificate data under `acme-data/`, loads the environment from `.env`, and bind-mounts `hosts.json` so route changes can be reloaded without rebuilding the image.

```bash
docker stop reverse-proxy; \ 
docker rm reverse-proxy; \
docker pull gsbelarus/reverse-proxy:latest; \	
docker run -d \
	--name reverse-proxy \
	--restart unless-stopped \
	-p 80:80 \
	-p 443:443 \
	--env-file ./.env \
	-v /opt/reverse-proxy/hosts.json:/app/hosts.json:ro \
	-v /opt/reverse-proxy/ssl:/app/ssl:ro \
	-v /opt/reverse-proxy/acme-data:/app/acme-data \
	gsbelarus/reverse-proxy
```

Notes:

- Keep `ssl/` mounted read-only if it contains only user-managed certificates.
- Keep `acme-data/` writable so the proxy can store the ACME account key and managed certificates.
- Mount `hosts.json` if you want to change routes without rebuilding the image. The process watches that file and reloads successful edits.
- If the reverse proxy runs in Docker, `localhost` inside `hosts.json` refers to the reverse-proxy container itself, not the Ubuntu host. Use a reachable target from inside the container: a Docker service/container name on the same network, `host.docker.internal` with `--add-host=host.docker.internal:host-gateway`, or `--network host` if that deployment model is acceptable.
- `--env-file ./.env` is read from the host shell's current working directory. Use an absolute path if you want to avoid any ambiguity.
- The image intentionally does not bundle manual certificate files; provide them through the `ssl/` mount.
- `ssl/` changes are not live-watched. Restart the process, or wait for a later registry reload, if you add or replace manual certificates.
- If you later switch from staging to production, update `REVERSE_PROXY_ACME_DIRECTORY_URL` and remove any staging certificates from `acme-data/` before reissuing.

## Proxy Failure Semantics

- Unknown host mapping: `404`
- Upstream unavailable or connection refused: `502`
- Upstream timeout or connect timeout: `504`
- Local overload from the concurrency cap: `503`
- Downstream disconnect: logged as cancellation and upstream work is aborted; the proxy does not attempt to send a synthetic response after the client is gone

Upstream HTTP responses, including upstream `4xx` and `5xx`, are still passed through unchanged. Structured logs distinguish them from edge-generated failures with:

- `statusSource: "upstream"` and `upstreamStatusCode` for proxied upstream responses
- `statusSource: "edge"` and `proxyStatusCode` for reverse-proxy-generated failures such as `502`, `503`, and `504`

Proxy-generated errors are returned as JSON in this shape:

```json
{
	"error": {
		"message": "Upstream proxy target timed out",
		"type": "upstream_timeout",
		"code": "REVERSE_PROXY_TIMEOUT",
		"requestId": "..."
	}
}
```

## Forwarding Behavior

- Request method and path are preserved
- Original `Host` is preserved unless the route defines `upstreamHost`; in that case the proxy forwards `Host: upstreamHost` (including a non-default port when needed)
- The reverse proxy always generates its own edge `x-request-id`
- Incoming caller `x-request-id` is preserved as `x-client-request-id` when present and forwarded upstream alongside the edge ID
- `x-forwarded-for`, `x-forwarded-host`, and `x-forwarded-proto` are added explicitly
- Downstream responses always return the edge `x-request-id`; upstream response IDs are surfaced as `x-upstream-request-id` when available
- Hop-by-hop headers are stripped from proxied HTTP requests and responses
- Public HTTPS and websocket traffic still runs through the same in-process HTTPS server after SNI-based TCP demultiplexing, so the HTTP proxy keeps the original client socket and remote address
- TLS context selection now uses a mixed registry: manual `ssl/` certificates first, then ACME-managed certificates for exact hostnames without manual coverage

### Correlation Headers

- Upstream request header `x-request-id`: edge-generated request ID created by this reverse proxy
- Upstream request header `x-client-request-id`: original caller request ID when the incoming request already had `x-request-id`
- Downstream response header `x-request-id`: edge-generated request ID created by this reverse proxy
- Downstream response header `x-upstream-request-id`: request ID returned by the proxied upstream HTTP service when available

## Upgrade Support

The proxy now handles HTTP `Upgrade` requests, including WebSocket-style handshakes, by tunneling them to mapped upstreams with the same connect timeout, idle timeout, logging, and cancellation rules.

Public `wss://` works through the HTTPS listener on port `443` for `http-proxy` targets. If the target uses `protocol: "http:"`, the proxy forwards that upgraded connection to the upstream without TLS; if the target uses `protocol: "https:"`, the proxy connects to the upstream over TLS and uses `upstreamHost` as the SNI name when configured, otherwise `host`. Public `ws://` on port `80` is not proxied, because port `80` is reserved for HTTP-to-HTTPS redirect traffic and ACME HTTP-01 challenge handling.

## TURN/TLS Support

`webrtc-turns.gdmn.app` is now routed as raw TLS passthrough on public port `443` based on the incoming TLS SNI value. The proxy does not terminate TLS for this host and does not attempt HTTP parsing. It simply tunnels bytes to `localhost:5349` with connect timeout, idle timeout, cleanup, and structured lifecycle logging.

Important constraint: SNI is required to distinguish TURN/TLS traffic from regular HTTPS traffic on the shared public `443` listener. Clients that do not send SNI cannot be deterministically separated from normal HTTPS on the same socket and will fall back to the HTTPS handler path.

## Observability

`GET /_reverse_proxy_log` now returns structured JSON containing:

- current, peak, and configured concurrency values
- timeout configuration, including `REVERSE_PROXY_CHATGPT_PROXY_TIMEOUT_MS`
- TLS certificate source and availability for each TLS-terminated hostname
- recent sanitized request lifecycle entries with `edgeRequestId`, `clientRequestId`, `upstreamRequestId`, route data, duration, `resultCategory`, `statusCode`, `proxyStatusCode`, `upstreamStatusCode`, and per-request timeout values
- passthrough tunnel concurrency and TLS tunnel lifecycle entries for TURN/TLS traffic

For `chatgpt-proxy.gdmn.app`, each request log entry includes the effective `connectTimeoutMs`, `upstreamTimeoutMs`, `inboundTimeoutMs`, and `chatgptProxyTimeoutOverrideUsed` flag so timeout incidents show the exact budget that was applied.