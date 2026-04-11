# reverse-proxy

This repository runs a Node.js edge proxy on ports `443` and `80`. Public port `443` is now an SNI-aware TCP router: standard HTTPS traffic is handed into the in-process HTTPS reverse proxy, while TURN/TLS traffic for `webrtc-turns.gdmn.app` is passed through as raw TLS to its localhost upstream.

## Runtime And Deployment Baseline

- Package manager: `npm` via `package-lock.json`
- Runtime entrypoint: `npm start` or `node src/index.js`
- Container runtime expectation: `Dockerfile` uses `node:25-alpine`, copies only runtime files, installs production dependencies, and starts `node src/index.js`
- Listener expectation: the process binds directly to `80` and `443`
- TLS expectation: manual certificates can exist at `ssl/<domain>/<domain>.crt`, `.key`, and `.ca-bundle`, and should be mounted at runtime rather than baked into the image
- Upstream expectation proven by this repo: most routed backends are localhost HTTP services, and `webrtc-turns.gdmn.app` is a raw TLS passthrough route to `localhost:5349`

## TLS Certificate Sources

- Manual certificates under `ssl/<domain>/` remain the first-priority source and continue to work for the matching domain and any subdomain covered by that certificate.
- Let's Encrypt is used only for TLS-terminated hostnames that do not have manual coverage from `ssl/`.
- ACME-managed certificates are stored separately under `acme-data/certificates/<domain>/` by default so user-provided files in `ssl/` stay untouched.
- If a manual certificate later appears for a hostname that was previously using Let's Encrypt, the manual certificate wins on the next registry reload.
- Hosts configured as `tls-passthrough` are excluded from certificate issuance and renewal.

## Let's Encrypt HTTP-01

- Port `80` still redirects normal traffic to HTTPS.
- The only exception is `/.well-known/acme-challenge/*`, which is served directly for active HTTP-01 challenges.
- Automatic issuance and renewal are enabled only when `REVERSE_PROXY_ACME_EMAIL` is set or `REVERSE_PROXY_ACME_ENABLED=true` is configured together with an email address.

## Host Mappings

- `chatgpt-proxy.gdmn.app` -> `localhost:3002`
- `alemaro.team` -> `localhost:3003`
- `socket-server.gdmn.app` -> `localhost:3030`
- `webrtc-turns.gdmn.app` -> raw TLS passthrough to `localhost:5349`

The proxy still normalizes a leading `www.` prefix before route lookup.

## Reliability Controls

The reverse proxy now applies explicit lifecycle controls to proxied HTTP requests, HTTP upgrade traffic, and TURN/TLS passthrough tunnels:

- Explicit upstream response timeout with `REVERSE_PROXY_UPSTREAM_TIMEOUT_MS`
- Explicit upstream connect timeout with `REVERSE_PROXY_CONNECT_TIMEOUT_MS`
- Bounded in-process concurrency with `REVERSE_PROXY_MAX_PARALLEL_REQUESTS`
- Structured request logging with request IDs and lifecycle outcome data via `/_reverse_proxy_log`
- Downstream disconnect propagation so upstream requests are aborted when the client disappears
- Deterministic `502`, `503`, and `504` responses for proxy-generated failures
- Structured passthrough tunnel logging for TURN/TLS connections

### Environment Variables

- `REVERSE_PROXY_UPSTREAM_TIMEOUT_MS`: idle timeout for proxied upstream requests and upgrade sockets. Default: `900000`
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

This example keeps manual certificates under `ssl/`, stores Let's Encrypt account and managed certificate data under `acme-data/`, and loads the environment from `.env`.

```bash
docker run -d \
	--name reverse-proxy \
	--restart unless-stopped \
	-p 80:80 \
	-p 443:443 \
	--env-file ./.env \
	-v /path/to/reverse-proxy/ssl:/app/ssl:ro \
	-v /path/to/reverse-proxy/acme-data:/app/acme-data \
	gsbelarus/reverse-proxy
```

Notes:

- Keep `ssl/` mounted read-only if it contains only user-managed certificates.
- Keep `acme-data/` writable so the proxy can store the ACME account key and managed certificates.
- `--env-file ./.env` is read from the host shell's current working directory. Use an absolute path if you want to avoid any ambiguity.
- The image intentionally does not bundle manual certificate files; provide them through the `ssl/` mount.
- If you later switch from staging to production, update `REVERSE_PROXY_ACME_DIRECTORY_URL` and remove any staging certificates from `acme-data/` before reissuing.

## Proxy Failure Semantics

- Unknown host mapping: `404`
- Upstream unavailable or connection refused: `502`
- Upstream timeout or connect timeout: `504`
- Local overload from the concurrency cap: `503`
- Downstream disconnect: logged as cancellation and upstream work is aborted; the proxy does not attempt to send a synthetic response after the client is gone

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
- Original `Host` is preserved
- `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, and `x-request-id` are added explicitly
- Hop-by-hop headers are stripped from proxied HTTP requests and responses
- Public HTTPS and websocket traffic still runs through the same in-process HTTPS server after SNI-based TCP demultiplexing, so the HTTP proxy keeps the original client socket and remote address
- TLS context selection now uses a mixed registry: manual `ssl/` certificates first, then ACME-managed certificates for exact hostnames without manual coverage

## Upgrade Support

The proxy now handles HTTP `Upgrade` requests, including WebSocket-style handshakes, by tunneling them to mapped upstreams with the same connect timeout, idle timeout, logging, and cancellation rules.

## TURN/TLS Support

`webrtc-turns.gdmn.app` is now routed as raw TLS passthrough on public port `443` based on the incoming TLS SNI value. The proxy does not terminate TLS for this host and does not attempt HTTP parsing. It simply tunnels bytes to `localhost:5349` with connect timeout, idle timeout, cleanup, and structured lifecycle logging.

Important constraint: SNI is required to distinguish TURN/TLS traffic from regular HTTPS traffic on the shared public `443` listener. Clients that do not send SNI cannot be deterministically separated from normal HTTPS on the same socket and will fall back to the HTTPS handler path.

## Observability

`GET /_reverse_proxy_log` now returns structured JSON containing:

- current, peak, and configured concurrency values
- timeout configuration
- TLS certificate source and availability for each TLS-terminated hostname
- recent sanitized request lifecycle entries with request IDs, routes, upstream targets, duration, outcome, and status details
- passthrough tunnel concurrency and TLS tunnel lifecycle entries for TURN/TLS traffic