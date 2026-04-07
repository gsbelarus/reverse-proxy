# reverse-proxy

This repository runs a Node.js edge proxy on ports `443` and `80`. Public port `443` is now an SNI-aware TCP router: standard HTTPS traffic is handed into the in-process HTTPS reverse proxy, while TURN/TLS traffic for `webrtc-turns.gdmn.app` is passed through as raw TLS to its localhost upstream.

## Runtime And Deployment Baseline

- Package manager: `npm` via `package-lock.json`
- Runtime entrypoint: `npm start` or `node src/index.js`
- Container runtime expectation: `Dockerfile` uses `node:23-alpine`, copies the full repository, runs `npm install`, and starts `node src/index.js`
- Listener expectation: the process binds directly to `80` and `443`
- TLS expectation: certificates must exist at `ssl/<domain>/<domain>.crt`, `.key`, and `.ca-bundle`
- Upstream expectation proven by this repo: most routed backends are localhost HTTP services, and `webrtc-turns.gdmn.app` is a raw TLS passthrough route to `localhost:5349`

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

## Upgrade Support

The proxy now handles HTTP `Upgrade` requests, including WebSocket-style handshakes, by tunneling them to mapped upstreams with the same connect timeout, idle timeout, logging, and cancellation rules.

## TURN/TLS Support

`webrtc-turns.gdmn.app` is now routed as raw TLS passthrough on public port `443` based on the incoming TLS SNI value. The proxy does not terminate TLS for this host and does not attempt HTTP parsing. It simply tunnels bytes to `localhost:5349` with connect timeout, idle timeout, cleanup, and structured lifecycle logging.

Important constraint: SNI is required to distinguish TURN/TLS traffic from regular HTTPS traffic on the shared public `443` listener. Clients that do not send SNI cannot be deterministically separated from normal HTTPS on the same socket and will fall back to the HTTPS handler path.

## Observability

`GET /_reverse_proxy_log` now returns structured JSON containing:

- current, peak, and configured concurrency values
- timeout configuration
- recent sanitized request lifecycle entries with request IDs, routes, upstream targets, duration, outcome, and status details
- passthrough tunnel concurrency and TLS tunnel lifecycle entries for TURN/TLS traffic