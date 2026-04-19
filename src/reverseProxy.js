const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const { STATUS_CODES } = require('http');
const { randomUUID } = require('crypto');

const { resolveHostMapping } = require('./config');

const CHATGPT_PROXY_HOST = 'chatgpt-proxy.gdmn.app';
const EDGE_REQUEST_ID_HEADER = 'x-request-id';
const CLIENT_REQUEST_ID_HEADER = 'x-client-request-id';
const UPSTREAM_REQUEST_ID_HEADER = 'x-upstream-request-id';
const MAX_REQUEST_ID_LENGTH = 256;

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

const REDACTED_QUERY_PARAM_PATTERN = /(token|key|secret|password|signature|sig|auth|cookie)/i;
const NETWORK_FAILURE_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EPIPE',
  'ERR_STREAM_PREMATURE_CLOSE'
]);

const noop = () => undefined;

const once = (fn) => {
  let called = false;

  return (...args) => {
    if (called) {
      return undefined;
    }

    called = true;
    return fn(...args);
  };
};

const addListener = (cleanupFns, emitter, event, listener) => {
  emitter.on(event, listener);
  cleanupFns.push(() => emitter.off(event, listener));
};

const swallowStreamErrors = (stream) => {
  if (!stream) {
    return;
  }

  stream.on('error', noop);
};

const sanitizePath = (rawUrl = '/') => {
  try {
    const url = new URL(rawUrl, 'http://reverse-proxy.local');

    for (const key of url.searchParams.keys()) {
      if (REDACTED_QUERY_PARAM_PATTERN.test(key)) {
        url.searchParams.set(key, '[redacted]');
      }
    }

    const sanitizedUrl = `${url.pathname}${url.search}`;
    return sanitizedUrl.length > 2_048
      ? `${sanitizedUrl.slice(0, 2_045)}...`
      : sanitizedUrl;
  } catch {
    const [pathname] = String(rawUrl).split('?');
    return pathname || '/';
  }
};

const sanitizeError = (error) => {
  if (!error) {
    return null;
  }

  return {
    code: error.code ?? 'UNKNOWN',
    message: String(error.message ?? 'Unknown error').slice(0, 512)
  };
};

const createLogStore = ({ maxEntries = 500 } = {}) => {
  const entries = [];

  return {
    append(entry) {
      const sanitizedEntry = JSON.parse(JSON.stringify(entry));
      entries.push(sanitizedEntry);

      if (entries.length > maxEntries) {
        entries.splice(0, entries.length - maxEntries);
      }

      console.log(JSON.stringify(sanitizedEntry));
    },
    snapshot(summary = {}) {
      return {
        summary,
        entries: [...entries].reverse()
      };
    }
  };
};

const createRequestTracker = ({ maxParallelRequests }) => {
  let currentParallelRequests = 0;
  let maxObservedParallelRequests = 0;
  let totalRequests = 0;

  return {
    recordRequest() {
      totalRequests += 1;
    },
    tryAcquire() {
      if (currentParallelRequests >= maxParallelRequests) {
        return null;
      }

      currentParallelRequests += 1;
      if (currentParallelRequests > maxObservedParallelRequests) {
        maxObservedParallelRequests = currentParallelRequests;
      }

      let released = false;

      return {
        release() {
          if (released) {
            return;
          }

          released = true;
          currentParallelRequests = Math.max(0, currentParallelRequests - 1);
        }
      };
    },
    snapshot() {
      return {
        currentParallelRequests,
        maxObservedParallelRequests,
        totalRequests,
        maxParallelRequests
      };
    }
  };
};

const createProxyError = (code, message, extra = {}) => {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, extra);
  return error;
};

const createCompletionResult = (
  statusCode,
  { kind = 'http', upstreamRequestId = null } = {}
) => {
  const isUpstreamHttpError = kind === 'http' && statusCode >= 400;

  return {
    statusCode,
    type: isUpstreamHttpError ? 'upstream_http_error' : 'completed',
    code: isUpstreamHttpError ? 'UPSTREAM_HTTP_ERROR' : 'SUCCESS',
    message:
      kind === 'upgrade'
        ? 'Upgrade tunnel completed'
        : isUpstreamHttpError
          ? `Upstream service responded with HTTP ${statusCode}`
          : 'Upstream response completed',
    resultCategory: isUpstreamHttpError ? 'upstream_http_error' : 'completed',
    statusSource: 'upstream',
    proxyStatusCode: null,
    upstreamStatusCode: statusCode,
    upstreamRequestId,
    respond: false,
    error: null
  };
};

const isHttpProxyTarget = (target) => {
  if (!target) {
    return false;
  }

  const mode = target.mode ?? 'http-proxy';
  const protocol = target.protocol ?? 'http:';

  return mode === 'http-proxy' && (protocol === 'http:' || protocol === 'https:');
};

const createEdgeResult = ({
  statusCode,
  type,
  code,
  message,
  resultCategory,
  respond,
  error
}) => ({
  statusCode,
  type,
  code,
  message,
  resultCategory,
  statusSource: 'edge',
  proxyStatusCode: statusCode,
  upstreamStatusCode: null,
  upstreamRequestId: null,
  respond,
  error
});

const classifyProxyError = (error = createProxyError('REVERSE_PROXY_BAD_GATEWAY', 'Bad Gateway')) => {
  const sanitizedError = sanitizeError(error);

  switch (error.code) {
    case 'REVERSE_PROXY_NOT_FOUND':
      return createEdgeResult({
        statusCode: 404,
        type: 'unknown_host',
        code: 'REVERSE_PROXY_NOT_FOUND',
        message: 'Unknown host mapping',
        resultCategory: 'not_found',
        respond: true,
        error: sanitizedError
      });
    case 'REVERSE_PROXY_OVERLOAD':
      return createEdgeResult({
        statusCode: 503,
        type: 'overloaded',
        code: 'REVERSE_PROXY_OVERLOAD',
        message: 'Reverse proxy overloaded',
        resultCategory: 'overloaded',
        respond: true,
        error: sanitizedError
      });
    case 'REVERSE_PROXY_CONNECT_TIMEOUT':
      return createEdgeResult({
        statusCode: 504,
        type: 'upstream_timeout',
        code: 'REVERSE_PROXY_CONNECT_TIMEOUT',
        message: 'Upstream proxy target connection timed out',
        resultCategory: 'timed_out',
        respond: true,
        error: sanitizedError
      });
    case 'REVERSE_PROXY_TIMEOUT':
    case 'ETIMEDOUT':
      return createEdgeResult({
        statusCode: 504,
        type: 'upstream_timeout',
        code: 'REVERSE_PROXY_TIMEOUT',
        message: 'Upstream proxy target timed out',
        resultCategory: 'timed_out',
        respond: true,
        error: sanitizedError
      });
    case 'REVERSE_PROXY_BAD_UPGRADE':
      return createEdgeResult({
        statusCode: 400,
        type: 'invalid_upgrade',
        code: 'REVERSE_PROXY_BAD_UPGRADE',
        message: 'Unsupported or malformed upgrade request',
        resultCategory: 'invalid_request',
        respond: true,
        error: sanitizedError
      });
    case 'REVERSE_PROXY_UNSUPPORTED_TARGET':
      return createEdgeResult({
        statusCode: 502,
        type: 'unsupported_target',
        code: 'REVERSE_PROXY_UNSUPPORTED_TARGET',
        message: 'Resolved host does not support HTTP proxying',
        resultCategory: 'invalid_target',
        respond: true,
        error: sanitizedError
      });
    case 'REVERSE_PROXY_DOWNSTREAM_DISCONNECT':
      return createEdgeResult({
        statusCode: 499,
        type: 'downstream_disconnect',
        code: 'REVERSE_PROXY_DOWNSTREAM_DISCONNECT',
        message: 'Downstream client disconnected before the proxy completed',
        resultCategory: 'cancelled',
        respond: false,
        error: sanitizedError
      });
    default:
      if (NETWORK_FAILURE_CODES.has(error.code) || error.isUpstream) {
        return createEdgeResult({
          statusCode: 502,
          type: 'upstream_unavailable',
          code: 'REVERSE_PROXY_BAD_GATEWAY',
          message: 'Upstream proxy target unavailable',
          resultCategory: 'upstream_failure',
          respond: true,
          error: sanitizedError
        });
      }

      return createEdgeResult({
        statusCode: 500,
        type: 'proxy_error',
        code: 'REVERSE_PROXY_INTERNAL_ERROR',
        message: 'Reverse proxy failed unexpectedly',
        resultCategory: 'proxy_error',
        respond: true,
        error: sanitizedError
      });
  }
};

const normalizeRequestIdValue = (headerValue) => {
  if (Array.isArray(headerValue)) {
    for (const value of headerValue) {
      const normalizedValue = normalizeRequestIdValue(value);

      if (normalizedValue) {
        return normalizedValue;
      }
    }

    return null;
  }

  if (headerValue == null) {
    return null;
  }

  const normalizedValue = String(headerValue).replace(/[\r\n]+/g, ' ').trim();

  if (!normalizedValue) {
    return null;
  }

  return normalizedValue.slice(0, MAX_REQUEST_ID_LENGTH);
};

const getRequestIdHeader = (headers, headerName) =>
  normalizeRequestIdValue(headers?.[headerName]);

const resolveClientRequestId = (headers) =>
  getRequestIdHeader(headers, CLIENT_REQUEST_ID_HEADER) ??
  getRequestIdHeader(headers, EDGE_REQUEST_ID_HEADER);

const resolveUpstreamRequestId = (headers) =>
  getRequestIdHeader(headers, EDGE_REQUEST_ID_HEADER) ??
  getRequestIdHeader(headers, UPSTREAM_REQUEST_ID_HEADER);

const getForwardedFor = (req) => {
  const currentValue = req.headers?.['x-forwarded-for'];
  const existingValue = Array.isArray(currentValue)
    ? currentValue.join(', ')
    : String(currentValue ?? '').trim();
  const remoteAddress = String(req.socket?.remoteAddress ?? '').trim();

  if (existingValue && remoteAddress) {
    return `${existingValue}, ${remoteAddress}`;
  }

  return existingValue || remoteAddress;
};

const buildForwardHeaders = (req, ctx, { includeUpgradeHeaders = false } = {}) => {
  const forwardedHeaders = {};

  for (const [headerName, headerValue] of Object.entries(req.headers ?? {})) {
    if (headerValue == null) {
      continue;
    }

    const lowerCaseHeader = headerName.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowerCaseHeader)) {
      continue;
    }

    forwardedHeaders[lowerCaseHeader] = headerValue;
  }

  const forwardedFor = getForwardedFor(req);
  if (forwardedFor) {
    forwardedHeaders['x-forwarded-for'] = forwardedFor;
  }

  forwardedHeaders['x-forwarded-host'] = ctx.originalHost || ctx.routeHost;
  forwardedHeaders['x-forwarded-proto'] = ctx.forwardedProto;
  forwardedHeaders[EDGE_REQUEST_ID_HEADER] = ctx.edgeRequestId;

  if (ctx.clientRequestId) {
    forwardedHeaders[CLIENT_REQUEST_ID_HEADER] = ctx.clientRequestId;
  } else {
    delete forwardedHeaders[CLIENT_REQUEST_ID_HEADER];
  }

  if (includeUpgradeHeaders) {
    if (req.headers?.connection) {
      forwardedHeaders.connection = req.headers.connection;
    }

    if (req.headers?.upgrade) {
      forwardedHeaders.upgrade = req.headers.upgrade;
    }
  }

  return forwardedHeaders;
};

const sanitizeResponseHeaders = (headers, edgeRequestId) => {
  const sanitizedHeaders = {};
  const upstreamRequestId = resolveUpstreamRequestId(headers);

  for (const [headerName, headerValue] of Object.entries(headers ?? {})) {
    if (headerValue == null) {
      continue;
    }

    if (HOP_BY_HOP_HEADERS.has(headerName.toLowerCase())) {
      continue;
    }

    sanitizedHeaders[headerName] = headerValue;
  }

  sanitizedHeaders[EDGE_REQUEST_ID_HEADER] = edgeRequestId;

  if (!sanitizedHeaders[UPSTREAM_REQUEST_ID_HEADER] && upstreamRequestId) {
    sanitizedHeaders[UPSTREAM_REQUEST_ID_HEADER] = upstreamRequestId;
  }

  return {
    responseHeaders: sanitizedHeaders,
    upstreamRequestId
  };
};

const renderErrorBody = (classification, requestId) =>
  JSON.stringify(
    {
      error: {
        message: classification.message,
        type: classification.type,
        code: classification.code,
        requestId
      }
    },
    null,
    2
  );

const writeJsonResponse = (res, statusCode, body, requestId) => {
  const payload = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
  const contentLength = Buffer.byteLength(payload);

  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': contentLength,
    ...(requestId ? { 'x-request-id': requestId } : {})
  });
  res.end(payload);
};

const writeProxyErrorResponse = (res, classification, requestId) => {
  if (res.headersSent || res.writableEnded || res.destroyed || !classification.respond) {
    return;
  }

  writeJsonResponse(res, classification.statusCode, renderErrorBody(classification, requestId), requestId);
};

const writeUpgradeErrorResponse = (socket, classification, requestId) => {
  if (socket.destroyed || !classification.respond) {
    return;
  }

  const body = renderErrorBody(classification, requestId);
  const statusMessage = STATUS_CODES[classification.statusCode] ?? 'Error';
  const response = [
    `HTTP/1.1 ${classification.statusCode} ${statusMessage}`,
    'Content-Type: application/json; charset=utf-8',
    'Cache-Control: no-store',
    `Content-Length: ${Buffer.byteLength(body)}`,
    `x-request-id: ${requestId}`,
    'Connection: close',
    '',
    body
  ].join('\r\n');

  socket.end(response);
};

const resolveTimeouts = (target, routeHost, config) => {
  const chatgptProxyTimeoutOverrideUsed =
    Boolean(target) &&
    routeHost === CHATGPT_PROXY_HOST &&
    target?.upstreamTimeoutMs === undefined;

  return {
    connectTimeoutMs: target?.connectTimeoutMs ?? config.connectTimeoutMs,
    upstreamTimeoutMs:
      target?.upstreamTimeoutMs ??
      (chatgptProxyTimeoutOverrideUsed
        ? (config.chatgptProxyTimeoutMs ?? config.upstreamTimeoutMs)
        : config.upstreamTimeoutMs),
    inboundTimeoutMs: config.inboundTimeoutMs,
    chatgptProxyTimeoutOverrideUsed
  };
};

const createRequestContext = ({ req, resolution, config, kind }) => {
  const edgeRequestId = randomUUID();

  return {
    requestId: edgeRequestId,
    edgeRequestId,
    clientRequestId: resolveClientRequestId(req.headers),
    kind,
    method: req.method ?? 'GET',
    path: sanitizePath(req.url),
    originalHost: resolution.originalHost,
    routeHost: resolution.normalizedHost,
    target: resolution.target
      ? {
        ...resolution.target,
        protocol: resolution.target.protocol ?? 'http:'
      }
      : null,
    forwardedProto: req.socket?.encrypted ? 'https' : 'http',
    startTimeMs: Date.now(),
    timeouts: resolveTimeouts(resolution.target, resolution.normalizedHost, config)
  };
};

const applyDownstreamTimeoutBudget = (req, res, ctx, config) => {
  if (ctx.timeouts.upstreamTimeoutMs <= config.inboundTimeoutMs) {
    return;
  }

  req.setTimeout(ctx.timeouts.upstreamTimeoutMs, noop);
  res.setTimeout(ctx.timeouts.upstreamTimeoutMs, noop);
};

const createLogEntry = (ctx, result, stats) => ({
  timestamp: new Date().toISOString(),
  requestId: ctx.edgeRequestId,
  edgeRequestId: ctx.edgeRequestId,
  clientRequestId: ctx.clientRequestId ?? null,
  upstreamRequestId: result.upstreamRequestId ?? null,
  kind: ctx.kind,
  host: ctx.originalHost,
  routeHost: ctx.routeHost,
  upstream: ctx.target,
  method: ctx.method,
  path: ctx.path,
  startTime: new Date(ctx.startTimeMs).toISOString(),
  durationMs: Date.now() - ctx.startTimeMs,
  resultCategory: result.resultCategory,
  resultType: result.type,
  message: result.message,
  statusSource: result.statusSource ?? null,
  statusCode: result.statusCode ?? null,
  proxyStatusCode: result.proxyStatusCode ?? null,
  upstreamStatusCode: result.upstreamStatusCode ?? null,
  timeoutValues: ctx.timeouts,
  concurrency: stats,
  error: result.error ?? null
});

const withUpstreamContext = (
  result,
  { upstreamRequestId = null, upstreamStatusCode = null } = {}
) => {
  if (!upstreamRequestId && upstreamStatusCode == null) {
    return result;
  }

  return {
    ...result,
    upstreamRequestId: result.upstreamRequestId ?? upstreamRequestId,
    upstreamStatusCode: result.upstreamStatusCode ?? upstreamStatusCode
  };
};

const withObservedStatus = (result, observedStatusCode) => {
  if (observedStatusCode == null || result.statusCode === observedStatusCode) {
    return result;
  }

  if (result.statusSource === 'edge') {
    return {
      ...result,
      statusCode: observedStatusCode,
      proxyStatusCode: result.proxyStatusCode ?? result.statusCode,
      upstreamStatusCode: result.upstreamStatusCode ?? observedStatusCode
    };
  }

  return {
    ...result,
    statusCode: observedStatusCode,
    upstreamStatusCode: observedStatusCode
  };
};

const defaultClientFactory = (target) =>
  target.protocol === 'https:' ? https : http;

const createUpstreamRequest = ({ req, ctx, headers, clientFactory = defaultClientFactory }) => {
  const transport = clientFactory(ctx.target);
  const upstreamReq = transport.request({
    protocol: ctx.target.protocol,
    host: ctx.target.host,
    port: ctx.target.port,
    path: req.url,
    method: req.method,
    headers
  });

  const connectTimer = setTimeout(() => {
    upstreamReq.destroy(
      createProxyError(
        'REVERSE_PROXY_CONNECT_TIMEOUT',
        `Upstream connection to ${ctx.target.host}:${ctx.target.port} timed out after ${ctx.timeouts.connectTimeoutMs}ms`,
        { isUpstream: true }
      )
    );
  }, ctx.timeouts.connectTimeoutMs);

  const cleanupFns = [() => clearTimeout(connectTimer)];

  const handleSocket = (socket) => {
    const clearConnectTimer = () => clearTimeout(connectTimer);

    if (!socket.connecting) {
      clearConnectTimer();
      return;
    }

    socket.once('connect', clearConnectTimer);
    socket.once('secureConnect', clearConnectTimer);
    socket.once('error', clearConnectTimer);
    cleanupFns.push(() => socket.off('connect', clearConnectTimer));
    cleanupFns.push(() => socket.off('secureConnect', clearConnectTimer));
    cleanupFns.push(() => socket.off('error', clearConnectTimer));
  };

  upstreamReq.on('socket', handleSocket);
  cleanupFns.push(() => upstreamReq.off('socket', handleSocket));

  upstreamReq.setTimeout(ctx.timeouts.upstreamTimeoutMs, () => {
    upstreamReq.destroy(
      createProxyError(
        'REVERSE_PROXY_TIMEOUT',
        `Upstream proxy target timed out after ${ctx.timeouts.upstreamTimeoutMs}ms`,
        { isUpstream: true }
      )
    );
  });

  return {
    upstreamReq,
    cleanup() {
      for (const cleanup of cleanupFns.splice(0)) {
        cleanup();
      }
    }
  };
};

const respondWithLogSnapshot = (res, logStore, summary) => {
  const payload = logStore.snapshot(summary);

  writeJsonResponse(res, 200, payload);
};

const createProxyRequestHandler = ({
  hosts,
  config,
  tracker,
  logStore,
  getLogSummary,
  clientFactory = defaultClientFactory
}) => {
  return (req, res) => {
    if (req.url === '/_reverse_proxy_log' && req.method === 'GET') {
      const summary =
        typeof getLogSummary === 'function'
          ? getLogSummary()
          : {
            ...tracker.snapshot(),
            timeoutValues: {
              inboundTimeoutMs: config.inboundTimeoutMs,
              upstreamTimeoutMs: config.upstreamTimeoutMs,
              chatgptProxyTimeoutMs: config.chatgptProxyTimeoutMs ?? config.upstreamTimeoutMs,
              connectTimeoutMs: config.connectTimeoutMs
            }
          };

      respondWithLogSnapshot(res, logStore, summary);
      return;
    }

    tracker.recordRequest();
    const resolution = resolveHostMapping(req.headers?.host, hosts);
    const ctx = createRequestContext({ req, resolution, config, kind: 'http' });

    if (!ctx.target) {
      const result = classifyProxyError(
        createProxyError('REVERSE_PROXY_NOT_FOUND', 'Unknown host mapping')
      );
      writeProxyErrorResponse(res, result, ctx.requestId);
      logStore.append(createLogEntry(ctx, result, tracker.snapshot()));
      return;
    }

    if (!isHttpProxyTarget(ctx.target)) {
      const result = classifyProxyError(
        createProxyError(
          'REVERSE_PROXY_UNSUPPORTED_TARGET',
          `Resolved host ${ctx.routeHost} does not support HTTP proxying`
        )
      );
      writeProxyErrorResponse(res, result, ctx.requestId);
      logStore.append(createLogEntry(ctx, result, tracker.snapshot()));
      return;
    }

    applyDownstreamTimeoutBudget(req, res, ctx, config);

    const lease = tracker.tryAcquire();
    if (!lease) {
      const result = classifyProxyError(
        createProxyError('REVERSE_PROXY_OVERLOAD', 'Reverse proxy overloaded')
      );
      writeProxyErrorResponse(res, result, ctx.requestId);
      logStore.append(createLogEntry(ctx, result, tracker.snapshot()));
      return;
    }

    let observedStatusCode = null;
    let observedUpstreamRequestId = null;
    let upstreamReq;
    let upstreamRes;
    const cleanupFns = [() => lease.release()];

    const finalize = once((result) => {
      for (const cleanup of cleanupFns.splice(0)) {
        try {
          cleanup();
        } catch {
          noop();
        }
      }

      logStore.append(
        createLogEntry(ctx, withObservedStatus(result, observedStatusCode), tracker.snapshot())
      );
    });

    const stopUpstream = (error) => {
      if (upstreamRes && !upstreamRes.destroyed) {
        swallowStreamErrors(upstreamRes);
        upstreamRes.destroy(error);
      }

      if (upstreamReq && !upstreamReq.destroyed) {
        swallowStreamErrors(upstreamReq);
        upstreamReq.destroy(error);
      }
    };

    const abortUpstreamSilently = () => {
      if (upstreamRes && !upstreamRes.destroyed) {
        swallowStreamErrors(upstreamRes);
        upstreamRes.destroy();
      }

      if (upstreamReq && !upstreamReq.destroyed) {
        swallowStreamErrors(upstreamReq);
        upstreamReq.destroy();
      }
    };

    const failRequest = (error) => {
      const result = withUpstreamContext(classifyProxyError(error), {
        upstreamRequestId: observedUpstreamRequestId,
        upstreamStatusCode: observedStatusCode
      });
      stopUpstream(error);

      if (result.respond) {
        if (!res.headersSent && !res.writableEnded && !res.destroyed) {
          writeProxyErrorResponse(res, result, ctx.requestId);
        } else if (!res.destroyed) {
          res.destroy(error);
        }
      }

      finalize(result);
    };

    const cancelFromDownstream = () => {
      const error = createProxyError(
        'REVERSE_PROXY_DOWNSTREAM_DISCONNECT',
        'Downstream client disconnected before the proxy completed'
      );
      abortUpstreamSilently();

      if (!res.destroyed) {
        res.destroy();
      }

      finalize(classifyProxyError(error));
    };

    addListener(cleanupFns, req, 'aborted', cancelFromDownstream);
    addListener(cleanupFns, req, 'error', cancelFromDownstream);
    addListener(cleanupFns, res, 'error', cancelFromDownstream);
    addListener(cleanupFns, res, 'close', () => {
      if (!res.writableFinished) {
        cancelFromDownstream();
      }
    });
    addListener(cleanupFns, res, 'finish', () => {
      finalize(
        createCompletionResult(observedStatusCode ?? 200, {
          upstreamRequestId: observedUpstreamRequestId
        })
      );
    });

    const upstream = createUpstreamRequest({
      req,
      ctx,
      headers: buildForwardHeaders(req, ctx),
      clientFactory
    });

    upstreamReq = upstream.upstreamReq;
    cleanupFns.push(() => upstream.cleanup());

    addListener(cleanupFns, upstreamReq, 'response', (incomingResponse) => {
      upstreamRes = incomingResponse;
      observedStatusCode = incomingResponse.statusCode ?? 502;

      const sanitizedResponse = sanitizeResponseHeaders(
        incomingResponse.headers,
        ctx.edgeRequestId
      );
      observedUpstreamRequestId = sanitizedResponse.upstreamRequestId;

      if (!res.headersSent) {
        res.writeHead(observedStatusCode, sanitizedResponse.responseHeaders);
      }

      addListener(cleanupFns, incomingResponse, 'error', (error) => {
        failRequest(
          createProxyError(
            'REVERSE_PROXY_UPSTREAM_PREMATURE_CLOSE',
            'Upstream response stream failed unexpectedly',
            { cause: error, isUpstream: true }
          )
        );
      });

      addListener(cleanupFns, incomingResponse, 'aborted', () => {
        failRequest(
          createProxyError(
            'REVERSE_PROXY_UPSTREAM_PREMATURE_CLOSE',
            'Upstream response stream aborted unexpectedly',
            { isUpstream: true }
          )
        );
      });

      addListener(cleanupFns, incomingResponse, 'close', () => {
        if (!incomingResponse.complete && !res.writableFinished) {
          failRequest(
            createProxyError(
              'REVERSE_PROXY_UPSTREAM_PREMATURE_CLOSE',
              'Upstream response closed before the response completed',
              { isUpstream: true }
            )
          );
        }
      });

      incomingResponse.pipe(res);
    });

    addListener(cleanupFns, upstreamReq, 'error', failRequest);
    req.pipe(upstreamReq);
  };
};

const createRawUpgradeRequest = (req, headers) => {
  const headerLines = [];

  for (const [headerName, headerValue] of Object.entries(headers)) {
    if (Array.isArray(headerValue)) {
      for (const value of headerValue) {
        headerLines.push(`${headerName}: ${value}`);
      }
      continue;
    }

    headerLines.push(`${headerName}: ${headerValue}`);
  }

  return `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n${headerLines.join(
    '\r\n'
  )}\r\n\r\n`;
};

const defaultUpgradeSocketFactory = (target) =>
  target.protocol === 'https:'
    ? tls.connect({
      host: target.host,
      port: target.port,
      servername: target.host
    })
    : net.connect({
      host: target.host,
      port: target.port
    });

const isValidUpgradeRequest = (req) => {
  const connectionHeader = String(req.headers?.connection ?? '').toLowerCase();
  const upgradeHeader = String(req.headers?.upgrade ?? '').trim();

  return connectionHeader.includes('upgrade') && Boolean(upgradeHeader);
};

const createUpgradeProxyHandler = ({
  hosts,
  config,
  tracker,
  logStore,
  socketFactory = defaultUpgradeSocketFactory
}) => {
  return (req, socket, head) => {
    tracker.recordRequest();
    const resolution = resolveHostMapping(req.headers?.host, hosts);
    const ctx = createRequestContext({ req, resolution, config, kind: 'upgrade' });

    if (!ctx.target) {
      const result = classifyProxyError(
        createProxyError('REVERSE_PROXY_NOT_FOUND', 'Unknown host mapping')
      );
      writeUpgradeErrorResponse(socket, result, ctx.requestId);
      logStore.append(createLogEntry(ctx, result, tracker.snapshot()));
      return;
    }

    if (!isHttpProxyTarget(ctx.target)) {
      const result = classifyProxyError(
        createProxyError(
          'REVERSE_PROXY_UNSUPPORTED_TARGET',
          `Resolved host ${ctx.routeHost} does not support HTTP upgrade proxying`
        )
      );
      writeUpgradeErrorResponse(socket, result, ctx.requestId);
      logStore.append(createLogEntry(ctx, result, tracker.snapshot()));
      return;
    }

    if (!isValidUpgradeRequest(req)) {
      const result = classifyProxyError(
        createProxyError(
          'REVERSE_PROXY_BAD_UPGRADE',
          'Unsupported or malformed upgrade request'
        )
      );
      writeUpgradeErrorResponse(socket, result, ctx.requestId);
      logStore.append(createLogEntry(ctx, result, tracker.snapshot()));
      return;
    }

    const lease = tracker.tryAcquire();
    if (!lease) {
      const result = classifyProxyError(
        createProxyError('REVERSE_PROXY_OVERLOAD', 'Reverse proxy overloaded')
      );
      writeUpgradeErrorResponse(socket, result, ctx.requestId);
      logStore.append(createLogEntry(ctx, result, tracker.snapshot()));
      return;
    }

    socket.pause();
    socket.setNoDelay(true);

    let observedStatusCode = 101;
    let upstreamSocket;
    let upstreamResponseSeen = false;
    const cleanupFns = [() => lease.release()];

    const finalize = once((result) => {
      for (const cleanup of cleanupFns.splice(0)) {
        try {
          cleanup();
        } catch {
          noop();
        }
      }

      logStore.append(
        createLogEntry(ctx, withObservedStatus(result, observedStatusCode), tracker.snapshot())
      );
    });

    const cancelFromDownstream = () => {
      const error = createProxyError(
        'REVERSE_PROXY_DOWNSTREAM_DISCONNECT',
        'Downstream client disconnected before the proxy completed'
      );

      if (upstreamSocket && !upstreamSocket.destroyed) {
        swallowStreamErrors(upstreamSocket);
        upstreamSocket.destroy();
      }

      finalize(classifyProxyError(error));
    };

    const failUpgrade = (error) => {
      const result = classifyProxyError(error);

      if (upstreamSocket && !upstreamSocket.destroyed) {
        swallowStreamErrors(upstreamSocket);
        upstreamSocket.destroy(error);
      }

      if (result.respond && !upstreamResponseSeen && !socket.destroyed) {
        writeUpgradeErrorResponse(socket, result, ctx.requestId);
      } else if (!socket.destroyed) {
        socket.destroy(error);
      }

      finalize(result);
    };

    addListener(cleanupFns, socket, 'error', cancelFromDownstream);
    addListener(cleanupFns, socket, 'close', cancelFromDownstream);

    upstreamSocket = socketFactory(ctx.target);
    cleanupFns.push(() => {
      if (upstreamSocket && !upstreamSocket.destroyed) {
        upstreamSocket.destroy();
      }
    });

    const connectTimer = setTimeout(() => {
      failUpgrade(
        createProxyError(
          'REVERSE_PROXY_CONNECT_TIMEOUT',
          `Upstream connection to ${ctx.target.host}:${ctx.target.port} timed out after ${ctx.timeouts.connectTimeoutMs}ms`,
          { isUpstream: true }
        )
      );
    }, ctx.timeouts.connectTimeoutMs);

    cleanupFns.push(() => clearTimeout(connectTimer));

    const idleTimeoutHandler = () => {
      failUpgrade(
        createProxyError(
          'REVERSE_PROXY_TIMEOUT',
          `Upstream proxy target timed out after ${ctx.timeouts.upstreamTimeoutMs}ms`,
          { isUpstream: true }
        )
      );
    };

    socket.setTimeout(ctx.timeouts.upstreamTimeoutMs, idleTimeoutHandler);
    upstreamSocket.setTimeout(ctx.timeouts.upstreamTimeoutMs, idleTimeoutHandler);
    cleanupFns.push(() => socket.setTimeout(0));
    cleanupFns.push(() => upstreamSocket.setTimeout(0));

    addListener(cleanupFns, upstreamSocket, 'data', () => {
      upstreamResponseSeen = true;
    });
    addListener(cleanupFns, upstreamSocket, 'error', failUpgrade);
    addListener(cleanupFns, upstreamSocket, 'close', () => {
      if (!upstreamResponseSeen) {
        failUpgrade(
          createProxyError(
            'REVERSE_PROXY_UPSTREAM_PREMATURE_CLOSE',
            'Upstream upgrade socket closed before returning a response',
            { isUpstream: true }
          )
        );
        return;
      }

      if (!socket.destroyed) {
        socket.end();
      }

      finalize(createCompletionResult(observedStatusCode, { kind: 'upgrade' }));
    });

    const connectEvent = ctx.target.protocol === 'https:' ? 'secureConnect' : 'connect';
    const handleConnect = () => {
      clearTimeout(connectTimer);

      const headers = buildForwardHeaders(req, ctx, { includeUpgradeHeaders: true });
      upstreamSocket.write(createRawUpgradeRequest(req, headers));

      if (head?.length) {
        upstreamSocket.write(head);
      }

      socket.pipe(upstreamSocket);
      upstreamSocket.pipe(socket);
      socket.resume();
    };

    upstreamSocket.once(connectEvent, handleConnect);
    cleanupFns.push(() => upstreamSocket.off(connectEvent, handleConnect));
  };
};

module.exports = {
  classifyProxyError,
  createLogStore,
  createProxyError,
  createProxyRequestHandler,
  createRequestContext,
  createRequestTracker,
  createUpgradeProxyHandler,
  applyDownstreamTimeoutBudget,
  isHttpProxyTarget,
  sanitizePath
};