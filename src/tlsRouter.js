const net = require('net');
const { randomUUID } = require('crypto');

const { getHostMap, normalizeHost } = require('./config');
const { classifyProxyError, createProxyError } = require('./reverseProxy');

const TLS_RECORD_HEADER_LENGTH = 5;
const TLS_HANDSHAKE_CONTENT_TYPE = 22;
const TLS_CLIENT_HELLO = 1;
const MAX_CLIENT_HELLO_BYTES = 64 * 1024;
const TLS_PASSTHROUGH_MODE = 'tls-passthrough';

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

const toTunnelResult = (error) => {
  const classification = classifyProxyError(error);

  return {
    type: classification.type,
    code: classification.code,
    message: classification.message,
    resultCategory: classification.resultCategory,
    error: classification.error
  };
};

const createTunnelCompletionResult = () => ({
  type: 'completed',
  code: 'SUCCESS',
  message: 'TLS passthrough tunnel completed',
  resultCategory: 'completed',
  error: null
});

const readHandshakeHeader = (bufferChunks, totalLength) => {
  if (totalLength < 4) {
    return null;
  }

  const header = Buffer.concat(bufferChunks, totalLength).subarray(0, 4);
  return {
    type: header[0],
    length: header.readUIntBE(1, 3)
  };
};

const parseServerNameExtension = (extensionsBuffer) => {
  let offset = 0;

  while (offset + 4 <= extensionsBuffer.length) {
    const extensionType = extensionsBuffer.readUInt16BE(offset);
    const extensionLength = extensionsBuffer.readUInt16BE(offset + 2);
    offset += 4;

    if (offset + extensionLength > extensionsBuffer.length) {
      return null;
    }

    if (extensionType === 0) {
      if (extensionLength < 2) {
        return null;
      }

      let nameOffset = offset + 2;
      const listEnd = offset + extensionLength;

      while (nameOffset + 3 <= listEnd) {
        const nameType = extensionsBuffer[nameOffset];
        const nameLength = extensionsBuffer.readUInt16BE(nameOffset + 1);
        nameOffset += 3;

        if (nameOffset + nameLength > listEnd) {
          return null;
        }

        if (nameType === 0) {
          return extensionsBuffer.toString('utf8', nameOffset, nameOffset + nameLength);
        }

        nameOffset += nameLength;
      }

      return null;
    }

    offset += extensionLength;
  }

  return null;
};

const parseClientHelloServerName = (clientHelloBody) => {
  let offset = 0;

  if (clientHelloBody.length < 34) {
    return null;
  }

  offset += 2; // legacy_version
  offset += 32; // random

  const sessionIdLength = clientHelloBody[offset];
  offset += 1 + sessionIdLength;

  if (offset + 2 > clientHelloBody.length) {
    return null;
  }

  const cipherSuitesLength = clientHelloBody.readUInt16BE(offset);
  offset += 2 + cipherSuitesLength;

  if (offset + 1 > clientHelloBody.length) {
    return null;
  }

  const compressionMethodsLength = clientHelloBody[offset];
  offset += 1 + compressionMethodsLength;

  if (offset === clientHelloBody.length) {
    return null;
  }

  if (offset + 2 > clientHelloBody.length) {
    return null;
  }

  const extensionsLength = clientHelloBody.readUInt16BE(offset);
  offset += 2;

  if (offset + extensionsLength > clientHelloBody.length) {
    return null;
  }

  return parseServerNameExtension(clientHelloBody.subarray(offset, offset + extensionsLength));
};

const inspectTlsClientHello = (buffer) => {
  if (!buffer?.length) {
    return { state: 'need_more_data' };
  }

  let offset = 0;
  const handshakeChunks = [];
  let handshakeBytesLength = 0;
  let handshakeHeader = null;

  while (offset + TLS_RECORD_HEADER_LENGTH <= buffer.length) {
    const contentType = buffer[offset];
    const recordLength = buffer.readUInt16BE(offset + 3);

    if (contentType !== TLS_HANDSHAKE_CONTENT_TYPE) {
      return { state: 'not_tls_handshake' };
    }

    if (offset + TLS_RECORD_HEADER_LENGTH + recordLength > buffer.length) {
      return { state: 'need_more_data' };
    }

    const recordPayload = buffer.subarray(
      offset + TLS_RECORD_HEADER_LENGTH,
      offset + TLS_RECORD_HEADER_LENGTH + recordLength
    );

    handshakeChunks.push(recordPayload);
    handshakeBytesLength += recordPayload.length;

    if (!handshakeHeader) {
      handshakeHeader = readHandshakeHeader(handshakeChunks, handshakeBytesLength);

      if (handshakeHeader && handshakeHeader.type !== TLS_CLIENT_HELLO) {
        return { state: 'not_client_hello' };
      }
    }

    if (handshakeHeader && handshakeBytesLength >= handshakeHeader.length + 4) {
      const handshakeBuffer = Buffer.concat(handshakeChunks, handshakeBytesLength).subarray(
        0,
        handshakeHeader.length + 4
      );
      const serverName = parseClientHelloServerName(handshakeBuffer.subarray(4));

      return {
        state: 'parsed',
        serverName: serverName ? normalizeHost(serverName) : null
      };
    }

    offset += TLS_RECORD_HEADER_LENGTH + recordLength;
  }

  return { state: 'need_more_data' };
};

const isPassthroughTarget = (target) => target?.mode === TLS_PASSTHROUGH_MODE;

const getPassthroughTarget = (hosts, serverName) => {
  const normalizedHost = normalizeHost(serverName);
  const target = getHostMap(hosts)[normalizedHost] ?? null;

  if (!isPassthroughTarget(target)) {
    return null;
  }

  return {
    routeHost: normalizedHost,
    target
  };
};

const toPassthroughSummary = (tracker) => {
  const stats = tracker.snapshot();

  return {
    currentConnections: stats.currentParallelRequests,
    maxObservedConnections: stats.maxObservedParallelRequests,
    totalConnections: stats.totalRequests,
    maxConnections: stats.maxParallelRequests
  };
};

const createTunnelLogEntry = (ctx, result, tracker) => ({
  timestamp: new Date().toISOString(),
  requestId: ctx.requestId,
  kind: 'tls_passthrough',
  host: ctx.host,
  routeHost: ctx.routeHost,
  upstream: ctx.upstream,
  startTime: new Date(ctx.startTimeMs).toISOString(),
  durationMs: Date.now() - ctx.startTimeMs,
  resultCategory: result.resultCategory,
  resultType: result.type,
  message: result.message,
  timeoutValues: ctx.timeoutValues,
  connection: ctx.connection,
  bytesReceived: ctx.bytesReceived,
  bytesSent: ctx.bytesSent,
  concurrency: toPassthroughSummary(tracker),
  error: result.error ?? null
});

const handOffToHttpsServer = ({ httpsServer, socket, bufferedData }) => {
  if (socket.destroyed) {
    return;
  }

  socket.pause();

  if (bufferedData.length > 0) {
    socket.unshift(bufferedData);
  }

  process.nextTick(() => {
    if (socket.destroyed) {
      return;
    }

    httpsServer.emit('connection', socket);
    socket.resume();
  });
};

const createTlsRouterHandler = ({
  hosts,
  httpsServer,
  config,
  tracker,
  logStore,
  socketFactory = net.connect
}) => {
  return (socket) => {
    let bufferedChunks = [];
    let bufferedLength = 0;
    let routed = false;

    const bufferedData = () => Buffer.concat(bufferedChunks, bufferedLength);

    const cleanupFns = [];
    const cleanup = () => {
      for (const fn of cleanupFns.splice(0)) {
        try {
          fn();
        } catch {
          noop();
        }
      }
    };

    const forwardToHttps = () => {
      if (routed || socket.destroyed) {
        return;
      }

      routed = true;
      cleanup();
      handOffToHttpsServer({
        httpsServer,
        socket,
        bufferedData: bufferedData()
      });
    };

    const sniffTimeout = setTimeout(forwardToHttps, config.connectTimeoutMs);
    cleanupFns.push(() => clearTimeout(sniffTimeout));

    const onSocketError = () => {
      cleanup();
    };

    socket.on('error', onSocketError);
    socket.on('close', cleanup);
    cleanupFns.push(() => socket.off('error', onSocketError));
    cleanupFns.push(() => socket.off('close', cleanup));

    const onData = (chunk) => {
      if (routed) {
        return;
      }

      bufferedChunks.push(chunk);
      bufferedLength += chunk.length;

      if (bufferedLength > MAX_CLIENT_HELLO_BYTES) {
        forwardToHttps();
        return;
      }

      const inspection = inspectTlsClientHello(bufferedData());

      if (inspection.state === 'need_more_data') {
        return;
      }

      if (inspection.state !== 'parsed' || !inspection.serverName) {
        forwardToHttps();
        return;
      }

      const passthroughRoute = getPassthroughTarget(hosts, inspection.serverName);
      if (!passthroughRoute) {
        forwardToHttps();
        return;
      }

      routed = true;
      cleanup();

      tracker.recordRequest();
      const lease = tracker.tryAcquire();
      const ctx = {
        requestId: randomUUID(),
        host: inspection.serverName,
        routeHost: passthroughRoute.routeHost,
        upstream: {
          host: passthroughRoute.target.host,
          port: passthroughRoute.target.port,
          mode: passthroughRoute.target.mode
        },
        timeoutValues: {
          connectTimeoutMs:
            passthroughRoute.target.connectTimeoutMs ?? config.connectTimeoutMs,
          upstreamTimeoutMs:
            passthroughRoute.target.upstreamTimeoutMs ?? config.upstreamTimeoutMs
        },
        startTimeMs: Date.now(),
        connection: {
          remoteAddress: socket.remoteAddress ?? null,
          remotePort: socket.remotePort ?? null
        },
        bytesReceived: 0,
        bytesSent: 0
      };
      let connectTimer = null;

      const finalize = once((result) => {
        if (connectTimer) {
          clearTimeout(connectTimer);
          connectTimer = null;
        }

        if (lease) {
          lease.release();
        }

        logStore.append(createTunnelLogEntry(ctx, result, tracker));
      });

      if (!lease) {
        socket.destroy();
        finalize(
          toTunnelResult(
            createProxyError('REVERSE_PROXY_OVERLOAD', 'Reverse proxy overloaded')
          )
        );
        return;
      }

      socket.pause();
      socket.setNoDelay(true);
      ctx.bytesReceived += bufferedLength;

      let upstreamSocket;
      let tunnelEstablished = false;

      const destroyUpstream = (error) => {
        if (upstreamSocket && !upstreamSocket.destroyed) {
          upstreamSocket.on('error', noop);
          upstreamSocket.destroy(error);
        }
      };

      const failTunnel = (error) => {
        destroyUpstream(error);

        if (!socket.destroyed) {
          socket.destroy(error);
        }

        finalize(toTunnelResult(error));
      };

      const cancelTunnel = () => {
        destroyUpstream();
        finalize(
          toTunnelResult(
            createProxyError(
              'REVERSE_PROXY_DOWNSTREAM_DISCONNECT',
              'Downstream client disconnected before the TLS passthrough tunnel completed'
            )
          )
        );
      };

      connectTimer = setTimeout(() => {
        failTunnel(
          createProxyError(
            'REVERSE_PROXY_CONNECT_TIMEOUT',
            `Upstream connection to ${ctx.upstream.host}:${ctx.upstream.port} timed out after ${ctx.timeoutValues.connectTimeoutMs}ms`,
            { isUpstream: true }
          )
        );
      }, ctx.timeoutValues.connectTimeoutMs);

      const idleTimeoutHandler = () => {
        failTunnel(
          createProxyError(
            'REVERSE_PROXY_TIMEOUT',
            `TLS passthrough tunnel timed out after ${ctx.timeoutValues.upstreamTimeoutMs}ms`,
            { isUpstream: true }
          )
        );
      };

      socket.on('error', cancelTunnel);
      socket.on('close', () => {
        if (!socket.writableEnded) {
          cancelTunnel();
        }
      });
      socket.on('data', (data) => {
        ctx.bytesReceived += data.length;
      });

      upstreamSocket = socketFactory({
        host: ctx.upstream.host,
        port: ctx.upstream.port
      });
      upstreamSocket.setNoDelay(true);
      upstreamSocket.on('data', (data) => {
        ctx.bytesSent += data.length;
      });
      upstreamSocket.on('error', failTunnel);
      upstreamSocket.on('close', () => {
        if (!tunnelEstablished) {
          failTunnel(
            createProxyError(
              'REVERSE_PROXY_UPSTREAM_PREMATURE_CLOSE',
              'TLS passthrough upstream closed before the tunnel was established',
              { isUpstream: true }
            )
          );
          return;
        }

        if (!socket.destroyed) {
          socket.end();
        }

        finalize(createTunnelCompletionResult());
      });

      upstreamSocket.once('connect', () => {
        tunnelEstablished = true;
        clearTimeout(connectTimer);
        connectTimer = null;
        socket.setTimeout(ctx.timeoutValues.upstreamTimeoutMs, idleTimeoutHandler);
        upstreamSocket.setTimeout(ctx.timeoutValues.upstreamTimeoutMs, idleTimeoutHandler);
        upstreamSocket.write(bufferedData());
        socket.pipe(upstreamSocket);
        upstreamSocket.pipe(socket);
        socket.resume();
      });
    };

    socket.on('data', onData);
    cleanupFns.push(() => socket.off('data', onData));
  };
};

module.exports = {
  createTlsRouterHandler,
  inspectTlsClientHello,
  toPassthroughSummary,
  TLS_PASSTHROUGH_MODE
};