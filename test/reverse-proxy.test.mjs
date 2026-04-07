import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const { getRuntimeConfig, resolveHostMapping } = require('../src/config.js');
const {
  applyDownstreamTimeoutBudget,
  classifyProxyError,
  createLogStore,
  createProxyError,
  createProxyRequestHandler,
  createRequestContext,
  createRequestTracker,
  createUpgradeProxyHandler
} = require('../src/reverseProxy.js');
const { createTlsRouterHandler, inspectTlsClientHello } = require('../src/tlsRouter.js');

const TEST_TLS_KEY = fs.readFileSync(
  path.resolve(process.cwd(), 'ssl', 'gdmn.app', 'gdmn.app.key'),
  'utf8'
);
const TEST_TLS_CERT = fs.readFileSync(
  path.resolve(process.cwd(), 'ssl', 'gdmn.app', 'gdmn.app.crt'),
  'utf8'
);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const waitFor = async (predicate, timeoutMs = 1_000) => {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }

    await delay(20);
  }

  throw new Error('Timed out waiting for condition');
};

const listen = (server) =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });

const closeServer = (server) =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        if (error.code === 'ERR_SERVER_NOT_RUNNING') {
          resolve();
          return;
        }

        reject(error);
        return;
      }

      resolve();
    });
  });

const createConfig = (overrides = {}) => ({
  inboundTimeoutMs: 500,
  upstreamTimeoutMs: 150,
  connectTimeoutMs: 75,
  maxParallelRequests: 4,
  logBufferLength: 25,
  ...overrides
});

const createProxyFixture = ({ hosts, config = createConfig() }) => {
  const tracker = createRequestTracker({
    maxParallelRequests: config.maxParallelRequests
  });
  const logStore = createLogStore({ maxEntries: config.logBufferLength });
  const handler = createProxyRequestHandler({ hosts, config, tracker, logStore });
  const upgradeHandler = createUpgradeProxyHandler({
    hosts,
    config,
    tracker,
    logStore
  });
  const server = http.createServer(handler);
  server.on('upgrade', upgradeHandler);

  return {
    server,
    tracker,
    logStore
  };
};

const requestProxy = ({
  port,
  hostHeader = 'chatgpt-proxy.gdmn.app',
  method = 'GET',
  path = '/'
}) =>
  new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path,
        headers: {
          host: hostHeader
        }
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body
          });
        });
        res.on('error', reject);
      }
    );

    req.on('error', reject);
    req.end();
  });

const requestSecureProxy = ({
  port,
  hostHeader = 'chatgpt-proxy.gdmn.app',
  method = 'GET',
  path = '/'
}) =>
  new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path,
        agent: false,
        servername: hostHeader,
        rejectUnauthorized: false,
        headers: {
          connection: 'close',
          host: hostHeader
        }
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body
          });
        });
        res.on('error', reject);
      }
    );

    req.on('error', reject);
    req.end();
  });

const createTlsEdgeFixture = ({ hosts, config = createConfig() }) => {
  const tracker = createRequestTracker({
    maxParallelRequests: config.maxParallelRequests
  });
  const tunnelTracker = createRequestTracker({
    maxParallelRequests: config.maxParallelRequests
  });
  const logStore = createLogStore({ maxEntries: config.logBufferLength });
  const handler = createProxyRequestHandler({
    hosts,
    config,
    tracker,
    logStore
  });
  const upgradeHandler = createUpgradeProxyHandler({
    hosts,
    config,
    tracker,
    logStore
  });
  const httpsServer = https.createServer(
    {
      key: TEST_TLS_KEY,
      cert: TEST_TLS_CERT
    },
    handler
  );
  httpsServer.on('upgrade', upgradeHandler);

  const tlsRouter = net.createServer(
    createTlsRouterHandler({
      hosts,
      httpsServer,
      config,
      tracker: tunnelTracker,
      logStore
    })
  );

  return {
    httpsServer,
    tlsRouter,
    tracker,
    tunnelTracker,
    logStore
  };
};

test('host resolution strips www prefix and port', () => {
  const resolution = resolveHostMapping('www.chatgpt-proxy.gdmn.app:443', {
    'chatgpt-proxy.gdmn.app': { host: 'localhost', port: 3002 }
  });

  assert.equal(resolution.normalizedHost, 'chatgpt-proxy.gdmn.app');
  assert.deepEqual(resolution.target, { host: 'localhost', port: 3002 });
});

test('chatgpt-proxy defaults to a 930000 ms upstream timeout budget', () => {
  const config = getRuntimeConfig({});
  const resolution = resolveHostMapping('chatgpt-proxy.gdmn.app');
  const ctx = createRequestContext({
    req: {
      method: 'GET',
      url: '/v1/chat/completions',
      socket: { encrypted: true }
    },
    resolution,
    config,
    kind: 'http'
  });

  assert.equal(config.chatgptProxyTimeoutMs, 930_000);
  assert.equal(ctx.timeouts.upstreamTimeoutMs, 930_000);
});

test('chatgpt-proxy honors REVERSE_PROXY_CHATGPT_PROXY_TIMEOUT_MS override', () => {
  const config = getRuntimeConfig({
    REVERSE_PROXY_CHATGPT_PROXY_TIMEOUT_MS: '945000'
  });
  const resolution = resolveHostMapping('chatgpt-proxy.gdmn.app');
  const ctx = createRequestContext({
    req: {
      method: 'GET',
      url: '/v1/chat/completions',
      socket: { encrypted: true }
    },
    resolution,
    config,
    kind: 'http'
  });

  assert.equal(config.chatgptProxyTimeoutMs, 945_000);
  assert.equal(ctx.timeouts.upstreamTimeoutMs, 945_000);
});

test('chatgpt-proxy raises downstream socket timeout to the effective budget', () => {
  const config = getRuntimeConfig({});
  const resolution = resolveHostMapping('chatgpt-proxy.gdmn.app');
  const ctx = createRequestContext({
    req: {
      method: 'GET',
      url: '/v1/chat/completions',
      socket: { encrypted: true }
    },
    resolution,
    config,
    kind: 'http'
  });
  const reqTimeouts = [];
  const resTimeouts = [];

  applyDownstreamTimeoutBudget(
    {
      setTimeout(value) {
        reqTimeouts.push(value);
      }
    },
    {
      setTimeout(value) {
        resTimeouts.push(value);
      }
    },
    ctx,
    config
  );

  assert.deepEqual(reqTimeouts, [930_000]);
  assert.deepEqual(resTimeouts, [930_000]);
});

test('timeout classification distinguishes proxy timeout from unavailable upstream', () => {
  const timeoutResult = classifyProxyError(
    createProxyError('REVERSE_PROXY_TIMEOUT', 'timed out', { isUpstream: true })
  );
  const unavailableResult = classifyProxyError(
    createProxyError('ECONNREFUSED', 'refused', { isUpstream: true })
  );

  assert.equal(timeoutResult.statusCode, 504);
  assert.equal(timeoutResult.type, 'upstream_timeout');
  assert.equal(unavailableResult.statusCode, 502);
  assert.equal(unavailableResult.type, 'upstream_unavailable');
});

test('upstream timeout returns 504 and releases concurrency', async (t) => {
  const upstreamServer = http.createServer(async (_req, _res) => {
    await delay(400);
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createProxyFixture({
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        port: upstreamPort,
        protocol: 'http:'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  const response = await requestProxy({ port: proxyPort, path: '/slow' });
  const body = JSON.parse(response.body);

  assert.equal(response.statusCode, 504);
  assert.equal(body.error.type, 'upstream_timeout');
  assert.equal(fixture.tracker.snapshot().currentParallelRequests, 0);
});

test('upstream connection failure returns 502', async (t) => {
  const placeholder = http.createServer();
  const unusedPort = await listen(placeholder);
  await closeServer(placeholder);

  const fixture = createProxyFixture({
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        port: unusedPort,
        protocol: 'http:'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  const response = await requestProxy({ port: proxyPort, path: '/down' });
  const body = JSON.parse(response.body);

  assert.equal(response.statusCode, 502);
  assert.equal(body.error.type, 'upstream_unavailable');
  assert.equal(fixture.tracker.snapshot().currentParallelRequests, 0);
});

test('overload returns 503 when max parallel requests is reached', async (t) => {
  let releaseUpstream;
  const upstreamHold = new Promise((resolve) => {
    releaseUpstream = resolve;
  });

  const upstreamServer = http.createServer(async (_req, res) => {
    await upstreamHold;
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createProxyFixture({
    config: createConfig({ maxParallelRequests: 1, upstreamTimeoutMs: 500 }),
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        port: upstreamPort,
        protocol: 'http:'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  const firstRequest = requestProxy({ port: proxyPort, path: '/hold' });
  await waitFor(() => fixture.tracker.snapshot().currentParallelRequests === 1);

  const secondResponse = await requestProxy({ port: proxyPort, path: '/overflow' });
  const secondBody = JSON.parse(secondResponse.body);

  assert.equal(secondResponse.statusCode, 503);
  assert.equal(secondBody.error.type, 'overloaded');

  releaseUpstream();
  const firstResponse = await firstRequest;
  assert.equal(firstResponse.statusCode, 200);
  assert.equal(fixture.tracker.snapshot().currentParallelRequests, 0);
});

test('downstream disconnect aborts upstream work and logs cancellation', async (t) => {
  let upstreamClosed = false;
  const upstreamServer = http.createServer((_req, res) => {
    res.on('close', () => {
      upstreamClosed = true;
    });
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createProxyFixture({
    config: createConfig({ upstreamTimeoutMs: 500 }),
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        port: upstreamPort,
        protocol: 'http:'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  await new Promise((resolve) => {
    const client = net.connect({ host: '127.0.0.1', port: proxyPort }, () => {
      client.write(
        'GET /disconnect HTTP/1.1\r\nHost: chatgpt-proxy.gdmn.app\r\nConnection: close\r\n\r\n'
      );
    });

    client.on('error', () => resolve());
    client.on('close', resolve);
    setTimeout(() => {
      client.destroy();
      resolve();
    }, 25);
  });

  await waitFor(() => upstreamClosed);
  await waitFor(() => fixture.tracker.snapshot().currentParallelRequests === 0);

  const entry = fixture.logStore.snapshot(fixture.tracker.snapshot()).entries[0];
  assert.equal(entry.resultCategory, 'cancelled');
  assert.equal(entry.resultType, 'downstream_disconnect');
});

test('premature upstream close releases concurrency and records the failure', async (t) => {
  const upstreamServer = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.write('partial');
    res.socket.destroy();
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createProxyFixture({
    config: createConfig({ upstreamTimeoutMs: 500 }),
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        port: upstreamPort,
        protocol: 'http:'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  await new Promise((resolve) => {
    const client = net.connect({ host: '127.0.0.1', port: proxyPort }, () => {
      client.write(
        'GET /partial HTTP/1.1\r\nHost: chatgpt-proxy.gdmn.app\r\nConnection: close\r\n\r\n'
      );
    });

    client.on('data', () => undefined);
    client.on('error', () => resolve());
    client.on('close', resolve);
  });

  await waitFor(() => fixture.tracker.snapshot().currentParallelRequests === 0);

  const entry = fixture.logStore.snapshot(fixture.tracker.snapshot()).entries[0];
  assert.equal(entry.resultCategory, 'upstream_failure');
  assert.equal(entry.statusCode, 502);
});

test('structured logs include request ids and sanitize sensitive query params', async (t) => {
  const upstreamServer = http.createServer((_req, res) => {
    res.writeHead(204);
    res.end();
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createProxyFixture({
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        port: upstreamPort,
        protocol: 'http:'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  const response = await requestProxy({
    port: proxyPort,
    path: '/health?token=super-secret&safe=1'
  });

  assert.equal(response.statusCode, 204);

  const entry = fixture.logStore.snapshot(fixture.tracker.snapshot()).entries[0];
  assert.ok(entry.requestId);
  assert.equal(entry.path, '/health?token=%5Bredacted%5D&safe=1');
  assert.equal(entry.timeoutValues.connectTimeoutMs, 75);
  assert.equal(entry.timeoutValues.upstreamTimeoutMs, 150);
});

test('upgrade requests are proxied for mapped hosts', async (t) => {
  const upstreamServer = http.createServer();
  upstreamServer.on('upgrade', (_req, socket, _head) => {
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'
    );
    socket.end();
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createProxyFixture({
    config: createConfig({ upstreamTimeoutMs: 500 }),
    hosts: {
      'socket-server.gdmn.app': {
        host: '127.0.0.1',
        port: upstreamPort,
        protocol: 'http:'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  const rawResponse = await new Promise((resolve, reject) => {
    const client = net.connect({ host: '127.0.0.1', port: proxyPort }, () => {
      client.write(
        'GET /socket HTTP/1.1\r\nHost: socket-server.gdmn.app\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'
      );
    });

    let data = '';
    client.setEncoding('utf8');
    client.on('data', (chunk) => {
      data += chunk;
    });
    client.on('end', () => resolve(data));
    client.on('error', reject);
  });

  assert.match(rawResponse, /101 Switching Protocols/);
  await waitFor(() => fixture.tracker.snapshot().currentParallelRequests === 0);
});

test('tls client hello inspection extracts the SNI host', async (t) => {
  let capturedChunk = null;
  const captureServer = net.createServer((socket) => {
    socket.once('data', (chunk) => {
      capturedChunk = chunk;
      socket.destroy();
    });
  });
  const capturePort = await listen(captureServer);
  t.after(() => closeServer(captureServer));

  await new Promise((resolve) => {
    const client = tls.connect({
      host: '127.0.0.1',
      port: capturePort,
      servername: 'webrtc-turns.gdmn.app',
      rejectUnauthorized: false
    });

    client.on('error', resolve);
    client.on('close', resolve);
  });

  assert.ok(capturedChunk);
  const inspection = inspectTlsClientHello(capturedChunk);
  assert.equal(inspection.state, 'parsed');
  assert.equal(inspection.serverName, 'webrtc-turns.gdmn.app');
});

test('https requests still proxy through the SNI router', async (t) => {
  const upstreamServer = http.createServer((_req, res) => {
    res.writeHead(204);
    res.end();
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createTlsEdgeFixture({
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        port: upstreamPort,
        protocol: 'http:',
        mode: 'http-proxy'
      }
    }
  });

  const routerPort = await listen(fixture.tlsRouter);
  t.after(() => closeServer(fixture.tlsRouter));
  t.after(() => closeServer(fixture.httpsServer));

  const response = await requestSecureProxy({ port: routerPort, path: '/health' });

  assert.equal(response.statusCode, 204);
  assert.equal(fixture.tunnelTracker.snapshot().totalRequests, 0);
});

test('websocket upgrades still proxy through the SNI router', async (t) => {
  const upstreamServer = http.createServer();
  upstreamServer.on('upgrade', (_req, socket) => {
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'
    );
    socket.end();
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createTlsEdgeFixture({
    hosts: {
      'socket-server.gdmn.app': {
        host: '127.0.0.1',
        port: upstreamPort,
        protocol: 'http:',
        mode: 'http-proxy'
      }
    }
  });

  const routerPort = await listen(fixture.tlsRouter);
  t.after(() => closeServer(fixture.tlsRouter));
  t.after(() => closeServer(fixture.httpsServer));

  const rawResponse = await new Promise((resolve, reject) => {
    const client = tls.connect({
      host: '127.0.0.1',
      port: routerPort,
      servername: 'socket-server.gdmn.app',
      rejectUnauthorized: false
    }, () => {
      client.write(
        'GET /socket HTTP/1.1\r\nHost: socket-server.gdmn.app\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'
      );
    });

    let data = '';
    client.setEncoding('utf8');
    client.on('data', (chunk) => {
      data += chunk;
    });
    client.on('end', () => resolve(data));
    client.on('error', reject);
  });

  assert.match(rawResponse, /101 Switching Protocols/);
  assert.equal(fixture.tunnelTracker.snapshot().totalRequests, 0);
});

test('turn tls traffic is routed as raw passthrough based on SNI', async (t) => {
  const turnServer = tls.createServer(
    {
      key: TEST_TLS_KEY,
      cert: TEST_TLS_CERT
    },
    (socket) => {
      socket.end('TURN');
    }
  );
  const turnPort = await listen(turnServer);
  t.after(() => closeServer(turnServer));

  const fixture = createTlsEdgeFixture({
    config: createConfig({ upstreamTimeoutMs: 500 }),
    hosts: {
      'webrtc-turns.gdmn.app': {
        host: '127.0.0.1',
        port: turnPort,
        mode: 'tls-passthrough'
      }
    }
  });

  const routerPort = await listen(fixture.tlsRouter);
  t.after(() => closeServer(fixture.tlsRouter));
  t.after(() => closeServer(fixture.httpsServer));

  const payload = await new Promise((resolve, reject) => {
    const client = tls.connect({
      host: '127.0.0.1',
      port: routerPort,
      servername: 'webrtc-turns.gdmn.app',
      rejectUnauthorized: false
    });

    let data = '';
    client.setEncoding('utf8');
    client.on('data', (chunk) => {
      data += chunk;
    });
    client.on('end', () => resolve(data));
    client.on('error', reject);
  });

  assert.equal(payload, 'TURN');
  await waitFor(() => fixture.tunnelTracker.snapshot().currentParallelRequests === 0);

  const entry = fixture.logStore.snapshot().entries[0];
  assert.equal(entry.kind, 'tls_passthrough');
  assert.equal(entry.routeHost, 'webrtc-turns.gdmn.app');
  assert.equal(entry.resultCategory, 'completed');
});