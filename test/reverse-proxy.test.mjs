import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const { createAcmeChallengeStore } = require('../src/acmeChallengeStore.js');
const { createAcmeManager } = require('../src/acmeManager.js');
const { getRuntimeConfig, resolveHostMapping } = require('../src/config.js');
const { createHttpRedirectHandler } = require('../src/httpChallenge.js');
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
const {
  buildCertificateChainPem,
  hasCompleteCertificateFiles,
  loadDomainCertificateFiles,
  parseCertificateBundle,
  writeDomainCertificateFiles
} = require('../src/tlsCertificates.js');
const { createTlsRegistry } = require('../src/tlsRegistry.js');
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

const captureTlsClientHello = (servername) =>
  new Promise(async (resolve, reject) => {
    let capturedChunk = null;
    const captureServer = net.createServer((socket) => {
      socket.once('data', (chunk) => {
        capturedChunk = chunk;
        socket.destroy();
      });
    });

    const capturePort = await listen(captureServer);

    const finish = async (error) => {
      await closeServer(captureServer);

      if (error) {
        reject(error);
        return;
      }

      resolve(capturedChunk);
    };

    const client = tls.connect({
      host: '127.0.0.1',
      port: capturePort,
      servername,
      rejectUnauthorized: false
    });

    client.on('error', () => finish());
    client.on('close', () => finish());
  });

const createMockSocket = (overrides = {}) => {
  const socket = new EventEmitter();

  return Object.assign(socket, {
    destroyed: false,
    writableEnded: false,
    remoteAddress: '127.0.0.1',
    remotePort: 0,
    pause() {
      return undefined;
    },
    resume() {
      return undefined;
    },
    setNoDelay() {
      return undefined;
    },
    setTimeout() {
      return undefined;
    },
    write() {
      return true;
    },
    unshift() {
      return undefined;
    },
    pipe(destination) {
      return destination;
    },
    destroy() {
      socket.destroyed = true;
    },
    end() {
      socket.writableEnded = true;
      socket.destroyed = true;
    }
  }, overrides);
};

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

const createTempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-'));

const seedCertificateFiles = async ({
  baseDir,
  certificateRoot,
  domain,
  sourceDomain = domain
}) => {
  const certificateFiles = loadDomainCertificateFiles(sourceDomain);

  await writeDomainCertificateFiles(
    domain,
    {
      caBundlePem: certificateFiles.intermediates.join(''),
      cert: certificateFiles.cert,
      key: certificateFiles.key
    },
    {
      baseDir,
      certificateRoot
    }
  );
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

test('certificate chain assembly concatenates PEM blocks without commas', () => {
  const leafCertificatePem =
    '-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n';
  const bundlePem =
    '-----BEGIN CERTIFICATE-----\nintermediate-1\n-----END CERTIFICATE-----\n' +
    '-----BEGIN CERTIFICATE-----\nintermediate-2\n-----END CERTIFICATE-----\n';

  const intermediates = parseCertificateBundle(bundlePem);
  const certChainPem = buildCertificateChainPem(leafCertificatePem, intermediates);

  assert.equal(intermediates.length, 2);
  assert.equal(certChainPem.includes(',-----BEGIN CERTIFICATE-----'), false);
  assert.equal(certChainPem, leafCertificatePem + intermediates.join(''));
});

test('certificate chain supports Node TLS verification for gdmn.app', async (t) => {
  const gdmnApp = loadDomainCertificateFiles('gdmn.app');

  const server = https.createServer(
    {
      key: gdmnApp.key,
      cert: gdmnApp.certChainPem
    },
    (_req, res) => {
      res.writeHead(200);
      res.end('ok');
    }
  );
  const port = await listen(server);
  t.after(() => closeServer(server));

  const requestDomain = (servername) =>
    new Promise((resolve, reject) => {
      const req = https.get(
        {
          host: '127.0.0.1',
          port,
          servername,
          path: '/',
          agent: false,
          headers: {
            host: servername
          }
        },
        (res) => {
          resolve(res.statusCode);
          res.resume();
        }
      );

      req.on('error', reject);
    });

  assert.equal(await requestDomain('chatgpt-proxy.gdmn.app'), 200);
});

test('certificate chain context can still be created for alemaro.team', () => {
  const alemaroTeam = loadDomainCertificateFiles('alemaro.team');

  assert.doesNotThrow(() => {
    tls.createSecureContext({
      key: alemaroTeam.key,
      cert: alemaroTeam.certChainPem
    });
  });
});

test('tls registry prefers manual certificate coverage over exact managed certificates', async (t) => {
  const tempDir = createTempDir();
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  await seedCertificateFiles({
    baseDir: tempDir,
    certificateRoot: 'manual-certs',
    domain: 'gdmn.app',
    sourceDomain: 'gdmn.app'
  });
  await seedCertificateFiles({
    baseDir: tempDir,
    certificateRoot: 'managed-certs',
    domain: 'chatgpt-proxy.gdmn.app',
    sourceDomain: 'alemaro.team'
  });

  const registry = createTlsRegistry({
    baseDir: tempDir,
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        mode: 'http-proxy',
        port: 3002,
        protocol: 'http:'
      },
      'new.example.com': {
        host: '127.0.0.1',
        mode: 'http-proxy',
        port: 3004,
        protocol: 'http:'
      }
    },
    managedCertificateRoot: 'managed-certs',
    manualCertificateRoot: 'manual-certs'
  });

  registry.reload();

  const certificateResolution = registry.lookup('chatgpt-proxy.gdmn.app');

  assert.equal(certificateResolution.source, 'manual');
  assert.equal(certificateResolution.certificateDomain, 'gdmn.app');
  assert.deepEqual(registry.getManagedHostnames(), ['new.example.com']);
});

test('http challenge handler serves active ACME challenges before redirecting other traffic', async (t) => {
  const challengeStore = createAcmeChallengeStore();
  const logStore = createLogStore({ maxEntries: 10 });
  const hosts = {
    'api.example.com': {
      host: '127.0.0.1',
      port: 3001,
      protocol: 'http:'
    }
  };
  challengeStore.set({
    identifier: 'api.example.com',
    keyAuthorization: 'token-1.authorized',
    token: 'token-1'
  });

  const server = http.createServer(
    createHttpRedirectHandler({
      challengeStore,
      hosts,
      logStore
    })
  );
  const port = await listen(server);
  t.after(() => closeServer(server));

  const challengeResponse = await requestProxy({
    hostHeader: 'api.example.com',
    path: '/.well-known/acme-challenge/token-1',
    port
  });
  const missingChallengeResponse = await requestProxy({
    hostHeader: 'api.example.com',
    path: '/.well-known/acme-challenge/missing',
    port
  });
  const redirectResponse = await requestProxy({
    hostHeader: 'www.api.example.com:80',
    path: '/health',
    port
  });

  assert.equal(challengeResponse.statusCode, 200);
  assert.equal(challengeResponse.body, 'token-1.authorized');
  assert.equal(missingChallengeResponse.statusCode, 404);
  assert.equal(redirectResponse.statusCode, 301);
  assert.equal(redirectResponse.headers.location, 'https://api.example.com/health');
});

test('http redirect handler rejects missing Host headers', async (t) => {
  const server = http.createServer(
    createHttpRedirectHandler({
      challengeStore: createAcmeChallengeStore(),
      hosts: {
        'api.example.com': {
          host: '127.0.0.1',
          port: 3001,
          protocol: 'http:'
        }
      },
      logStore: createLogStore({ maxEntries: 10 })
    })
  );
  const port = await listen(server);
  t.after(() => closeServer(server));

  const rawResponse = await new Promise((resolve, reject) => {
    const client = net.connect({ host: '127.0.0.1', port }, () => {
      client.write('GET /health HTTP/1.1\r\nConnection: close\r\n\r\n');
    });

    let data = '';
    client.setEncoding('utf8');
    client.on('data', (chunk) => {
      data += chunk;
    });
    client.on('end', () => resolve(data));
    client.on('error', reject);
  });

  assert.match(rawResponse, /400 Bad Request/);
  assert.doesNotMatch(rawResponse, /Location:/i);
});

test('http redirect handler rejects unknown Host headers instead of redirecting them', async (t) => {
  const server = http.createServer(
    createHttpRedirectHandler({
      challengeStore: createAcmeChallengeStore(),
      hosts: {
        'api.example.com': {
          host: '127.0.0.1',
          port: 3001,
          protocol: 'http:'
        }
      },
      logStore: createLogStore({ maxEntries: 10 })
    })
  );
  const port = await listen(server);
  t.after(() => closeServer(server));

  const response = await requestProxy({
    hostHeader: 'attacker.example.net',
    path: '/health',
    port
  });

  assert.equal(response.statusCode, 400);
  assert.equal(response.headers.location, undefined);
  assert.equal(response.body, 'Bad Request');
});

test('acme manager provisions only HTTPS hosts without manual certificate coverage', async (t) => {
  const tempDir = createTempDir();
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  await seedCertificateFiles({
    baseDir: tempDir,
    certificateRoot: 'manual-certs',
    domain: 'gdmn.app',
    sourceDomain: 'gdmn.app'
  });

  const registry = createTlsRegistry({
    baseDir: tempDir,
    hosts: {
      'chatgpt-proxy.gdmn.app': {
        host: '127.0.0.1',
        mode: 'http-proxy',
        port: 3002,
        protocol: 'http:'
      },
      'new.example.com': {
        host: '127.0.0.1',
        mode: 'http-proxy',
        port: 3004,
        protocol: 'http:'
      },
      'webrtc-turns.gdmn.app': {
        host: '127.0.0.1',
        mode: 'tls-passthrough',
        port: 5349
      }
    },
    managedCertificateRoot: 'managed-certs',
    manualCertificateRoot: 'manual-certs'
  });
  const challengeStore = createAcmeChallengeStore();
  const logStore = createLogStore({ maxEntries: 50 });
  const requestedDomains = [];
  const challengeLookups = [];
  const certificateChainPem = loadDomainCertificateFiles('gdmn.app').certChainPem;

  registry.reload();

  const manager = createAcmeManager({
    acmeModule: {
      Client: class {
        async auto(options) {
          const domain = requestedDomains[requestedDomains.length - 1];

          await options.challengeCreateFn(
            { identifier: { value: domain } },
            { token: 'token-1', type: 'http-01' },
            'token-1.authorized'
          );
          challengeLookups.push(
            challengeStore.resolveRequest(
              domain,
              '/.well-known/acme-challenge/token-1'
            )?.keyAuthorization ?? null
          );
          await options.challengeRemoveFn(
            { identifier: { value: domain } },
            { token: 'token-1', type: 'http-01' }
          );

          return certificateChainPem;
        }
      },
      crypto: {
        async createCsr({ commonName }, keyPem) {
          requestedDomains.push(commonName);
          return [Buffer.from(keyPem ?? TEST_TLS_KEY), Buffer.from(`csr:${commonName}`)];
        },
        async createPrivateKey() {
          return Buffer.from(TEST_TLS_KEY);
        }
      }
    },
    baseDir: tempDir,
    challengeStore,
    config: {
      ...createConfig(),
      acme: {
        accountKeyPath: 'acme-data/account.key',
        directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
        email: 'ops@example.com',
        enabled: true,
        managedCertificateRoot: 'managed-certs',
        preferredChain: '',
        renewCheckIntervalMs: 60_000,
        renewalWindowMs: 30 * 24 * 60 * 60 * 1000,
        skipChallengeVerification: true,
        termsOfServiceAgreed: true
      }
    },
    logStore,
    setIntervalFn: () => 1,
    clearIntervalFn: () => undefined,
    tlsRegistry: registry
  });

  await manager.syncCertificates();
  registry.reload();

  assert.deepEqual(requestedDomains, ['new.example.com']);
  assert.deepEqual(challengeLookups, ['token-1.authorized']);
  assert.equal(challengeStore.snapshot().length, 0);
  assert.equal(registry.lookup('chatgpt-proxy.gdmn.app').source, 'manual');
  assert.equal(registry.lookup('new.example.com').source, 'managed');
  assert.equal(
    hasCompleteCertificateFiles('new.example.com', {
      baseDir: tempDir,
      certificateRoot: 'managed-certs'
    }),
    true
  );
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

test('http requests reject tls-passthrough targets as unsupported', async (t) => {
  const fixture = createProxyFixture({
    hosts: {
      'webrtc-turns.gdmn.app': {
        host: '127.0.0.1',
        port: 5349,
        mode: 'tls-passthrough'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  const response = await requestProxy({
    port: proxyPort,
    hostHeader: 'webrtc-turns.gdmn.app',
    path: '/turn'
  });
  const body = JSON.parse(response.body);

  assert.equal(response.statusCode, 502);
  assert.equal(body.error.type, 'unsupported_target');
  assert.equal(body.error.code, 'REVERSE_PROXY_UNSUPPORTED_TARGET');
});

test('upgrade requests reject tls-passthrough targets as unsupported', async (t) => {
  const fixture = createProxyFixture({
    hosts: {
      'webrtc-turns.gdmn.app': {
        host: '127.0.0.1',
        port: 5349,
        mode: 'tls-passthrough'
      }
    }
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  const rawResponse = await new Promise((resolve, reject) => {
    const client = net.connect({ host: '127.0.0.1', port: proxyPort }, () => {
      client.write(
        'GET /turn HTTP/1.1\r\nHost: webrtc-turns.gdmn.app\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'
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

  assert.match(rawResponse, /502 Bad Gateway/);
  assert.match(rawResponse, /"type": "unsupported_target"/);
  assert.match(rawResponse, /"code": "REVERSE_PROXY_UNSUPPORTED_TARGET"/);
});

test('tls client hello inspection extracts the SNI host', async (t) => {
  const capturedChunk = await captureTlsClientHello('webrtc-turns.gdmn.app');

  assert.ok(capturedChunk);
  const inspection = inspectTlsClientHello(capturedChunk);
  assert.equal(inspection.state, 'parsed');
  assert.equal(inspection.serverName, 'webrtc-turns.gdmn.app');
});

test(
  'tls passthrough clears connect timer when upstream fails before connect',
  { concurrency: false },
  async (t) => {
    const originalClearTimeout = global.clearTimeout;
    const clearedTimers = [];

    global.clearTimeout = (timer) => {
      clearedTimers.push(timer);
      return originalClearTimeout(timer);
    };

    t.after(() => {
      global.clearTimeout = originalClearTimeout;
    });

    const clientHello = await captureTlsClientHello('webrtc-turns.gdmn.app');
    const config = createConfig({ connectTimeoutMs: 500, upstreamTimeoutMs: 500 });
    const tracker = createRequestTracker({
      maxParallelRequests: config.maxParallelRequests
    });
    const logStore = createLogStore({ maxEntries: config.logBufferLength });
    const upstreamSocket = createMockSocket();
    const downstreamSocket = createMockSocket({ remotePort: 12345 });
    const handler = createTlsRouterHandler({
      hosts: {
        'webrtc-turns.gdmn.app': {
          host: '127.0.0.1',
          port: 5349,
          mode: 'tls-passthrough'
        }
      },
      httpsServer: {
        emit() {
          throw new Error('Unexpected HTTPS handoff for passthrough target');
        }
      },
      config,
      tracker,
      logStore,
      socketFactory: () => upstreamSocket
    });

    handler(downstreamSocket);
    downstreamSocket.emit('data', clientHello);

    assert.equal(clearedTimers.length, 1);

    upstreamSocket.emit(
      'error',
      createProxyError('ECONNREFUSED', 'connect ECONNREFUSED 127.0.0.1:5349', {
        isUpstream: true
      })
    );

    await waitFor(() => logStore.snapshot().entries.length === 1);

    assert.equal(clearedTimers.length, 2);
    assert.equal(logStore.snapshot().entries[0].resultCategory, 'upstream_failure');
  }
);

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