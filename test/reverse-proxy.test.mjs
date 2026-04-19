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
const { createHostsStore, loadHostsConfig } = require('../src/hostsConfig.js');
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
  path = '/',
  headers = {}
}) =>
  new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path,
        headers: {
          ...headers,
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

const writeHostsConfigFile = (baseDir, hosts) => {
  fs.writeFileSync(path.join(baseDir, 'hosts.json'), `${JSON.stringify(hosts, null, 2)}\n`, 'utf8');
};

const CHATGPT_PROXY_HOST_MAP = {
  'chatgpt-proxy.gdmn.app': {
    host: 'localhost',
    port: 3002,
    protocol: 'http:',
    mode: 'http-proxy'
  }
};

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

test('hosts config loads external host mappings from json', (t) => {
  const tempDir = createTempDir();
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  writeHostsConfigFile(tempDir, {
    $schema: './hosts.schema.json',
    'api.example.com': {
      host: '127.0.0.1',
      port: 3001,
      protocol: 'https:'
    },
    'turn.example.com': {
      host: '127.0.0.1',
      port: 5349,
      mode: 'tls-passthrough'
    }
  });

  const hosts = loadHostsConfig({ baseDir: tempDir });

  assert.deepEqual(hosts, {
    'api.example.com': {
      host: '127.0.0.1',
      port: 3001,
      protocol: 'https:',
      mode: 'http-proxy'
    },
    'turn.example.com': {
      host: '127.0.0.1',
      port: 5349,
      mode: 'tls-passthrough'
    }
  });
});

test('hosts store keeps the last known good config during hot reload failures', async (t) => {
  const tempDir = createTempDir();
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  writeHostsConfigFile(tempDir, CHATGPT_PROXY_HOST_MAP);

  let watchHandler = null;
  const fakeWatcher = new EventEmitter();
  fakeWatcher.close = () => undefined;

  const store = createHostsStore({
    baseDir: tempDir,
    debounceMs: 0,
    watchFn: (_directoryPath, handler) => {
      watchHandler = handler;
      return fakeWatcher;
    }
  });

  t.after(() => store.close());

  store.reload();

  const reloadHostnames = [];
  const reloadErrors = [];

  store.watch({
    onReload(snapshot) {
      reloadHostnames.push(snapshot.hostnames);
    },
    onError(error) {
      reloadErrors.push(error.message);
    }
  });

  assert.ok(watchHandler);

  writeHostsConfigFile(tempDir, {
    'api.example.com': {
      host: '127.0.0.1',
      port: 3001,
      protocol: 'http:'
    }
  });
  watchHandler('change', 'hosts.json');

  await waitFor(() => reloadHostnames.length === 1);

  assert.deepEqual(reloadHostnames[0], ['api.example.com']);
  assert.deepEqual(Object.keys(store.getHosts()), ['api.example.com']);

  fs.writeFileSync(path.join(tempDir, 'hosts.json'), '{ invalid json\n', 'utf8');
  watchHandler('rename', 'hosts.json');

  await waitFor(() => reloadErrors.length === 1);

  assert.deepEqual(Object.keys(store.getHosts()), ['api.example.com']);
  assert.match(reloadErrors[0], /Failed to parse hosts config/);
});

test('host resolution strips www prefix and port', () => {
  const resolution = resolveHostMapping('www.chatgpt-proxy.gdmn.app:443', {
    'chatgpt-proxy.gdmn.app': { host: 'localhost', port: 3002 }
  });

  assert.equal(resolution.normalizedHost, 'chatgpt-proxy.gdmn.app');
  assert.deepEqual(resolution.target, { host: 'localhost', port: 3002 });
});

test('chatgpt-proxy defaults to a 930000 ms upstream timeout budget', () => {
  const config = getRuntimeConfig({});
  const resolution = resolveHostMapping('chatgpt-proxy.gdmn.app', CHATGPT_PROXY_HOST_MAP);
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
  const resolution = resolveHostMapping('chatgpt-proxy.gdmn.app', CHATGPT_PROXY_HOST_MAP);
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
  const resolution = resolveHostMapping('chatgpt-proxy.gdmn.app', CHATGPT_PROXY_HOST_MAP);
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

test('tls registry falls back to managed certificates when a manual folder is incomplete', async (t) => {
  const tempDir = createTempDir();
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  fs.mkdirSync(path.join(tempDir, 'manual-certs', 'api.example.com'), { recursive: true });
  await seedCertificateFiles({
    baseDir: tempDir,
    certificateRoot: 'managed-certs',
    domain: 'api.example.com',
    sourceDomain: 'alemaro.team'
  });

  const registry = createTlsRegistry({
    baseDir: tempDir,
    hosts: {
      'api.example.com': {
        host: '127.0.0.1',
        mode: 'http-proxy',
        port: 3001,
        protocol: 'http:'
      }
    },
    managedCertificateRoot: 'managed-certs',
    manualCertificateRoot: 'manual-certs'
  });

  registry.reload();

  assert.equal(registry.lookup('api.example.com').source, 'managed');
  assert.deepEqual(registry.getManagedHostnames(), ['api.example.com']);
  assert.equal(registry.getSnapshot().certificateStates[0].source, 'managed');
});

test('tls registry recalculates managed hostnames from a live host provider', () => {
  let currentHosts = {
    'one.example.com': {
      host: '127.0.0.1',
      port: 3001,
      protocol: 'http:',
      mode: 'http-proxy'
    }
  };

  const registry = createTlsRegistry({
    hosts: () => currentHosts
  });

  registry.reload();
  assert.deepEqual(registry.getManagedHostnames(), ['one.example.com']);

  currentHosts = {
    'two.example.com': {
      host: '127.0.0.1',
      port: 3002,
      protocol: 'http:',
      mode: 'http-proxy'
    },
    'webrtc-turns.gdmn.app': {
      host: '127.0.0.1',
      port: 5349,
      mode: 'tls-passthrough'
    }
  };

  registry.reload();
  assert.deepEqual(registry.getManagedHostnames(), ['two.example.com']);
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

test('acme manager provisions tls hosts added by the live host provider', async (t) => {
  const tempDir = createTempDir();
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  let currentHosts = {
    'existing.example.com': {
      host: '127.0.0.1',
      mode: 'http-proxy',
      port: 3001,
      protocol: 'http:'
    }
  };

  const registry = createTlsRegistry({
    baseDir: tempDir,
    hosts: () => currentHosts,
    managedCertificateRoot: 'managed-certs',
    manualCertificateRoot: 'manual-certs'
  });
  const challengeStore = createAcmeChallengeStore();
  const logStore = createLogStore({ maxEntries: 50 });
  const requestedDomains = [];
  const certificateChainPem = loadDomainCertificateFiles('gdmn.app').certChainPem;

  const manager = createAcmeManager({
    acmeModule: {
      Client: class {
        async auto() {
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

  currentHosts = {
    ...currentHosts,
    'added.example.com': {
      host: '127.0.0.1',
      mode: 'http-proxy',
      port: 3002,
      protocol: 'http:'
    }
  };

  await manager.syncCertificates();

  assert.deepEqual(requestedDomains, ['existing.example.com', 'added.example.com']);
  assert.equal(registry.lookup('added.example.com').source, 'managed');
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
  assert.equal(entry.edgeRequestId, entry.requestId);
  assert.equal(entry.clientRequestId, null);
  assert.equal(entry.upstreamRequestId, null);
  assert.equal(entry.path, '/health?token=%5Bredacted%5D&safe=1');
  assert.equal(entry.statusSource, 'upstream');
  assert.equal(entry.upstreamStatusCode, 204);
  assert.equal(entry.timeoutValues.inboundTimeoutMs, 500);
  assert.equal(entry.timeoutValues.connectTimeoutMs, 75);
  assert.equal(entry.timeoutValues.upstreamTimeoutMs, 150);
  assert.equal(entry.timeoutValues.chatgptProxyTimeoutOverrideUsed, true);
});

test('incoming client request ids are preserved separately from edge request ids', async (t) => {
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

  const clientRequestId = 'client-request-1';
  const response = await requestProxy({
    port: proxyPort,
    headers: {
      'x-request-id': clientRequestId
    }
  });

  assert.equal(response.statusCode, 204);

  const entry = fixture.logStore.snapshot(fixture.tracker.snapshot()).entries[0];
  assert.equal(entry.clientRequestId, clientRequestId);
  assert.ok(entry.edgeRequestId);
  assert.notEqual(entry.edgeRequestId, clientRequestId);
  assert.equal(entry.requestId, entry.edgeRequestId);
  assert.equal(response.headers['x-request-id'], entry.edgeRequestId);
});

test('forwarded headers include both client and edge request ids', async (t) => {
  let forwardedHeaders = null;
  const upstreamServer = http.createServer((req, res) => {
    forwardedHeaders = req.headers;
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

  const clientRequestId = 'client-request-2';
  const response = await requestProxy({
    port: proxyPort,
    headers: {
      'x-request-id': clientRequestId
    }
  });

  assert.equal(response.statusCode, 204);
  assert.ok(forwardedHeaders);
  assert.equal(forwardedHeaders['x-client-request-id'], clientRequestId);
  assert.ok(forwardedHeaders['x-request-id']);
  assert.notEqual(forwardedHeaders['x-request-id'], clientRequestId);
  assert.equal(response.headers['x-request-id'], forwardedHeaders['x-request-id']);
});

test('upstream request ids and upstream http failures are surfaced in responses and logs', async (t) => {
  const upstreamRequestId = 'upstream-request-1';
  const upstreamServer = http.createServer((_req, res) => {
    res.writeHead(502, {
      'Content-Type': 'application/json',
      'x-request-id': upstreamRequestId
    });
    res.end(JSON.stringify({ error: 'upstream bad gateway' }));
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
    path: '/upstream-failure'
  });

  assert.equal(response.statusCode, 502);
  assert.match(response.body, /upstream bad gateway/);
  assert.ok(response.headers['x-request-id']);
  assert.notEqual(response.headers['x-request-id'], upstreamRequestId);
  assert.equal(response.headers['x-upstream-request-id'], upstreamRequestId);

  const entry = fixture.logStore.snapshot(fixture.tracker.snapshot()).entries[0];
  assert.equal(entry.edgeRequestId, response.headers['x-request-id']);
  assert.equal(entry.upstreamRequestId, upstreamRequestId);
  assert.equal(entry.statusSource, 'upstream');
  assert.equal(entry.statusCode, 502);
  assert.equal(entry.proxyStatusCode, null);
  assert.equal(entry.upstreamStatusCode, 502);
  assert.equal(entry.resultCategory, 'upstream_http_error');
});

test('proxy-generated timeout logs include the effective chatgpt timeout budget', async (t) => {
  const upstreamServer = http.createServer(async (_req, _res) => {
    await delay(400);
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createProxyFixture({
    config: createConfig({
      inboundTimeoutMs: 80,
      upstreamTimeoutMs: 120,
      chatgptProxyTimeoutMs: 180,
      connectTimeoutMs: 35
    }),
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
    path: '/slow'
  });
  const body = JSON.parse(response.body);

  assert.equal(response.statusCode, 504);
  assert.equal(body.error.type, 'upstream_timeout');

  const entry = fixture.logStore.snapshot(fixture.tracker.snapshot()).entries[0];
  assert.equal(entry.routeHost, 'chatgpt-proxy.gdmn.app');
  assert.equal(entry.statusSource, 'edge');
  assert.equal(entry.statusCode, 504);
  assert.equal(entry.proxyStatusCode, 504);
  assert.equal(entry.upstreamStatusCode, null);
  assert.equal(entry.timeoutValues.connectTimeoutMs, 35);
  assert.equal(entry.timeoutValues.upstreamTimeoutMs, 180);
  assert.equal(entry.timeoutValues.inboundTimeoutMs, 80);
  assert.equal(entry.timeoutValues.chatgptProxyTimeoutOverrideUsed, true);
});

test('reverse proxy log snapshot exposes correlation and timeout fields', async (t) => {
  const upstreamRequestId = 'upstream-request-2';
  const upstreamServer = http.createServer((_req, res) => {
    res.writeHead(204, {
      'x-request-id': upstreamRequestId
    });
    res.end();
  });
  const upstreamPort = await listen(upstreamServer);
  t.after(() => closeServer(upstreamServer));

  const fixture = createProxyFixture({
    config: createConfig({
      inboundTimeoutMs: 45,
      upstreamTimeoutMs: 65,
      chatgptProxyTimeoutMs: 95,
      connectTimeoutMs: 35
    }),
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

  const clientRequestId = 'client-request-3';
  const upstreamResponse = await requestProxy({
    port: proxyPort,
    path: '/snapshot-source',
    headers: {
      'x-request-id': clientRequestId
    }
  });
  const snapshotResponse = await requestProxy({
    port: proxyPort,
    path: '/_reverse_proxy_log'
  });

  assert.equal(upstreamResponse.statusCode, 204);
  assert.equal(snapshotResponse.statusCode, 200);

  const snapshot = JSON.parse(snapshotResponse.body);
  const entry = snapshot.entries[0];

  assert.equal(snapshot.summary.timeoutValues.inboundTimeoutMs, 45);
  assert.equal(snapshot.summary.timeoutValues.upstreamTimeoutMs, 65);
  assert.equal(snapshot.summary.timeoutValues.chatgptProxyTimeoutMs, 95);
  assert.equal(snapshot.summary.timeoutValues.connectTimeoutMs, 35);
  assert.equal(entry.routeHost, 'chatgpt-proxy.gdmn.app');
  assert.equal(entry.edgeRequestId, upstreamResponse.headers['x-request-id']);
  assert.equal(entry.clientRequestId, clientRequestId);
  assert.equal(entry.upstreamRequestId, upstreamRequestId);
  assert.equal(entry.timeoutValues.connectTimeoutMs, 35);
  assert.equal(entry.timeoutValues.upstreamTimeoutMs, 95);
  assert.equal(entry.timeoutValues.inboundTimeoutMs, 45);
  assert.equal(entry.timeoutValues.chatgptProxyTimeoutOverrideUsed, true);
});

test('proxy handlers pick up host mapping changes from a live host provider without restart', async (t) => {
  const firstUpstreamServer = http.createServer((_req, res) => {
    res.writeHead(204);
    res.end();
  });
  const firstUpstreamPort = await listen(firstUpstreamServer);
  t.after(() => closeServer(firstUpstreamServer));

  const secondUpstreamServer = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('reloaded');
  });
  const secondUpstreamPort = await listen(secondUpstreamServer);
  t.after(() => closeServer(secondUpstreamServer));

  let currentHosts = {
    'chatgpt-proxy.gdmn.app': {
      host: '127.0.0.1',
      port: firstUpstreamPort,
      protocol: 'http:'
    }
  };

  const fixture = createProxyFixture({
    hosts: () => currentHosts
  });

  const proxyPort = await listen(fixture.server);
  t.after(() => closeServer(fixture.server));

  const initialResponse = await requestProxy({ port: proxyPort });
  assert.equal(initialResponse.statusCode, 204);

  currentHosts = {
    'api.example.com': {
      host: '127.0.0.1',
      port: secondUpstreamPort,
      protocol: 'http:'
    }
  };

  const removedHostResponse = await requestProxy({
    port: proxyPort,
    hostHeader: 'chatgpt-proxy.gdmn.app'
  });
  const addedHostResponse = await requestProxy({
    port: proxyPort,
    hostHeader: 'api.example.com'
  });

  assert.equal(removedHostResponse.statusCode, 404);
  assert.equal(addedHostResponse.statusCode, 200);
  assert.equal(addedHostResponse.body, 'reloaded');
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