const http = require('http');
const https = require('https');
const net = require('net');

const { HOSTS, getRuntimeConfig } = require('./config');
const { createAcmeManager } = require('./acmeManager');
const { createAcmeChallengeStore } = require('./acmeChallengeStore');
const { createHttpRedirectHandler } = require('./httpChallenge');
const {
  createLogStore,
  createProxyRequestHandler,
  createRequestTracker,
  createUpgradeProxyHandler
} = require('./reverseProxy');
const { createTlsRegistry } = require('./tlsRegistry');
const { createTlsRouterHandler, toPassthroughSummary } = require('./tlsRouter');

const config = getRuntimeConfig();
const logStore = createLogStore({ maxEntries: config.logBufferLength });
const tracker = createRequestTracker({
  maxParallelRequests: config.maxParallelRequests
});
const passthroughTracker = createRequestTracker({
  maxParallelRequests: config.maxParallelRequests
});
const challengeStore = createAcmeChallengeStore();
const tlsRegistry = createTlsRegistry({
  baseDir: process.cwd(),
  hosts: HOSTS,
  logStore,
  managedCertificateRoot: config.acme.managedCertificateRoot,
  manualCertificateRoot: 'ssl'
});

tlsRegistry.reload();

const acmeManager = createAcmeManager({
  baseDir: process.cwd(),
  challengeStore,
  config,
  logStore,
  tlsRegistry
});

const sslOptions = {
  SNICallback: (servername, cb) => {
    const certificateResolution = tlsRegistry.lookup(servername);

    if (!certificateResolution.context) {
      logStore.append({
        timestamp: new Date().toISOString(),
        type: 'tls',
        event: 'ssl_context_missing',
        certificateDomain: certificateResolution.certificateDomain,
        message: certificateResolution.error?.message ?? null,
        servername,
        source: certificateResolution.source
      });
      cb(new Error('No matching SSL certificate'), null);
      return;
    }

    cb(null, certificateResolution.context);
  }
};

const app = createProxyRequestHandler({
  hosts: HOSTS,
  config,
  tracker,
  logStore,
  getLogSummary: () => {
    const httpStats = tracker.snapshot();

    return {
      ...httpStats,
      timeoutValues: {
        inboundTimeoutMs: config.inboundTimeoutMs,
        upstreamTimeoutMs: config.upstreamTimeoutMs,
        connectTimeoutMs: config.connectTimeoutMs
      },
      tlsPassthroughConnections: toPassthroughSummary(passthroughTracker),
      tlsCertificates: tlsRegistry.getSnapshot().certificateStates
    };
  }
});
const upgradeHandler = createUpgradeProxyHandler({
  hosts: HOSTS,
  config,
  tracker,
  logStore
});

const applyServerTimeouts = (server) => {
  server.requestTimeout = config.inboundTimeoutMs;
  server.timeout = config.inboundTimeoutMs;
  server.keepAliveTimeout = config.inboundTimeoutMs;
  server.headersTimeout = config.inboundTimeoutMs + 5_000;
};

const httpsServer = https.createServer(sslOptions, app);
httpsServer.on('upgrade', upgradeHandler);
applyServerTimeouts(httpsServer);

httpsServer.on('tlsClientError', (error, tlsSocket) => {
  logStore.append({
    timestamp: new Date().toISOString(),
    type: 'tls',
    event: 'tls_client_error',
    message: error.message,
    remoteAddress: tlsSocket?.remoteAddress ?? null
  });
});

logStore.append({
  timestamp: new Date().toISOString(),
  type: 'startup',
  event: 'https_handler_ready',
  hosts: Object.keys(HOSTS),
  timeoutValues: {
    inboundTimeoutMs: config.inboundTimeoutMs,
    upstreamTimeoutMs: config.upstreamTimeoutMs,
    connectTimeoutMs: config.connectTimeoutMs
  },
  maxParallelRequests: config.maxParallelRequests,
  acmeEnabled: config.acme.enabled
});

const tlsRouter = net.createServer(
  createTlsRouterHandler({
    hosts: HOSTS,
    httpsServer,
    config,
    tracker: passthroughTracker,
    logStore
  })
);

let listenersReady = 0;
const maybeStartAcme = async () => {
  listenersReady += 1;

  if (listenersReady < 2) {
    return;
  }

  try {
    await acmeManager.start();
  } catch (error) {
    logStore.append({
      timestamp: new Date().toISOString(),
      type: 'acme',
      event: 'acme_start_failed',
      message: error.message
    });
  }
};

tlsRouter.listen(443, () => {
  logStore.append({
    timestamp: new Date().toISOString(),
    type: 'startup',
    event: 'tls_router_listening',
    port: 443,
    passthroughHosts: Object.entries(HOSTS)
      .filter(([, target]) => target.mode === 'tls-passthrough')
      .map(([host]) => host)
  });

  void maybeStartAcme();
});

const httpServer = http.createServer(
  createHttpRedirectHandler({
    challengeStore,
    hosts: HOSTS,
    logStore
  })
);

applyServerTimeouts(httpServer);

httpServer.listen(80, () => {
  logStore.append({
    timestamp: new Date().toISOString(),
    type: 'startup',
    event: 'http_redirect_server_listening',
    port: 80
  });

  void maybeStartAcme();
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    acmeManager.stop();
  });
}
