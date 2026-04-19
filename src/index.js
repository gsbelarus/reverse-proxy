const http = require('http');
const https = require('https');
const net = require('net');

const { getRuntimeConfig } = require('./config');
const { createAcmeManager } = require('./acmeManager');
const { createAcmeChallengeStore } = require('./acmeChallengeStore');
const { createHttpRedirectHandler } = require('./httpChallenge');
const { createHostsStore } = require('./hostsConfig');
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
const hostsStore = createHostsStore({
  baseDir: process.cwd()
});

let initialHostsSnapshot;

try {
  initialHostsSnapshot = hostsStore.reload();
} catch (error) {
  logStore.append({
    timestamp: new Date().toISOString(),
    type: 'config',
    event: 'hosts_config_load_failed',
    filePath: hostsStore.getFilePath(),
    message: error.message
  });
  throw error;
}

const getHosts = () => hostsStore.getHosts();

logStore.append({
  timestamp: new Date().toISOString(),
  type: 'config',
  event: 'hosts_config_loaded',
  filePath: initialHostsSnapshot.filePath,
  hostCount: initialHostsSnapshot.hostCount,
  hosts: initialHostsSnapshot.hostnames
});

const tlsRegistry = createTlsRegistry({
  baseDir: process.cwd(),
  hosts: getHosts,
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

let listenersReady = 0;

const handleHostsReload = async (snapshot) => {
  tlsRegistry.reload();
  logStore.append({
    timestamp: new Date().toISOString(),
    type: 'config',
    event: 'hosts_config_reloaded',
    filePath: snapshot.filePath,
    hostCount: snapshot.hostCount,
    hosts: snapshot.hostnames
  });

  if (listenersReady < 2) {
    return;
  }

  try {
    await acmeManager.syncCertificates();
  } catch (error) {
    logStore.append({
      timestamp: new Date().toISOString(),
      type: 'acme',
      event: 'acme_sync_failed_after_hosts_reload',
      message: error.message
    });
  }
};

hostsStore.watch({
  onReload(snapshot) {
    void handleHostsReload(snapshot);
  },
  onError(error) {
    logStore.append({
      timestamp: new Date().toISOString(),
      type: 'config',
      event: 'hosts_config_reload_failed',
      filePath: hostsStore.getFilePath(),
      message: error.message
    });
  }
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
  hosts: getHosts,
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
        chatgptProxyTimeoutMs: config.chatgptProxyTimeoutMs ?? config.upstreamTimeoutMs,
        connectTimeoutMs: config.connectTimeoutMs
      },
      tlsPassthroughConnections: toPassthroughSummary(passthroughTracker),
      tlsCertificates: tlsRegistry.getSnapshot().certificateStates
    };
  }
});
const upgradeHandler = createUpgradeProxyHandler({
  hosts: getHosts,
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
  hosts: initialHostsSnapshot.hostnames,
  timeoutValues: {
    inboundTimeoutMs: config.inboundTimeoutMs,
    upstreamTimeoutMs: config.upstreamTimeoutMs,
    chatgptProxyTimeoutMs: config.chatgptProxyTimeoutMs ?? config.upstreamTimeoutMs,
    connectTimeoutMs: config.connectTimeoutMs
  },
  maxParallelRequests: config.maxParallelRequests,
  acmeEnabled: config.acme.enabled
});

const tlsRouter = net.createServer(
  createTlsRouterHandler({
    hosts: getHosts,
    httpsServer,
    config,
    tracker: passthroughTracker,
    logStore
  })
);

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
    passthroughHosts: Object.entries(getHosts())
      .filter(([, target]) => target.mode === 'tls-passthrough')
      .map(([host]) => host)
  });

  void maybeStartAcme();
});

const httpServer = http.createServer(
  createHttpRedirectHandler({
    challengeStore,
    hosts: getHosts,
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
    hostsStore.close();
    acmeManager.stop();
  });
}
