const http = require('http');
const https = require('https');
const net = require('net');
const { createSecureContext } = require('tls');

const { HOSTS, getRuntimeConfig } = require('./config');
const { loadDomainCertificateFiles } = require('./tlsCertificates');
const {
  createLogStore,
  createProxyRequestHandler,
  createRequestTracker,
  createUpgradeProxyHandler
} = require('./reverseProxy');
const { createTlsRouterHandler, toPassthroughSummary } = require('./tlsRouter');

const config = getRuntimeConfig();
const logStore = createLogStore({ maxEntries: config.logBufferLength });
const tracker = createRequestTracker({
  maxParallelRequests: config.maxParallelRequests
});
const passthroughTracker = createRequestTracker({
  maxParallelRequests: config.maxParallelRequests
});

const getSecCtx = (domain) => {
  const { key, certChainPem, intermediates } = loadDomainCertificateFiles(domain);

  logStore.append({
    timestamp: new Date().toISOString(),
    type: 'startup',
    event: 'ssl_context_loaded',
    domain,
    certificateCount: intermediates.length
  });

  return createSecureContext({ key, cert: certChainPem });
};

const secCtx = {
  'gdmn.app': getSecCtx('gdmn.app'),
  'alemaro.team': getSecCtx('alemaro.team')
};

const sslOptions = {
  SNICallback: (servername, cb) => {
    let ctx;

    if (servername.endsWith('gdmn.app')) {
      ctx = secCtx['gdmn.app'];
    } else if (servername.endsWith('alemaro.team')) {
      ctx = secCtx['alemaro.team'];
    } else {
      logStore.append({
        timestamp: new Date().toISOString(),
        type: 'startup',
        event: 'ssl_context_missing',
        servername
      });
      cb(new Error('No matching SSL certificate'), null);
      return;
    }

    cb(null, ctx);
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
      tlsPassthroughConnections: toPassthroughSummary(passthroughTracker)
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
  maxParallelRequests: config.maxParallelRequests
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
});

const httpServer = http.createServer((req, res) => {
  const httpsUrl = `https://${req.headers.host}${req.url}`;
  res.writeHead(301, { Location: httpsUrl });
  res.end();
});

applyServerTimeouts(httpServer);

httpServer.listen(80, () => {
  logStore.append({
    timestamp: new Date().toISOString(),
    type: 'startup',
    event: 'http_redirect_server_listening',
    port: 80
  });
});
