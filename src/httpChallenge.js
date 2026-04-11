const { isAcmeChallengeRequest } = require('./acmeChallengeStore');
const { resolveHostMapping } = require('./config');

const BAD_REQUEST_STATUS_CODE = 400;

const toRedirectPath = (rawUrl = '/') => {
  try {
    const url = new URL(String(rawUrl ?? '/'), 'http://reverse-proxy.local');
    return `${url.pathname}${url.search}`;
  } catch {
    const value = String(rawUrl ?? '/');
    return value.startsWith('/') ? value : '/';
  }
};

const writeBadRequestResponse = (res) => {
  res.writeHead(BAD_REQUEST_STATUS_CODE, {
    'Cache-Control': 'no-store',
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end('Bad Request');
};

const createHttpRedirectHandler = ({ challengeStore, hosts, logStore }) => (req, res) => {
  const challenge = challengeStore?.resolveRequest(req.headers.host, req.url);

  if (challenge) {
    logStore?.append({
      timestamp: new Date().toISOString(),
      type: 'acme',
      event: 'http_challenge_served',
      domain: challenge.identifier,
      token: challenge.token
    });

    res.writeHead(200, {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/plain; charset=utf-8'
    });
    res.end(challenge.keyAuthorization);
    return;
  }

  if (isAcmeChallengeRequest(req.url)) {
    logStore?.append({
      timestamp: new Date().toISOString(),
      type: 'acme',
      event: 'http_challenge_missing',
      host: req.headers.host ?? '',
      path: req.url ?? '/'
    });

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
    return;
  }

  const resolution = resolveHostMapping(req.headers.host, hosts);

  if (!resolution.originalHost.trim() || !resolution.normalizedHost || !resolution.target) {
    logStore?.append({
      timestamp: new Date().toISOString(),
      type: 'http',
      event: 'http_redirect_rejected',
      host: req.headers.host ?? '',
      normalizedHost: resolution.normalizedHost,
      path: req.url ?? '/',
      reason: resolution.originalHost.trim() ? 'unknown_host' : 'missing_host'
    });

    writeBadRequestResponse(res);
    return;
  }

  const httpsUrl = `https://${resolution.normalizedHost}${toRedirectPath(req.url)}`;
  res.writeHead(301, { Location: httpsUrl });
  res.end();
};

module.exports = {
  createHttpRedirectHandler
};