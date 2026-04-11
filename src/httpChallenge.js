const { isAcmeChallengeRequest } = require('./acmeChallengeStore');

const createHttpRedirectHandler = ({ challengeStore, logStore }) => (req, res) => {
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

  const httpsUrl = `https://${req.headers.host ?? ''}${req.url ?? '/'}`;
  res.writeHead(301, { Location: httpsUrl });
  res.end();
};

module.exports = {
  createHttpRedirectHandler
};