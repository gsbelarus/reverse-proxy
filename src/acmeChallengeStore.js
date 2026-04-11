const { normalizeHost } = require('./config');

const ACME_HTTP_01_PATH_PREFIX = '/.well-known/acme-challenge/';

const getAcmeChallengeToken = (rawUrl = '/') => {
  let pathname = String(rawUrl ?? '/');

  try {
    pathname = new URL(pathname, 'http://reverse-proxy.local').pathname;
  } catch {
    pathname = pathname.split('?')[0] || '/';
  }

  if (!pathname.startsWith(ACME_HTTP_01_PATH_PREFIX)) {
    return null;
  }

  let token;

  try {
    token = decodeURIComponent(pathname.slice(ACME_HTTP_01_PATH_PREFIX.length));
  } catch {
    return null;
  }

  if (!token || token.includes('/')) {
    return null;
  }

  return token;
};

const isAcmeChallengeRequest = (rawUrl = '/') => getAcmeChallengeToken(rawUrl) !== null;

const createAcmeChallengeStore = () => {
  const entries = new Map();

  const toKey = (identifier, token) => `${normalizeHost(identifier)}:${token}`;

  return {
    set({ identifier, token, keyAuthorization }) {
      const entry = {
        identifier: normalizeHost(identifier),
        token: String(token ?? ''),
        keyAuthorization: String(keyAuthorization ?? '')
      };

      entries.set(toKey(entry.identifier, entry.token), entry);
      return entry;
    },
    remove({ identifier, token }) {
      entries.delete(toKey(identifier, token));
    },
    get({ identifier, token }) {
      return entries.get(toKey(identifier, token)) ?? null;
    },
    resolveRequest(hostHeader, rawUrl) {
      const token = getAcmeChallengeToken(rawUrl);

      if (!token) {
        return null;
      }

      return entries.get(toKey(hostHeader, token)) ?? null;
    },
    snapshot() {
      return [...entries.values()];
    }
  };
};

module.exports = {
  ACME_HTTP_01_PATH_PREFIX,
  createAcmeChallengeStore,
  getAcmeChallengeToken,
  isAcmeChallengeRequest
};