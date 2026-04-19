const DEFAULT_INBOUND_TIMEOUT_MS = 900_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 900_000;
const DEFAULT_CHATGPT_PROXY_TIMEOUT_MS = 930_000;
const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_PARALLEL_REQUESTS = 256;
const DEFAULT_LOG_BUFFER_LENGTH = 500;
const DEFAULT_ACME_RENEWAL_WINDOW_DAYS = 30;
const DEFAULT_ACME_RENEW_CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000;
const DEFAULT_ACME_MANAGED_CERTIFICATE_ROOT = 'acme-data/certificates';
const DEFAULT_ACME_ACCOUNT_KEY_PATH = 'acme-data/account.key';
const DEFAULT_ACME_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory';

const parsePositiveInteger = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const parseBoolean = (value, fallback) => {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  const normalizedValue = String(value).trim().toLowerCase();

  if (['1', 'true', 'yes', 'on'].includes(normalizedValue)) {
    return true;
  }

  if (['0', 'false', 'no', 'off'].includes(normalizedValue)) {
    return false;
  }

  return fallback;
};

const getRuntimeConfig = (env = process.env) => {
  const acmeEmail = String(env.REVERSE_PROXY_ACME_EMAIL ?? '').trim();
  const acmeEnabled = parseBoolean(env.REVERSE_PROXY_ACME_ENABLED, Boolean(acmeEmail));

  return {
    inboundTimeoutMs: parsePositiveInteger(
      env.REVERSE_PROXY_INBOUND_TIMEOUT_MS,
      DEFAULT_INBOUND_TIMEOUT_MS
    ),
    upstreamTimeoutMs: parsePositiveInteger(
      env.REVERSE_PROXY_UPSTREAM_TIMEOUT_MS,
      DEFAULT_UPSTREAM_TIMEOUT_MS
    ),
    chatgptProxyTimeoutMs: parsePositiveInteger(
      env.REVERSE_PROXY_CHATGPT_PROXY_TIMEOUT_MS,
      DEFAULT_CHATGPT_PROXY_TIMEOUT_MS
    ),
    connectTimeoutMs: parsePositiveInteger(
      env.REVERSE_PROXY_CONNECT_TIMEOUT_MS,
      DEFAULT_CONNECT_TIMEOUT_MS
    ),
    maxParallelRequests: parsePositiveInteger(
      env.REVERSE_PROXY_MAX_PARALLEL_REQUESTS,
      DEFAULT_MAX_PARALLEL_REQUESTS
    ),
    logBufferLength: parsePositiveInteger(
      env.REVERSE_PROXY_LOG_BUFFER_LENGTH,
      DEFAULT_LOG_BUFFER_LENGTH
    ),
    acme: {
      enabled: acmeEnabled && Boolean(acmeEmail),
      email: acmeEmail,
      termsOfServiceAgreed: parseBoolean(
        env.REVERSE_PROXY_ACME_TERMS_OF_SERVICE_AGREED,
        true
      ),
      directoryUrl: String(
        env.REVERSE_PROXY_ACME_DIRECTORY_URL ?? DEFAULT_ACME_DIRECTORY_URL
      ).trim(),
      renewalWindowMs:
        parsePositiveInteger(
          env.REVERSE_PROXY_ACME_RENEWAL_WINDOW_DAYS,
          DEFAULT_ACME_RENEWAL_WINDOW_DAYS
        ) *
        24 *
        60 *
        60 *
        1000,
      renewCheckIntervalMs: parsePositiveInteger(
        env.REVERSE_PROXY_ACME_RENEW_CHECK_INTERVAL_MS,
        DEFAULT_ACME_RENEW_CHECK_INTERVAL_MS
      ),
      managedCertificateRoot: String(
        env.REVERSE_PROXY_ACME_MANAGED_CERT_DIR ?? DEFAULT_ACME_MANAGED_CERTIFICATE_ROOT
      ).trim(),
      accountKeyPath: String(
        env.REVERSE_PROXY_ACME_ACCOUNT_KEY_PATH ?? DEFAULT_ACME_ACCOUNT_KEY_PATH
      ).trim(),
      preferredChain: String(env.REVERSE_PROXY_ACME_PREFERRED_CHAIN ?? '').trim(),
      skipChallengeVerification: parseBoolean(
        env.REVERSE_PROXY_ACME_SKIP_CHALLENGE_VERIFICATION,
        false
      )
    }
  };
};

const stripPort = (value) => {
  if (!value) {
    return '';
  }

  if (value.startsWith('[')) {
    const bracketIndex = value.indexOf(']');
    return bracketIndex === -1 ? value : value.slice(0, bracketIndex + 1);
  }

  const colonIndex = value.indexOf(':');
  return colonIndex === -1 ? value : value.slice(0, colonIndex);
};

const normalizeHost = (hostHeader = '') => {
  const lowerCaseHost = stripPort(String(hostHeader).trim().toLowerCase());

  if (lowerCaseHost.startsWith('www.')) {
    return lowerCaseHost.slice(4);
  }

  return lowerCaseHost;
};

const getHostMap = (hostMap = {}) => {
  if (typeof hostMap === 'function') {
    const providedHostMap = hostMap();
    return providedHostMap && typeof providedHostMap === 'object' ? providedHostMap : {};
  }

  return hostMap && typeof hostMap === 'object' ? hostMap : {};
};

const resolveHostMapping = (hostHeader, hostMap = {}) => {
  const normalizedHost = normalizeHost(hostHeader);
  const currentHostMap = getHostMap(hostMap);

  return {
    originalHost: String(hostHeader ?? ''),
    normalizedHost,
    target: currentHostMap[normalizedHost] ?? null
  };
};

module.exports = {
  getHostMap,
  getRuntimeConfig,
  normalizeHost,
  resolveHostMapping
};