const fs = require('fs');
const path = require('path');

const { normalizeHost } = require('./config');

const DEFAULT_HOSTS_CONFIG_PATH = 'hosts.json';
const DEFAULT_HOST_WATCH_DEBOUNCE_MS = 150;
const HTTP_PROXY_MODE = 'http-proxy';
const TLS_PASSTHROUGH_MODE = 'tls-passthrough';
const RESERVED_TOP_LEVEL_KEYS = new Set(['$schema']);
const SUPPORTED_HOST_MODES = new Set([HTTP_PROXY_MODE, TLS_PASSTHROUGH_MODE]);
const SUPPORTED_HTTP_PROTOCOLS = new Set(['http:', 'https:']);
const ALLOWED_TARGET_KEYS = new Set([
  'connectTimeoutMs',
  'host',
  'mode',
  'port',
  'protocol',
  'upstreamTimeoutMs'
]);

const toResolvedHostsConfigPath = ({
  baseDir = process.cwd(),
  hostsPath = DEFAULT_HOSTS_CONFIG_PATH
} = {}) => path.resolve(baseDir, hostsPath);

const parsePositiveInteger = (value, fieldName) => {
  const parsed = Number.parseInt(value, 10);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${fieldName} must be a positive integer`);
  }

  return parsed;
};

const validateHostName = (hostname) => {
  const normalizedHost = normalizeHost(hostname);

  if (!normalizedHost) {
    throw new Error('Host keys must not be empty');
  }

  if (normalizedHost !== hostname) {
    throw new Error(
      `Host key "${hostname}" must already be normalized as "${normalizedHost}"`
    );
  }

  return normalizedHost;
};

const normalizeHostTarget = (hostname, target) => {
  if (!target || typeof target !== 'object' || Array.isArray(target)) {
    throw new Error(`Target for ${hostname} must be an object`);
  }

  for (const key of Object.keys(target)) {
    if (!ALLOWED_TARGET_KEYS.has(key)) {
      throw new Error(`Unsupported target setting "${key}" for ${hostname}`);
    }
  }

  const host = String(target.host ?? '').trim();

  if (!host) {
    throw new Error(`Target host for ${hostname} must not be empty`);
  }

  const mode = String(target.mode ?? HTTP_PROXY_MODE).trim();

  if (!SUPPORTED_HOST_MODES.has(mode)) {
    throw new Error(`Unsupported target mode "${mode}" for ${hostname}`);
  }

  const normalizedTarget = {
    host,
    mode,
    port: parsePositiveInteger(target.port, `Target port for ${hostname}`)
  };

  if (mode === HTTP_PROXY_MODE) {
    const protocol = String(target.protocol ?? 'http:').trim();

    if (!SUPPORTED_HTTP_PROTOCOLS.has(protocol)) {
      throw new Error(`Unsupported target protocol "${protocol}" for ${hostname}`);
    }

    normalizedTarget.protocol = protocol;
  }

  if (target.connectTimeoutMs !== undefined) {
    normalizedTarget.connectTimeoutMs = parsePositiveInteger(
      target.connectTimeoutMs,
      `Target connectTimeoutMs for ${hostname}`
    );
  }

  if (target.upstreamTimeoutMs !== undefined) {
    normalizedTarget.upstreamTimeoutMs = parsePositiveInteger(
      target.upstreamTimeoutMs,
      `Target upstreamTimeoutMs for ${hostname}`
    );
  }

  return Object.freeze(normalizedTarget);
};

const createHostsSnapshot = (filePath, hosts) => ({
  filePath,
  hostCount: Object.keys(hosts).length,
  hostnames: Object.keys(hosts),
  hosts
});

const loadHostsConfig = ({
  baseDir = process.cwd(),
  hostsPath = DEFAULT_HOSTS_CONFIG_PATH,
  fsModule = fs,
  filePath = toResolvedHostsConfigPath({ baseDir, hostsPath })
} = {}) => {
  let rawHostsConfig;

  try {
    rawHostsConfig = fsModule.readFileSync(filePath, 'utf8');
  } catch (error) {
    throw new Error(`Failed to read hosts config at ${filePath}: ${error.message}`);
  }

  let parsedHostsConfig;

  try {
    parsedHostsConfig = JSON.parse(rawHostsConfig);
  } catch (error) {
    throw new Error(`Failed to parse hosts config at ${filePath}: ${error.message}`);
  }

  if (!parsedHostsConfig || typeof parsedHostsConfig !== 'object' || Array.isArray(parsedHostsConfig)) {
    throw new Error(`Hosts config at ${filePath} must be a JSON object keyed by hostname`);
  }

  const normalizedHosts = {};

  for (const [hostname, target] of Object.entries(parsedHostsConfig)) {
    if (RESERVED_TOP_LEVEL_KEYS.has(hostname)) {
      continue;
    }

    const normalizedHost = validateHostName(hostname);

    if (normalizedHosts[normalizedHost]) {
      throw new Error(`Duplicate host entry for ${normalizedHost}`);
    }

    normalizedHosts[normalizedHost] = normalizeHostTarget(normalizedHost, target);
  }

  return Object.freeze(normalizedHosts);
};

const createHostsStore = ({
  baseDir = process.cwd(),
  hostsPath = DEFAULT_HOSTS_CONFIG_PATH,
  fsModule = fs,
  watchFn = fs.watch,
  debounceMs = DEFAULT_HOST_WATCH_DEBOUNCE_MS
} = {}) => {
  const filePath = toResolvedHostsConfigPath({ baseDir, hostsPath });
  const watchedFileName = path.basename(filePath).toLowerCase();
  let hosts = Object.freeze({});
  let watcher = null;
  let reloadTimer = null;
  const reloadListeners = new Set();
  const errorListeners = new Set();

  const emitReload = (snapshot) => {
    for (const listener of reloadListeners) {
      try {
        listener(snapshot);
      } catch {
        // Listener failures should not break the watcher.
      }
    }
  };

  const emitError = (error) => {
    for (const listener of errorListeners) {
      try {
        listener(error);
      } catch {
        // Listener failures should not break the watcher.
      }
    }
  };

  const getSnapshot = () => createHostsSnapshot(filePath, hosts);

  const reload = () => {
    const nextHosts = loadHostsConfig({ filePath, fsModule });
    hosts = nextHosts;
    return getSnapshot();
  };

  const clearReloadTimer = () => {
    if (!reloadTimer) {
      return;
    }

    clearTimeout(reloadTimer);
    reloadTimer = null;
  };

  const scheduleReload = () => {
    clearReloadTimer();

    reloadTimer = setTimeout(() => {
      reloadTimer = null;

      try {
        emitReload(reload());
      } catch (error) {
        emitError(error);
      }
    }, debounceMs);

    if (typeof reloadTimer.unref === 'function') {
      reloadTimer.unref();
    }
  };

  const handleWatchError = (error) => {
    emitError(error);
  };

  const watch = ({ onReload, onError } = {}) => {
    if (typeof onReload === 'function') {
      reloadListeners.add(onReload);
    }

    if (typeof onError === 'function') {
      errorListeners.add(onError);
    }

    if (!watcher) {
      watcher = watchFn(path.dirname(filePath), (eventType, changedFileName) => {
        if (eventType !== 'change' && eventType !== 'rename') {
          return;
        }

        if (!changedFileName) {
          scheduleReload();
          return;
        }

        const normalizedFileName = String(changedFileName).toLowerCase();

        if (normalizedFileName === watchedFileName) {
          scheduleReload();
        }
      });

      if (watcher && typeof watcher.on === 'function') {
        watcher.on('error', handleWatchError);
      }
    }

    return () => {
      if (typeof onReload === 'function') {
        reloadListeners.delete(onReload);
      }

      if (typeof onError === 'function') {
        errorListeners.delete(onError);
      }
    };
  };

  const close = () => {
    clearReloadTimer();

    if (watcher) {
      if (typeof watcher.off === 'function') {
        watcher.off('error', handleWatchError);
      }

      watcher.close();
      watcher = null;
    }

    reloadListeners.clear();
    errorListeners.clear();
  };

  return {
    close,
    getFilePath() {
      return filePath;
    },
    getHosts() {
      return hosts;
    },
    getSnapshot,
    reload,
    watch
  };
};

module.exports = {
  DEFAULT_HOSTS_CONFIG_PATH,
  createHostsStore,
  loadHostsConfig
};