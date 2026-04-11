const { createSecureContext } = require('tls');

const { normalizeHost } = require('./config');
const {
  discoverCertificateDomains,
  getCertificateNotAfter,
  hasCompleteCertificateFiles,
  loadDomainCertificateFiles
} = require('./tlsCertificates');

const TLS_PASSTHROUGH_MODE = 'tls-passthrough';

const byDomainSpecificity = (left, right) => right.domain.length - left.domain.length;
const byDomainNameSpecificity = (left, right) => right.length - left.length || left.localeCompare(right);

const isTlsTerminatedTarget = (target) => (target?.mode ?? 'http-proxy') !== TLS_PASSTHROUGH_MODE;

const hostMatchesCertificateDomain = (host, certificateDomain) =>
  host === certificateDomain || host.endsWith(`.${certificateDomain}`);

const createTlsRegistry = ({
  hosts,
  baseDir = process.cwd(),
  manualCertificateRoot = 'ssl',
  managedCertificateRoot = 'acme-data/certificates',
  logStore,
  createSecureContextFn = createSecureContext
}) => {
  let state = {
    certificateStates: [],
    managedHostnames: [],
    managedEntries: new Map(),
    managedErrors: new Map(),
    manualEntries: [],
    manualErrors: new Map(),
    manualOverrideDomains: []
  };

  const appendLog = (entry) => {
    logStore?.append({
      timestamp: new Date().toISOString(),
      type: 'tls',
      ...entry
    });
  };

  const getTlsTerminatedHosts = () =>
    Object.entries(hosts)
      .filter(([, target]) => isTlsTerminatedTarget(target))
      .map(([host]) => normalizeHost(host))
      .sort((left, right) => left.localeCompare(right));

  const loadEntry = (domain, source, certificateRoot) => {
    const certificateFiles = loadDomainCertificateFiles(domain, {
      baseDir,
      certificateRoot
    });

    appendLog({
      event: 'ssl_context_loaded',
      domain,
      source,
      certificateCount: certificateFiles.intermediates.length
    });

    return {
      context: createSecureContextFn({
        key: certificateFiles.key,
        cert: certificateFiles.certChainPem
      }),
      domain,
      notAfter: getCertificateNotAfter(certificateFiles.cert),
      source
    };
  };

  const findManualEntry = (host) =>
    state.manualEntries.find((entry) => hostMatchesCertificateDomain(host, entry.domain)) ?? null;

  const findManualOverrideDomain = (host) =>
    state.manualOverrideDomains.find((domain) => hostMatchesCertificateDomain(host, domain)) ?? null;

  const findManualError = (host) => {
    const domain = findManualOverrideDomain(host);

    if (!domain) {
      return null;
    }

    const error = state.manualErrors.get(domain);
    return error ? { certificateDomain: domain, error } : null;
  };

  const reload = () => {
    const manualOverrideDomains = discoverCertificateDomains({
      baseDir,
      certificateRoot: manualCertificateRoot
    }).sort(byDomainNameSpecificity);
    const manualEntries = [];
    const manualErrors = new Map();

    for (const domain of manualOverrideDomains) {
      try {
        manualEntries.push(loadEntry(domain, 'manual', manualCertificateRoot));
      } catch (error) {
        manualErrors.set(domain, error);
        appendLog({
          event: 'ssl_context_load_failed',
          domain,
          source: 'manual',
          message: error.message
        });
      }
    }

    manualEntries.sort(byDomainSpecificity);

    const managedHostnames = getTlsTerminatedHosts().filter(
      (host) => !manualOverrideDomains.some((domain) => hostMatchesCertificateDomain(host, domain))
    );
    const managedEntries = new Map();
    const managedErrors = new Map();

    for (const host of managedHostnames) {
      if (
        !hasCompleteCertificateFiles(host, {
          baseDir,
          certificateRoot: managedCertificateRoot
        })
      ) {
        continue;
      }

      try {
        managedEntries.set(host, loadEntry(host, 'managed', managedCertificateRoot));
      } catch (error) {
        managedErrors.set(host, error);
        appendLog({
          event: 'ssl_context_load_failed',
          domain: host,
          source: 'managed',
          message: error.message
        });
      }
    }

    const certificateStates = getTlsTerminatedHosts().map((host) => {
      const manualEntry = manualEntries.find((entry) => hostMatchesCertificateDomain(host, entry.domain));

      if (manualEntry) {
        return {
          certificateDomain: manualEntry.domain,
          hasContext: true,
          host,
          notAfter: manualEntry.notAfter.toISOString(),
          source: 'manual'
        };
      }

      const manualErrorDomain = manualOverrideDomains.find((domain) =>
        hostMatchesCertificateDomain(host, domain)
      );

      if (manualErrorDomain) {
        return {
          certificateDomain: manualErrorDomain,
          hasContext: false,
          host,
          message: manualErrors.get(manualErrorDomain)?.message ?? 'Failed to load manual certificate',
          source: 'manual_invalid'
        };
      }

      const managedEntry = managedEntries.get(host);

      if (managedEntry) {
        return {
          certificateDomain: managedEntry.domain,
          hasContext: true,
          host,
          notAfter: managedEntry.notAfter.toISOString(),
          source: 'managed'
        };
      }

      if (managedErrors.has(host)) {
        return {
          certificateDomain: host,
          hasContext: false,
          host,
          message: managedErrors.get(host)?.message ?? 'Failed to load managed certificate',
          source: 'managed_invalid'
        };
      }

      return {
        certificateDomain: host,
        hasContext: false,
        host,
        source: 'missing'
      };
    });

    state = {
      certificateStates,
      managedHostnames,
      managedEntries,
      managedErrors,
      manualEntries,
      manualErrors,
      manualOverrideDomains
    };

    return state;
  };

  const lookup = (servername) => {
    const normalizedHost = normalizeHost(servername);
    const manualEntry = findManualEntry(normalizedHost);

    if (manualEntry) {
      return {
        certificateDomain: manualEntry.domain,
        context: manualEntry.context,
        notAfter: manualEntry.notAfter,
        source: 'manual'
      };
    }

    const manualError = findManualError(normalizedHost);

    if (manualError) {
      return {
        certificateDomain: manualError.certificateDomain,
        context: null,
        error: manualError.error,
        source: 'manual_invalid'
      };
    }

    const managedEntry = state.managedEntries.get(normalizedHost);

    if (managedEntry) {
      return {
        certificateDomain: managedEntry.domain,
        context: managedEntry.context,
        notAfter: managedEntry.notAfter,
        source: 'managed'
      };
    }

    const managedError = state.managedErrors.get(normalizedHost);

    if (managedError) {
      return {
        certificateDomain: normalizedHost,
        context: null,
        error: managedError,
        source: 'managed_invalid'
      };
    }

    return {
      certificateDomain: normalizedHost,
      context: null,
      source: 'missing'
    };
  };

  const getSnapshot = () => ({
    certificateStates: [...state.certificateStates],
    managedHostnames: [...state.managedHostnames],
    manualOverrideDomains: [...state.manualOverrideDomains]
  });

  return {
    getManagedHostnames() {
      return [...state.managedHostnames];
    },
    getSnapshot,
    hasManualCoverage(hostname) {
      return findManualOverrideDomain(normalizeHost(hostname)) !== null;
    },
    lookup,
    reload
  };
};

module.exports = {
  createTlsRegistry,
  hostMatchesCertificateDomain
};