const fs = require('fs');
const path = require('path');

const acme = require('acme-client');

const {
  isCertificateExpiring,
  loadDomainCertificateFiles,
  splitCertificateChainPem,
  writeDomainCertificateFiles
} = require('./tlsCertificates');

const createAcmeManager = ({
  config,
  tlsRegistry,
  challengeStore,
  logStore,
  baseDir = process.cwd(),
  acmeModule = acme,
  fsModule = fs,
  setIntervalFn = setInterval,
  clearIntervalFn = clearInterval,
  now = () => Date.now()
}) => {
  const acmeConfig = config.acme ?? {};
  let accountClientPromise = null;
  let intervalId = null;
  let syncPromise = null;

  const appendLog = (entry) => {
    logStore?.append({
      timestamp: new Date().toISOString(),
      type: 'acme',
      ...entry
    });
  };

  const ensureAccountKey = async () => {
    const accountKeyPath = path.resolve(baseDir, acmeConfig.accountKeyPath);
    const fsPromises = fsModule.promises ?? fs.promises;

    try {
      return await fsPromises.readFile(accountKeyPath, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw error;
      }
    }

    const accountKey = await acmeModule.crypto.createPrivateKey();
    await fsPromises.mkdir(path.dirname(accountKeyPath), { recursive: true });
    await fsPromises.writeFile(accountKeyPath, accountKey, 'utf8');

    appendLog({
      event: 'account_key_created',
      path: acmeConfig.accountKeyPath
    });

    return Buffer.isBuffer(accountKey) ? accountKey.toString('utf8') : String(accountKey);
  };

  const getClient = async () => {
    if (!accountClientPromise) {
      accountClientPromise = (async () => {
        const accountKey = await ensureAccountKey();

        return new acmeModule.Client({
          accountKey,
          directoryUrl: acmeConfig.directoryUrl
        });
      })();
    }

    return accountClientPromise;
  };

  const loadManagedCertificate = (domain) => {
    try {
      return loadDomainCertificateFiles(domain, {
        baseDir,
        certificateRoot: acmeConfig.managedCertificateRoot
      });
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return null;
      }

      appendLog({
        event: 'managed_certificate_invalid',
        domain,
        message: error.message
      });
      return null;
    }
  };

  const ensureDomainCertificate = async (domain) => {
    if (tlsRegistry.hasManualCoverage(domain)) {
      appendLog({
        event: 'certificate_skipped_manual_override',
        domain
      });
      return false;
    }

    const existingManagedCertificate = loadManagedCertificate(domain);

    if (
      existingManagedCertificate &&
      !isCertificateExpiring(existingManagedCertificate.cert, {
        now: now(),
        withinMs: acmeConfig.renewalWindowMs
      })
    ) {
      appendLog({
        event: 'certificate_still_valid',
        domain,
        source: 'managed'
      });
      return false;
    }

    const [privateKey, csr] = await acmeModule.crypto.createCsr(
      {
        altNames: [domain],
        commonName: domain
      },
      existingManagedCertificate?.key
    );
    const client = await getClient();

    appendLog({
      event: 'certificate_order_started',
      domain,
      reason: existingManagedCertificate ? 'renewal' : 'initial'
    });

    const certificateChainPem = await client.auto({
      challengeCreateFn: async (authz, challenge, keyAuthorization) => {
        challengeStore.set({
          identifier: authz.identifier.value,
          keyAuthorization,
          token: challenge.token
        });
        appendLog({
          event: 'http_challenge_registered',
          challengeType: challenge.type,
          domain: authz.identifier.value,
          token: challenge.token
        });
      },
      challengePriority: ['http-01'],
      challengeRemoveFn: async (authz, challenge) => {
        challengeStore.remove({
          identifier: authz.identifier.value,
          token: challenge.token
        });
        appendLog({
          event: 'http_challenge_removed',
          challengeType: challenge.type,
          domain: authz.identifier.value,
          token: challenge.token
        });
      },
      csr,
      email: acmeConfig.email,
      preferredChain: acmeConfig.preferredChain || undefined,
      skipChallengeVerification: acmeConfig.skipChallengeVerification,
      termsOfServiceAgreed: acmeConfig.termsOfServiceAgreed
    });
    const certificateChain = splitCertificateChainPem(certificateChainPem);

    if (certificateChain.intermediates.length === 0) {
      throw new Error(`ACME provider returned no intermediates for ${domain}`);
    }

    await writeDomainCertificateFiles(
      domain,
      {
        caBundlePem: certificateChain.caBundlePem,
        cert: certificateChain.cert,
        key: Buffer.isBuffer(privateKey) ? privateKey.toString('utf8') : String(privateKey)
      },
      {
        baseDir,
        certificateRoot: acmeConfig.managedCertificateRoot,
        fsModule
      }
    );

    appendLog({
      event: 'certificate_stored',
      certificateCount: certificateChain.intermediates.length,
      domain,
      source: 'managed'
    });

    return true;
  };

  const syncCertificates = async () => {
    if (!acmeConfig.enabled) {
      return false;
    }

    if (syncPromise) {
      return syncPromise;
    }

    syncPromise = (async () => {
      let certificateChanged = false;

      try {
        tlsRegistry.reload();

        for (const domain of tlsRegistry.getManagedHostnames()) {
          try {
            certificateChanged = (await ensureDomainCertificate(domain)) || certificateChanged;
          } catch (error) {
            appendLog({
              event: 'certificate_order_failed',
              domain,
              message: error.message
            });
          }
        }
      } finally {
        tlsRegistry.reload();
        syncPromise = null;
      }

      return certificateChanged;
    })();

    return syncPromise;
  };

  const start = async () => {
    if (!acmeConfig.enabled) {
      appendLog({
        event: 'acme_disabled',
        reason: acmeConfig.email ? 'disabled_by_configuration' : 'missing_email'
      });
      return false;
    }

    await syncCertificates();

    if (!intervalId) {
      intervalId = setIntervalFn(() => {
        void syncCertificates();
      }, acmeConfig.renewCheckIntervalMs);
    }

    appendLog({
      event: 'acme_started',
      renewCheckIntervalMs: acmeConfig.renewCheckIntervalMs
    });

    return true;
  };

  const stop = () => {
    if (!intervalId) {
      return;
    }

    clearIntervalFn(intervalId);
    intervalId = null;
  };

  return {
    ensureDomainCertificate,
    start,
    stop,
    syncCertificates
  };
};

module.exports = {
  createAcmeManager
};