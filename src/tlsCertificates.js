const fs = require('fs');
const path = require('path');
const { X509Certificate } = require('crypto');

const CERTIFICATE_BLOCK_PATTERN =
  /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\r?\n*/g;

const ensureTrailingNewline = (pem) => {
  const value = String(pem ?? '');
  return value.endsWith('\n') ? value : `${value}\n`;
};

const parseCertificateBundle = (bundlePem) =>
  (String(bundlePem ?? '').match(CERTIFICATE_BLOCK_PATTERN) ?? []).map(ensureTrailingNewline);

const buildCertificateChainPem = (leafCertificatePem, intermediateCertificates = []) =>
  [
    ensureTrailingNewline(leafCertificatePem),
    ...intermediateCertificates.map(ensureTrailingNewline)
  ].join('');

const getCertificateFilePaths = (
  domain,
  { baseDir = process.cwd(), certificateRoot = 'ssl' } = {}
) => {
  const domainDir = path.resolve(baseDir, path.join(certificateRoot, domain));

  return {
    domainDir,
    certPath: path.join(domainDir, `${domain}.crt`),
    keyPath: path.join(domainDir, `${domain}.key`),
    caBundlePath: path.join(domainDir, `${domain}.ca-bundle`)
  };
};

const hasCompleteCertificateFiles = (
  domain,
  { baseDir = process.cwd(), fsModule = fs, certificateRoot = 'ssl' } = {}
) => {
  const { certPath, keyPath, caBundlePath } = getCertificateFilePaths(domain, {
    baseDir,
    certificateRoot
  });

  return [certPath, keyPath, caBundlePath].every((filePath) => fsModule.existsSync(filePath));
};

const discoverCertificateDomains = (
  { baseDir = process.cwd(), fsModule = fs, certificateRoot = 'ssl' } = {}
) => {
  const rootPath = path.resolve(baseDir, certificateRoot);

  if (!fsModule.existsSync(rootPath)) {
    return [];
  }

  return fsModule
    .readdirSync(rootPath, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((domain) =>
      hasCompleteCertificateFiles(domain, {
        baseDir,
        fsModule,
        certificateRoot
      })
    )
    .sort((left, right) => left.localeCompare(right));
};

const splitCertificateChainPem = (chainPem) => {
  const certificates = parseCertificateBundle(chainPem);

  if (certificates.length === 0) {
    throw new Error('Certificate chain is empty');
  }

  const [cert, ...intermediates] = certificates;

  return {
    cert,
    intermediates,
    caBundlePem: intermediates.join(''),
    certChainPem: certificates.join('')
  };
};

const getCertificateNotAfter = (leafCertificatePem) =>
  new Date(new X509Certificate(ensureTrailingNewline(leafCertificatePem)).validTo);

const isCertificateExpiring = (
  leafCertificatePem,
  { withinMs = 0, now = Date.now() } = {}
) => getCertificateNotAfter(leafCertificatePem).getTime() <= Number(now) + withinMs;

const loadDomainCertificateFiles = (
  domain,
  { baseDir = process.cwd(), fsModule = fs, certificateRoot = 'ssl' } = {}
) => {
  const { certPath, keyPath, caBundlePath } = getCertificateFilePaths(domain, {
    baseDir,
    certificateRoot
  });
  const cert = fsModule.readFileSync(certPath, { encoding: 'utf8' });
  const key = fsModule.readFileSync(keyPath, { encoding: 'utf8' });
  const caBundlePem = fsModule.readFileSync(caBundlePath, { encoding: 'utf8' });
  const { intermediates, certChainPem } = splitCertificateChainPem(
    buildCertificateChainPem(cert, parseCertificateBundle(caBundlePem))
  );

  if (intermediates.length === 0) {
    throw new Error(`No CA file or CA file is invalid for ${domain}`);
  }

  return {
    cert,
    key,
    intermediates,
    certChainPem
  };
};

const tryLoadDomainCertificateFiles = (domain, options = {}) => {
  try {
    return loadDomainCertificateFiles(domain, options);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return null;
    }

    throw error;
  }
};

const replaceFile = async (fsPromises, tempPath, targetPath) => {
  try {
    await fsPromises.rename(tempPath, targetPath);
  } catch (error) {
    if (!['EEXIST', 'EPERM'].includes(error?.code)) {
      throw error;
    }

    await fsPromises.rm(targetPath, { force: true });
    await fsPromises.rename(tempPath, targetPath);
  }
};

const writeDomainCertificateFiles = async (
  domain,
  { cert, key, caBundlePem },
  { baseDir = process.cwd(), fsModule = fs, certificateRoot = 'ssl' } = {}
) => {
  const { domainDir, certPath, keyPath, caBundlePath } = getCertificateFilePaths(domain, {
    baseDir,
    certificateRoot
  });
  const fsPromises = fsModule.promises ?? fs.promises;
  const tempSuffix = `${process.pid}.${Date.now()}.tmp`;
  const tempCertPath = `${certPath}.${tempSuffix}`;
  const tempKeyPath = `${keyPath}.${tempSuffix}`;
  const tempCaBundlePath = `${caBundlePath}.${tempSuffix}`;

  await fsPromises.mkdir(domainDir, { recursive: true });

  try {
    await Promise.all([
      fsPromises.writeFile(tempCertPath, ensureTrailingNewline(cert), 'utf8'),
      fsPromises.writeFile(tempKeyPath, ensureTrailingNewline(key), 'utf8'),
      fsPromises.writeFile(tempCaBundlePath, ensureTrailingNewline(caBundlePem), 'utf8')
    ]);
    await replaceFile(fsPromises, tempCertPath, certPath);
    await replaceFile(fsPromises, tempKeyPath, keyPath);
    await replaceFile(fsPromises, tempCaBundlePath, caBundlePath);
  } finally {
    await Promise.all(
      [tempCertPath, tempKeyPath, tempCaBundlePath].map((filePath) =>
        fsPromises.rm(filePath, { force: true }).catch(() => undefined)
      )
    );
  }
};

module.exports = {
  buildCertificateChainPem,
  discoverCertificateDomains,
  getCertificateFilePaths,
  getCertificateNotAfter,
  hasCompleteCertificateFiles,
  isCertificateExpiring,
  loadDomainCertificateFiles,
  parseCertificateBundle,
  splitCertificateChainPem,
  tryLoadDomainCertificateFiles,
  writeDomainCertificateFiles
};