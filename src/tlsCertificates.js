const fs = require('fs');
const path = require('path');

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

const loadDomainCertificateFiles = (
  domain,
  { baseDir = process.cwd(), fsModule = fs } = {}
) => {
  const cert = fsModule.readFileSync(
    path.resolve(baseDir, path.join('ssl', domain, `${domain}.crt`)),
    { encoding: 'utf8' }
  );
  const key = fsModule.readFileSync(
    path.resolve(baseDir, path.join('ssl', domain, `${domain}.key`)),
    { encoding: 'utf8' }
  );
  const caBundlePem = fsModule.readFileSync(
    path.resolve(baseDir, path.join('ssl', domain, `${domain}.ca-bundle`)),
    { encoding: 'utf8' }
  );
  const intermediates = parseCertificateBundle(caBundlePem);

  if (intermediates.length === 0) {
    throw new Error(`No CA file or CA file is invalid for ${domain}`);
  }

  return {
    cert,
    key,
    intermediates,
    certChainPem: buildCertificateChainPem(cert, intermediates)
  };
};

module.exports = {
  buildCertificateChainPem,
  loadDomainCertificateFiles,
  parseCertificateBundle
};