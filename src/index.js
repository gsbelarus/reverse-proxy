const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { createSecureContext } = require('tls');

const logData = [];
const maxLogLength = 100;
let parralelRequests = 0;
let maxParallelRequests = 0;

const log = (data) => {
  if (typeof data !== 'string') {
    data = JSON.stringify(data, null, 2);
  }
  logData.push(`${new Date().toLocaleString('by')}: ${data}`);
  if (logData.length > maxLogLength) {
    logData.splice(0, logData.length - maxLogLength);
  }
  console.log(data);
};

const getLog = () => logData.reverse().join('\n\n');

const loadCert = (domain) => {
  const cert = fs.readFileSync(path.resolve(process.cwd(), path.join('ssl', domain, `${domain}.crt`)), { encoding: 'utf8' });
  const key = fs.readFileSync(path.resolve(process.cwd(), path.join('ssl', domain, `${domain}.key`)), { encoding: 'utf8' });
  const ca = fs
    .readFileSync(path.resolve(process.cwd(), path.join('ssl', domain, `${domain}.ca-bundle`)), { encoding: 'utf8' })
    .split('-----END CERTIFICATE-----\n')
    .filter((cert) => cert.trim() !== '')
    .map((cert) => cert + '-----END CERTIFICATE-----\n');

  if (!ca) {
    throw new Error('No CA file or file is invalid');
  } else {
    log(`CA file for ${domain} is valid. Number of certificates: ${ca.length}...`);
  }

  return { key, cert, ca };
};

const getSecCtx = (domain) => {
  const { key, cert, ca } = loadCert(domain);
  return createSecureContext({ key, cert: cert + ca });
};

const secCtx = {
  'gdmn.app': getSecCtx('gdmn.app'),
  'alemaro.team': getSecCtx('alemaro.team')
};

const sslOptions = {
  SNICallback: (servername, cb) => {
    let ctx;

    if (servername.endsWith('gdmn.app')) {
      ctx = secCtx[ 'gdmn.app' ];
    }
    else if (servername.endsWith('alemaro.team')) {
      ctx = secCtx[ 'alemaro.team' ];
    }
    else {
      log(`No matching SSL certificate for ${servername}`);
      cb(new Error('No matching SSL certificate'), null);
      return;
    }

    cb(null, ctx);
  }
};

const hosts = {
  'coder-ai.gdmn.app': {
    host: 'localhost',
    port: 3001
  },
  'chatgpt-proxy.gdmn.app': {
    host: 'localhost',
    port: 3002
  },
  'whisper-proxy.gdmn.app': {
    host: 'localhost',
    port: 8000
  },
  'alemaro.team': {
    host: 'localhost',
    port: 3003
  },
  'socket-server.gdmn.app': {
    host: 'localhost',
    port: 3030
  },
  'webrtc-turns.gdmn.app': {
    host: 'localhost',
    port: 5349
  },
};

const app = (req, res) => {
  if (req.url === '/_reverse_proxy_log' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.write(`Max parallel requests: ${maxParallelRequests}\n\n`);
    res.write(`Current parallel requests: ${parralelRequests}\n\n`);
    res.write(getLog());
    res.end();
  } else {
    req.setTimeout(900_000); // 15 minutes

    const redirectTo = hosts[ req.headers?.host ?? '' ];

    if (redirectTo) {
      //log(`${req.headers.host}${req.url}`);

      try {
        parralelRequests++;

        if (parralelRequests > maxParallelRequests) {
          maxParallelRequests = parralelRequests;
        }

        const http_client = http.request({
          host: redirectTo.host,
          port: redirectTo.port,
          path: req.url,
          method: req.method,
          headers: req.headers,
          body: req.body
        }, (resp) => {
          res.writeHead(resp.statusCode, resp.headers);
          resp.pipe(res);
          parralelRequests--;
        });

        req.pipe(http_client);
      }
      catch (e) {
        log(`Error: ${e.message}`);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.write('Internal Server Error');
        res.end();
      }
    } else {
      log(`Not found: ${req.headers?.host}, ${req.url}`);

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.write('Not Found');
      res.end();
    }
  }
};

const options = sslOptions; //loadCert('gdmn.app');

const httpsServer = https.createServer(options, app);

httpsServer.requestTimeout = 900_000;
httpsServer.timeout = 900_000;
httpsServer.keepAliveTimeout = 900_000;
httpsServer.headersTimeout = 950_000; // Slightly longer than request timeout

httpsServer.listen(443, () => log(`>>> HTTPS server is running at https://localhost`));


// Define the HTTP server
const httpServer = http.createServer((req, res) => {
  // Construct the HTTPS URL
  const httpsUrl = `https://${req.headers.host}${req.url}`;

  // Send a 301 Moved Permanently response with the HTTPS URL
  res.writeHead(301, { Location: httpsUrl });
  res.end();
});

httpServer.requestTimeout = 900_000;
httpServer.timeout = 900_000;
httpServer.keepAliveTimeout = 900_000;
httpServer.headersTimeout = 950_000; // Slightly longer than request timeout

httpServer.listen(80, () => log(`>>> HTTP server is listening on port 80 and redirecting all traffic to HTTPS`));  
