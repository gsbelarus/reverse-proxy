const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const logData = [];
const maxLogLength = 100;

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

const cert = fs.readFileSync(path.resolve(process.cwd(), 'ssl/gdmn.app.crt'));
const key = fs.readFileSync(path.resolve(process.cwd(), 'ssl/gdmn.app.key'));

const ca = fs
  .readFileSync(path.resolve(process.cwd(), 'ssl/gdmn.app.ca-bundle'), { encoding: 'utf8' })
  .split('-----END CERTIFICATE-----\r\n')
  .filter((cert) => cert.trim() !== '')
  .map((cert) => cert + '-----END CERTIFICATE-----\r\n');

if (!ca) {
  throw new Error('No CA file or file is invalid');
} else {
  log(`CA file is valid. Number of certificates: ${ca.length}...`);
}

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
};

const app = (req, res) => {
  if (req.url === '/_reverse_proxy_log' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.write(getLog());
    res.end();
  } else {
    const redirectTo = hosts[ req.headers?.host ];

    if (redirectTo) {
      log(`${req.headers.host}${req.url}`);

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
      });

      req.pipe(http_client);
    } else {
      log(`Not found: ${req.headers.host}, ${req.url}`);

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.write('Not Found');
      res.end();
    }
  }
};

https
  .createServer({ cert, ca, key }, app)
  .listen(443, () => log(`>>> HTTPS server is running at https://localhost`));

