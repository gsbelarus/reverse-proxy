const https = require('https');
const express = require('express');
const cookieParser = require('cookie-parser');
//const bodyParser = require("body-parser");
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

const clearLog = () => logData.splice(0, logData.length);

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

const app = express();
app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use(cookieParser());
//app.use(bodyParser.json());

const port = 443;

const hosts = {
  'coder-ai.gdmn.app': 'http://localhost:3001',
};

const stat = {

};

app.get('/_reverse_proxy_about', (_req, res) => {
  res
    .set('Content-Type', 'text/plain')
    .send('Reverse Proxy Server');
});

app.get('/_reverse_proxy_log', (_req, res) => {
  res
    .set('Content-Type', 'text/plain')
    .send(getLog());
});

app.get('/_reverse_proxy_stat', (_req, res) => {
  res
    .set('Content-Type', 'text/plain')
    .send(JSON.stringify(stat));
});

app.all('*', async (req, res) => {
  const fullOriginalUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
  const host = req.get('host');

  if (!host) {
    log(`>>> server error: no host in request`);
    res.status(500).send('Internal Server Error');
    return;
  }

  let redirectToHost = hosts[host];

  if (!redirectToHost) {
    if (host.substring(0, 4).toLowerCase() === 'www.') {
      redirectToHost = hosts[host.substring(4)];
    }
  }

  if (redirectToHost) {
    try {
      const fullRedirectUrl = redirectToHost + req.originalUrl;

      log(`>>> ${req.method} ${fullOriginalUrl} --> ${fullRedirectUrl}`);
      log(`>>> ${JSON.stringify(req.headers, null, 2)}`);
      const response = await fetch(fullRedirectUrl, {
        method: req.method,
        headers: req.headers,
        body: (req.method === 'GET' || req.method === 'HEAD') ? undefined : JSON.stringify(req.body),
      });

      const headers = Array.from(response.headers)
        // Be careful about content-encoding header!
        .filter(([key]) => !key.includes('content-encoding'))
        .reduce((headers, [key, value]) => ({ [key]: value, ...headers }), {});

      const body = await response.text();

      res.set(headers).status(response.status).send(body);

      log(`>>> ${response.status} ${response.statusText}`);
    } catch (error) {
      log(`>>> server error: ${error}`);
      res.status(500).send('Internal Server Error');
    }
  } else {
    log(`>>> ${req.method} ${fullOriginalUrl} --> 404`);
    res.status(404).send('Server Not Found');
  }
});

const httpsServer = https.createServer({ cert, ca, key }, app);

httpsServer.listen(port, () => log(`>>> HTTPS server is running at https://localhost:${port}`));

/*
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});
*/