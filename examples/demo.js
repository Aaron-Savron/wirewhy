'use strict';
const { createServer } = require('node:http');
const { diagnose, formatReport } = require('../src');

async function main() {
  const server = createServer((req, res) => res.end('ok'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  await new Promise(resolve => server.close(resolve));
  console.log(formatReport(await diagnose(url)));
}
main().catch(() => { console.error('Could not start the local demo server.'); process.exitCode = 1; });
