'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { resolve } = require('node:path');
const { diagnose } = require('../src');
const { server } = require('./helpers');
const exec = promisify(execFile);

test('successful HEAD request preserves the URL path and sends no GET', async t => {
  const requests = [];
  const app = await server((req, res) => { requests.push([req.method, req.url]); res.end('ok'); });
  t.after(app.close);
  const result = await diagnose(`${app.url}/private-token?token=secret`);
  assert.equal(result.outcome, 'ok');
  assert.equal(result.request.status, 200);
  assert.deepEqual(requests, [['HEAD', '/private-token?token=secret']]);
  assert.ok(!JSON.stringify(result).includes('secret'));
});
test('GET is opt-in and HTTP errors report a status', async t => {
  let method;
  const app = await server((req, res) => { method = req.method; res.writeHead(403); res.end(); });
  t.after(app.close);
  const result = await diagnose(app.url, { method: 'GET' });
  assert.equal(method, 'GET');
  assert.equal(result.findings[0].code, 'http.403');
});
test('relative redirects are followed and bounded', async t => {
  const app = await server((req, res) => {
    if (req.url === '/start') { res.writeHead(302, { location: '/end' }); res.end(); }
    else if (req.url === '/loop') { res.writeHead(302, { location: '/loop' }); res.end(); }
    else res.end();
  });
  t.after(app.close);
  assert.equal((await diagnose(`${app.url}/start`)).outcome, 'ok');
  const loop = await diagnose(`${app.url}/loop`);
  assert.ok(loop.error.codes.includes('REDIRECT_LIMIT'));
});
test('refused connection is measured, not inferred from a string', async () => {
  const app = await server((req, res) => res.end());
  const url = app.url;
  await app.close();
  const result = await diagnose(url, { timeoutMs: 1000 });
  assert.ok(result.findings.some(item => item.code === 'connection.refused'));
  assert.equal(result.checks.dns.ok, true);
  assert.equal(result.checks.ipv4.ok, false);
});
test('timeout terminates a stalled request', async t => {
  const app = await server(() => {});
  t.after(app.close);
  const result = await diagnose(app.url, { timeoutMs: 100 });
  assert.ok(result.findings.some(item => item.code === 'request.timeout'));
  assert.ok(result.checkDurationMs < 2000);
});
test('caller cancellation skips follow-up probes', async t => {
  const app = await server(() => {});
  t.after(app.close);
  const controller = new AbortController();
  controller.abort();
  const result = await diagnose(app.url, { signal: controller.signal });
  assert.equal(result.findings[0].code, 'request.aborted');
  assert.deepEqual(Object.keys(result.checks), ['nativeFetch']);
});
test('self-signed TLS server produces certificate evidence', async t => {
  const app = await server((req, res) => res.end(), true);
  t.after(app.close);
  const result = await diagnose(app.url, { compareSystemCa: false });
  assert.ok(result.findings.some(item => item.code === 'tls.validation'));
  assert.ok(result.error.codes.includes('DEPTH_ZERO_SELF_SIGNED_CERT'));
  assert.equal(result.checks.ipv4.ok, true);
});
test('system-CA comparison uses a fresh runtime and proves the trust difference', {
  skip: process.platform !== 'linux' || !process.allowedNodeEnvironmentFlags.has('--use-system-ca')
}, async t => {
  const app = await server((req, res) => res.end(), true);
  t.after(app.close);
  const script = `require('./src').diagnose(process.argv[1], {timeoutMs: 2000}).then(r => console.log(JSON.stringify(r)))`;
  const env = { ...process.env, SSL_CERT_FILE: resolve(__dirname, 'fixtures/cert.pem'), NODE_OPTIONS: '' };
  for (const name of ['NODE_EXTRA_CA_CERTS', 'NODE_USE_SYSTEM_CA', 'NODE_TLS_REJECT_UNAUTHORIZED', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) delete env[name];
  const { stdout } = await exec(process.execPath, ['-e', script, app.url], { cwd: resolve(__dirname, '..'), env });
  const result = JSON.parse(stdout);
  assert.equal(result.checks.systemCa.ok, true);
  assert.ok(result.findings.some(item => item.code === 'tls.trust-store'));
});
test('DNS failure resolves through the real resolver', async () => {
  const result = await diagnose('http://wirewhy-no-such-host.invalid', { timeoutMs: 1500 });
  assert.ok(result.findings.some(item => item.code === 'dns.failure'));
});
test('rejects unsafe methods, URL credentials, protocols, and invalid timeouts', async () => {
  await assert.rejects(diagnose('file:///tmp/private'));
  await assert.rejects(diagnose('https://user:password@example.com'));
  await assert.rejects(diagnose('https://example.com', { method: 'POST' }));
  await assert.rejects(diagnose('https://example.com', { timeoutMs: 0 }));
  await assert.rejects(diagnose('https://example.com', { timeoutMs: Infinity }));
});
