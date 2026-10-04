'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { inspectSite, formatSiteReport } = require('../src');
const { validateServerOptions } = require('../src/server');
const { validateConfig } = require('../src/config');
const { server } = require('./helpers');
const { setTimeout: delay } = require('node:timers/promises');
const cli = resolve(__dirname, '../src/cli.js');

function run(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', data => stdout += data);
    child.stderr.on('data', data => stderr += data);
    child.once('error', reject);
    child.once('close', code => resolve({ code, stdout, stderr }));
  });
}
test('website inspection uses GET and marks access restrictions separately from downtime', async t => {
  let method; let agent;
  const app = await server((req, res) => { method = req.method; agent = req.headers['user-agent']; res.writeHead(403); res.end(); });
  t.after(app.close);
  const report = await inspectSite(app.url);
  assert.equal(method, 'GET');
  assert.ok(agent.includes('wirewhy-'));
  assert.equal(report.availability, 'restricted');
  assert.ok(formatSiteReport(report).includes('RESTRICTED'));
  assert.deepEqual(JSON.parse(formatSiteReport(report, 'json')), report);
});
test('text output highlights the matching NGINX error without repeated access-log detail', () => {
  const report = {
    availability: 'unavailable', outcome: 'failed', url: 'https://example.com', complete: true,
    website: {request: {status: 502, durationMs: 43}, findings: [{confidence: 'confirmed', summary: 'The server returned HTTP 502.', nextSteps: ['Check the upstream service.']}]},
    server: {location: 'production', nginx: {installed: true, process: 'running', service: 'active', config: 'ok', siteMatched: true, version: 'nginx/1.30.4'}, app: null, issues: []},
    logs: [
      {kind: 'nginx-error', confidence: 'likely', correlation: 'site-request', code: 'upstream.refused', summary: 'NGINX could not connect to the upstream app.', source: '/var/log/nginx/error.log', timestamp: '2026-10-04T18:00:00.000Z', excerpt: '2026/10/04 18:00:00 [error] 1#1: *2 connect() failed (111: Connection refused) while connecting to upstream, client: 192.0.2.1, server: example.com, request: "GET /private-path HTTP/1.1", upstream: "http://127.0.0.1:3000/private-path", host: "example.com"', nextStep: 'Check the app service and its listening port.'},
      {kind: 'nginx-access', confidence: 'confirmed', correlation: 'probe', code: 'http.probe', summary: 'The diagnostic request returned HTTP 502.', source: '/var/log/nginx/access.log', timestamp: '2026-10-04T18:00:00.000Z', excerpt: 'wirewhy probe returned 502', nextStep: 'Inspect the error log.'}
    ]
  };
  const output = formatSiteReport(report);
  assert.match(output, /Matching error logs:/);
  assert.match(output, /Connection refused/);
  assert.doesNotMatch(output, /diagnostic request|client:|private-path|192\.0\.2\.1/);
});
test('origin comparison leads the next step when public HTTP fails but NGINX is healthy', () => {
  const report = {
    availability: 'unavailable', outcome: 'failed', url: 'https://example.com', complete: true,
    website: {request: {status: 502, durationMs: 43}, findings: [{confidence: 'confirmed', summary: 'The server returned HTTP 502.', nextSteps: ['Check the upstream service.']}]},
    server: {location: 'production', nginx: {installed: true, process: 'running', service: 'active', config: 'ok', siteMatched: true}, origin: {checked: true, scheme: 'https', port: 443, status: 200}, app: null, issues: []},
    logs: []
  };
  const output = formatSiteReport(report);
  assert.match(output, /Website\s+HTTP 502/);
  assert.match(output, /Origin\s+HTTP 200 from NGINX https:443 \(GET \/, TLS verified\)/);
  assert.match(output, /The origin is healthy, but the public route failed/);
  assert.match(output, /Check CDN, load balancer, and DNS routing/);
  assert.doesNotMatch(output, /Check the upstream service/);
});
test('a saved site makes the bare command check immediately without prompting', async t => {
  const app = await server((req, res) => res.end());
  t.after(app.close);
  const directory = mkdtempSync(join(tmpdir(), 'wirewhy-config-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const config = join(directory, 'config.json');
  const env = { WIREWHY_CONFIG: config };
  assert.equal((await run(['setup', app.url], env)).code, 0);
  const saved = JSON.parse(readFileSync(config, 'utf8'));
  assert.equal(saved.url, `${app.url}/`);
  const result = await run([], env);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes('UP'));
  assert.ok(result.stdout.includes('HTTP 200'));
});
test('a stalled HTTP 200 body is an unavailable response, not a healthy website', async t => {
  const app = await server((req, res) => { res.writeHead(200); res.write('partial HTML'); });
  t.after(app.close);
  const report = await inspectSite(app.url, { timeoutMs: 100 });
  assert.equal(report.availability, 'unavailable');
  assert.equal(report.website.request.status, 200);
  assert.ok(report.website.findings.some(finding => finding.code === 'request.timeout'));
  assert.ok(formatSiteReport(report).includes('response failed'));
});
test('bare command remembers the discovered service for future crash logs', { skip: process.platform === 'win32' }, async t => {
  const app = await server((req, res) => res.end());
  t.after(app.close);
  const directory = mkdtempSync(join(tmpdir(), 'wirewhy-discovery-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const raw = { nginx: { installed: true, process: 'running', service: 'active', config: 'ok', siteMatched: true }, app: { service: 'app.service', state: 'active', discovered: true }, logs: [], issues: [] };
  const writeSsh = () => writeFileSync(join(directory, 'ssh'), `#!/usr/bin/env node\nprocess.stdin.resume(); process.stdin.on('end',()=>console.log(${JSON.stringify(JSON.stringify(raw))}));\n`, { mode: 0o755 });
  writeSsh();
  const config = join(directory, 'config.json');
  const env = { WIREWHY_CONFIG: config, PATH: `${directory}:${process.env.PATH}` };
  assert.equal((await run(['setup', app.url, '--ssh', 'production'], env)).code, 0);
  const result = await run([], env);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(readFileSync(config, 'utf8')).discoveredService, 'app.service');
  raw.app.state = 'failed';
  writeSsh();
  const degraded = await run([], env);
  assert.equal(degraded.code, 1);
  assert.ok(degraded.stdout.includes('DEGRADED'));
  assert.ok(degraded.stdout.includes('HTTP 200'));
});
test('bare command without configuration explains the first step instead of hanging on stdin', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'wirewhy-empty-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const result = await run([], { WIREWHY_CONFIG: join(directory, 'missing.json') });
  assert.equal(result.code, 2);
  assert.ok(result.stderr.includes('wirewhy setup'));
});
test('server arguments cannot inject commands or SSH options', () => {
  for (const ssh of ['-oProxyCommand=bad', 'host; touch /tmp/bad', 'host$(id)', 'host\nother']) assert.throws(() => validateServerOptions({ ssh }));
  assert.throws(() => validateServerOptions({ service: 'app; reboot' }));
  assert.throws(() => validateServerOptions({ logs: ['/log\nprivate'] }));
  assert.throws(() => validateConfig({ url: 'https://example.com', ssh: 'host', local: true }));
  assert.throws(() => validateConfig({ url: 'https://example.com', sudo: true }));
  assert.throws(() => validateServerOptions({ ssh: 'host', local: true }));
  assert.throws(() => validateServerOptions({ logs: ['/app/error.log'] }));
  assert.throws(() => validateServerOptions({ local: 'yes' }));
});
test('a broken access-denied response is downtime rather than an access restriction', async t => {
  const app = await server((req, res) => { res.writeHead(403); res.write('partial page'); });
  t.after(app.close);
  assert.equal((await inspectSite(app.url, { timeoutMs: 100 })).availability, 'unavailable');
});
test('outage collection finds NGINX and application evidence, not another site', { skip: process.platform === 'win32' }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'wirewhy-server-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const bin = join(directory, 'bin'); mkdirSync(bin);
  const errorLog = join(directory, 'nginx-error.log');
  const accessLog = join(directory, 'nginx-access.log');
  const appLog = join(directory, 'app.log');
  writeFileSync(errorLog, ''); writeFileSync(accessLog, '');
  writeFileSync(appLog, `${new Date().toISOString()} TypeError: database unavailable\n    at route (/app/server.js:42:5)\n`);
  const app = await server((req, res) => {
    const date = new Date().toISOString().slice(0, 19).replaceAll('-', '/').replace('T', ' ');
    writeFileSync(errorLog, `${date} [error] 1#1: *1 connect() failed (111: Connection refused) while connecting to upstream, server: unrelated.test, request: "GET / HTTP/1.1", host: "unrelated.test"\n${date} [error] 1#1: *2 connect() failed (111: Connection refused) while connecting to upstream, server: 127.0.0.1, request: "GET / HTTP/1.1", upstream: "http://127.0.0.1:3000/private-secret", host: "127.0.0.1"\n`);
    res.writeHead(502); res.end('Bad gateway');
  });
  t.after(app.close);
  const config = `error_log ${errorLog}; http { access_log ${accessLog}; server { server_name 127.0.0.1; location / { proxy_pass http://127.0.0.1:3000; } } }`;
  const responses = {
    nginx: { '-v': { stderr: 'nginx version: nginx/1.30.4' }, '-V': { stderr: '--prefix=/usr/share/nginx' }, '-T': { stdout: config } },
    systemctl: { 'is-active': { stdout: 'active\n' } },
    journalctl: { '*': { stdout: '' } }
  };
  for (const [name, variants] of Object.entries(responses)) {
    const file = join(bin, name);
    writeFileSync(file, `#!/usr/bin/env node\nconst variants=${JSON.stringify(variants)}; const r=variants[process.argv[2]]||variants['*']; if(r?.stdout)process.stdout.write(r.stdout); if(r?.stderr)process.stderr.write(r.stderr); process.exit(r?.code||0);\n`, { mode: 0o755 });
  }
  const env = { PATH: `${bin}:${process.env.PATH}`, WIREWHY_CONFIG: join(directory, 'none.json'), TZ: 'UTC' };
  const result = await run(['site', app.url, '--local', '--service', 'app.service', '--log', appLog, '--format', 'json'], env);
  assert.equal(result.code, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.availability, 'unavailable');
  assert.equal(report.server.nginx.config, 'ok');
  assert.equal(report.server.app.service, 'app.service');
  assert.equal(report.logs[0].code, 'upstream.refused');
  assert.ok(report.logs.some(log => log.code === 'app.exception'));
  assert.ok(!result.stdout.includes('unrelated.test'));
  assert.ok(!result.stdout.includes('private-secret'));
});
test('real isolated NGINX outage exposes its actual upstream error log', { skip: !process.env.WIREWHY_NGINX_BINARY, timeout: 20000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'wirewhy-real-nginx-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const allocation = await server((req, res) => res.end());
  const url = allocation.url;
  const port = allocation.app.address().port;
  await allocation.close();
  const upstream = await server((req, res) => res.end());
  const deadPort = upstream.app.address().port;
  await upstream.close();
  const errorLog = join(directory, 'error.log');
  const configPath = join(directory, 'nginx.conf');
  writeFileSync(configPath, `pid ${directory}/nginx.pid; error_log ${errorLog} error; worker_processes 1; events { worker_connections 32; } http { client_body_temp_path ${directory}/body; proxy_temp_path ${directory}/proxy; fastcgi_temp_path ${directory}/fastcgi; uwsgi_temp_path ${directory}/uwsgi; scgi_temp_path ${directory}/scgi; access_log ${directory}/access.log; server { listen 127.0.0.1:${port}; server_name 127.0.0.1; location / { proxy_pass http://127.0.0.1:${deadPort}; } } }`);
  const child = spawn(process.env.WIREWHY_NGINX_BINARY, ['-c', configPath, '-e', 'stderr', '-g', 'daemon off;'], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', data => stderr += data);
  t.after(async () => { if (child.exitCode === null) { child.kill('SIGTERM'); await new Promise(resolve => child.once('close', resolve)); } });
  let ready = false;
  for (let i = 0; i < 30 && !ready; i++) {
    try { await (await fetch(url)).text(); ready = true; } catch { await delay(50); }
  }
  assert.ok(ready, stderr);
  const bin = join(directory, 'bin'); mkdirSync(bin);
  writeFileSync(join(bin, 'nginx'), `#!/usr/bin/env node\nconst r=require('node:child_process').spawnSync(process.env.WIREWHY_NGINX_BINARY,process.argv.slice(2),{stdio:'inherit'}); process.exit(r.status||0);\n`, { mode: 0o755 });
  const result = await run(['site', url, '--local', '--nginx-config', configPath, '--format', 'json'], { PATH: `${bin}:${process.env.PATH}`, WIREWHY_CONFIG: join(directory, 'none.json') });
  assert.equal(result.code, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.website.request.status, 502);
  assert.equal(report.server.nginx.config, 'ok');
  const matched = report.logs.find(log => log.code === 'upstream.refused');
  assert.ok(matched, JSON.stringify(report));
  assert.equal(matched.source, errorLog);
  assert.ok(matched.excerpt.includes('connect() failed'));
  assert.ok(readFileSync(errorLog, 'utf8').includes('Connection refused'));
});

test('origin check separates a failing public route from a healthy real NGINX origin', { skip: !process.env.WIREWHY_NGINX_BINARY, timeout: 20000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'wirewhy-origin-nginx-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const reserve = await server((req, res) => res.end());
  const originPort = reserve.app.address().port;
  await reserve.close();
  const publicRoute = await server((req, res) => { res.writeHead(502); res.end('Bad gateway'); });
  t.after(publicRoute.close);
  const upstream = await server((req, res) => res.end('healthy origin'));
  t.after(upstream.close);
  const upstreamPort = upstream.app.address().port;
  const configPath = join(directory, 'nginx.conf');
  writeFileSync(configPath, `pid ${directory}/nginx.pid; error_log ${directory}/error.log; worker_processes 1; events { worker_connections 32; } http { client_body_temp_path ${directory}/body; proxy_temp_path ${directory}/proxy; fastcgi_temp_path ${directory}/fastcgi; uwsgi_temp_path ${directory}/uwsgi; scgi_temp_path ${directory}/scgi; access_log ${directory}/access.log; server { listen 127.0.0.1:${originPort}; server_name 127.0.0.1; location / { proxy_pass http://127.0.0.1:${upstreamPort}; } } }`);
  const child = spawn(process.env.WIREWHY_NGINX_BINARY, ['-c', configPath, '-e', 'stderr', '-g', 'daemon off;'], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', data => stderr += data);
  t.after(async () => { if (child.exitCode === null) { child.kill('SIGTERM'); await new Promise(resolve => child.once('close', resolve)); } });
  let ready = false;
  for (let i = 0; i < 30 && !ready; i++) {
    try { ready = (await (await fetch(`http://127.0.0.1:${originPort}`)).text()) === 'healthy origin'; } catch { await delay(50); }
  }
  assert.ok(ready, stderr);
  const bin = join(directory, 'bin'); mkdirSync(bin);
  writeFileSync(join(bin, 'nginx'), `#!/usr/bin/env node\nconst r=require('node:child_process').spawnSync(process.env.WIREWHY_NGINX_BINARY,process.argv.slice(2),{stdio:'inherit'}); process.exit(r.status||0);\n`, { mode: 0o755 });
  const url = new URL(publicRoute.url);
  const env = { PATH: `${bin}:${process.env.PATH}`, WIREWHY_CONFIG: join(directory, 'none.json'), WIREWHY_NGINX_BINARY: process.env.WIREWHY_NGINX_BINARY };
  const result = await run(['site', url.href, '--local', '--nginx-config', configPath], env);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stdout, /Website\s+HTTP 502/);
  assert.match(result.stdout, /Origin\s+HTTP 200/);
  assert.match(result.stdout, /The origin is healthy, but the public route failed/);
  assert.match(result.stdout, /Check CDN, load balancer, and DNS routing/);
});
