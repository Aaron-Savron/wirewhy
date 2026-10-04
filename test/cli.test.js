'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { resolve, join } = require('node:path');
const { server } = require('./helpers');
const cli = resolve(__dirname, '../src/cli.js');

function run(args, stdin = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', data => stdout += data);
    child.stderr.on('data', data => stderr += data);
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout, stderr }));
    child.stdin.end(stdin);
  });
}
test('CLI check produces parseable JSON and a success exit code', async t => {
  const app = await server((req, res) => res.end());
  t.after(app.close);
  const result = await run(['check', app.url, '--format', 'json']);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).request.status, 200);
});
test('CLI uses exit 1 for diagnostic failure and exit 2 for invalid input', async t => {
  const app = await server((req, res) => { res.writeHead(500); res.end(); });
  t.after(app.close);
  assert.equal((await run(['check', app.url])).code, 1);
  for (const args of [['check'], ['check', app.url, '--timeout', '-1'], ['check', app.url, '--format', 'xml'], ['run'], ['check', 'https://secret@']]) {
    const result = await run(args);
    assert.equal(result.code, 2);
    assert.ok(!result.stderr.includes('secret'));
  }
});
test('CLI explains a serialized error without echoing raw details', async () => {
  const result = await run(['explain', '--url', 'https://example.com/reset/secret', '--format', 'json'], JSON.stringify({ message: 'secret', cause: { code: 'ENOTFOUND' } }));
  assert.equal(result.code, 1);
  assert.equal(JSON.parse(result.stdout).findings[0].code, 'dns.failure');
  assert.ok(!result.stdout.includes('secret'));
  assert.equal((await run(['explain', '--url', 'https://example.com'], '{secret')).code, 2);
});
test('CLI run preloads into CommonJS and preserves application exit codes', async t => {
  const app = await server((req, res) => { res.writeHead(503); res.end(); });
  t.after(app.close);
  const script = `fetch(process.argv[1]).then(r => r.text()).then(() => { console.log('application output'); process.exitCode = 7; })`;
  const result = await run(['run', '--', process.execPath, '-e', script, app.url]);
  assert.equal(result.code, 7);
  assert.ok(result.stdout.includes('application output'));
  assert.ok(result.stderr.includes('HTTP 503'));
});
test('CLI run supports ESM and writes reports as JSONL', async t => {
  const app = await server((req, res) => { res.writeHead(401); res.end(); });
  t.after(app.close);
  const directory = mkdtempSync(join(tmpdir(), 'wirewhy-cli-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const output = join(directory, 'report.jsonl');
  const script = `await (await fetch(process.argv[1])).text();`;
  const result = await run(['run', '--output', output, '--', process.execPath, '--input-type=module', '-e', script, app.url]);
  assert.equal(result.code, 0, result.stderr);
  const lines = readFileSync(output, 'utf8').trim().split('\n');
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).findings[0].code, 'http.401');
});
test('CLI run catches failures from nested Node processes', async t => {
  const app = await server((req, res) => res.end());
  const url = app.url;
  await app.close();
  const script = `require('node:child_process').spawnSync(process.execPath, ['-e', "fetch(process.argv[1]).catch(() => {})", process.argv[1]], {stdio:'inherit'})`;
  const result = await run(['run', '--', process.execPath, '-e', script, url]);
  assert.equal(result.code, 0);
  assert.ok(result.stderr.includes('connection attempt was refused'));
});
test('CLI run reports spawn errors', async () => {
  assert.equal((await run(['run', '--', 'wirewhy-command-that-does-not-exist'])).code, 2);
});
test('CLI writes Markdown to an output file', async t => {
  const app = await server((req, res) => res.end());
  t.after(app.close);
  const directory = mkdtempSync(join(tmpdir(), 'wirewhy-markdown-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const output = join(directory, 'report.md');
  const result = await run(['check', app.url, '--format', 'markdown', '--output', output]);
  assert.equal(result.code, 0);
  assert.ok(readFileSync(output, 'utf8').startsWith('```text'));
});
