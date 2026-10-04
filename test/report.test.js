'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { explain, formatReport } = require('../src');
const { runtimeInfo, bypassesProxy } = require('../src/runtime');

const clean = runtimeInfo('https://example.com', {});
function report(code, extra = {}) { return explain({ cause: { code } }, { url: 'https://example.com', runtime: clean, ...extra }); }
for (const [code, finding] of [
  ['ENOTFOUND', 'dns.failure'], ['EAI_AGAIN', 'dns.failure'], ['ECONNREFUSED', 'connection.refused'],
  ['ECONNRESET', 'connection.closed'], ['EPIPE', 'connection.closed'], ['UND_ERR_SOCKET', 'connection.closed'],
  ['ETIMEDOUT', 'request.timeout'], ['UND_ERR_HEADERS_TIMEOUT', 'request.timeout'],
  ['CERT_HAS_EXPIRED', 'tls.validation'], ['ERR_TLS_CERT_ALTNAME_INVALID', 'tls.validation'],
  ['UND_ERR_INVALID_ARG', 'client.configuration']
]) test(`classifies ${code}`, () => assert.ok(report(code).findings.some(item => item.code === finding)));

test('handles cyclic causes and AggregateError children', () => {
  const error = new AggregateError([Object.assign(new Error(), { code: 'ECONNREFUSED' }), { cause: { code: 'ENETUNREACH' } }]);
  error.cause = error;
  assert.deepEqual(explain(error).error.codes, ['ECONNREFUSED', 'ENETUNREACH']);
});
test('recognizes abort and timeout names', () => {
  assert.equal(explain({ name: 'AbortError' }).findings[0].code, 'request.aborted');
  assert.equal(explain({ name: 'TimeoutError' }).findings[0].code, 'request.timeout');
});
test('unknown failures do not fabricate a cause', () => {
  assert.equal(explain(new Error('private detail')).findings[0].confidence, 'unknown');
});
test('reports remove credentials, paths, queries, messages, and stacks', () => {
  const error = { code: 'ENOTFOUND', message: 'private-token', stack: 'private-token', cause: { code: 'secret-token' } };
  const result = explain(error, { url: 'https://user:private-token@example.com/reset/private-token?key=private-token', method: 'private-token', runtime: clean });
  for (const format of ['json', 'text', 'markdown']) {
    const output = formatReport(result, format);
    assert.ok(!output.includes('private-token'));
    assert.ok(!output.includes('secret-token'));
  }
  assert.equal(result.request.url, 'https://example.com');
});
test('confirmed trust-store finding requires a successful comparison', () => {
  const result = report('UNABLE_TO_GET_ISSUER_CERT_LOCALLY', { checks: { defaultTls: { ok: false, codes: ['UNABLE_TO_GET_ISSUER_CERT_LOCALLY'] }, systemCa: { ok: true } } });
  assert.equal(result.findings[0].code, 'tls.trust-store');
  assert.equal(result.findings[0].confidence, 'confirmed');
  assert.equal(report('UNABLE_TO_GET_ISSUER_CERT_LOCALLY').findings[0].code, 'tls.validation');
  assert.equal(report('UNABLE_TO_GET_ISSUER_CERT_LOCALLY', { checks: { systemCa: { ok: true } } }).findings[0].code, 'tls.validation');
});
test('IPv6 finding stays likely and requires both measurements', () => {
  const result = report('ECONNREFUSED', { checks: { ipv4: { ok: true }, ipv6: { ok: false, codes: ['ECONNREFUSED'] } } });
  assert.equal(result.findings.find(item => item.code === 'network.ipv6').confidence, 'likely');
  assert.ok(!report('ECONNREFUSED').findings.some(item => item.code === 'network.ipv6'));
});
test('proxy evidence is possible because custom dispatchers may handle it', () => {
  const runtime = runtimeInfo('https://example.com', { HTTPS_PROXY: 'http://user:secret@proxy.local:8080' });
  const result = report('ECONNRESET', { runtime });
  assert.equal(result.findings.find(item => item.code === 'proxy.configuration').confidence, 'possible');
  assert.ok(!JSON.stringify(result).includes('secret'));
  assert.ok(!report('ECONNRESET', { runtime: { ...runtime, noProxyMatch: true } }).findings.some(item => item.code === 'proxy.configuration'));
});
test('NO_PROXY matching respects host boundaries, ports, and IPv6', () => {
  assert.equal(bypassesProxy('https://sub.example.com', '.example.com'), true);
  assert.equal(bypassesProxy('https://badexample.com', '.example.com'), false);
  assert.equal(bypassesProxy('https://example.com', 'example.com:80'), false);
  assert.equal(bypassesProxy('https://example.com', 'example.com:443'), true);
  assert.equal(bypassesProxy('http://[::1]:8080', '[::1]:8080'), true);
  assert.equal(bypassesProxy('https://anything.com', '*'), true);
});
test('HTTP statuses are distinct from transport errors', () => {
  const result = explain(null, { url: 'https://example.com', status: 429, runtime: clean });
  assert.equal(result.error, null);
  assert.equal(result.findings[0].code, 'http.429');
  assert.equal(result.outcome, 'failed');
});
test('formatters produce JSON, Markdown, and text', () => {
  const result = report('ENOTFOUND');
  assert.deepEqual(JSON.parse(formatReport(result, 'json')), result);
  assert.ok(formatReport(result, 'markdown').startsWith('```text\n'));
  assert.ok(formatReport(result).includes('Hostname resolution failed'));
  assert.throws(() => formatReport(result, 'html'));
});
