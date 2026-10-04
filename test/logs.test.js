'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeLogs, redactLog, logTime } = require('../src/logs');

const now = '2026-10-04T18:00:00Z';
const error = (host = 'example.com', date = '2026/10/04 17:59:58', path = '/') => `${date} [error] 100#100: *42 connect() failed (111: Connection refused) while connecting to upstream, client: 192.0.2.2, server: ${host}, request: "GET ${path} HTTP/1.1", upstream: "http://127.0.0.1:3000/", host: "${host}"`;
const raw = logs => ({ collectedAt: now, timezoneOffsetMinutes: 0, nginx: { service: 'active' }, logs });

test('ranks the matching upstream error and excludes other hosts, paths, and stale logs', () => {
  const source = { path: '/var/log/nginx/error.log', kind: 'nginx-error', siteScoped: false, ok: true,
    lines: [error('other.com'), error('example.com', '2026/10/04 16:00:00'), error('example.com', '2026/10/04 17:59:59', '/other'), error()] };
  const result = analyzeLogs(raw([source]), 'https://example.com/');
  assert.equal(result.entries.length, 1);
  assert.equal(result.entries[0].code, 'upstream.refused');
  assert.equal(result.entries[0].confidence, 'likely');
  assert.equal(result.entries[0].correlation, 'site-request');
  assert.ok(result.entries[0].excerpt.includes('Connection refused'));
  assert.ok(!result.entries[0].excerpt.includes('192.0.2.2'));
});
test('scoped application journals show the exception and stack without claiming a request match', () => {
  const result = analyzeLogs(raw([{ path: 'journal:app.service', kind: 'app-journal', siteScoped: true, ok: true,
    lines: ['2026-10-04T17:59:59.123456+00:00 host app[1]: TypeError: database is unavailable', '2026-10-04T17:59:59.123457+00:00 host app[1]:     at handle (/app/server.js:42:5)'] }]), 'https://example.com');
  assert.equal(result.entries.length, 1);
  assert.equal(result.entries[0].confidence, 'possible');
  assert.equal(result.entries[0].correlation, 'service');
  assert.ok(result.entries[0].excerpt.includes('/app/server.js:42:5'));
});
test('timestamp-less app logs are explicitly unverified', () => {
  const result = analyzeLogs(raw([{ path: '/app/error.log', kind: 'app-file', siteScoped: true, ok: true, lines: ['TypeError: app failed'] }]), 'https://example.com');
  assert.equal(result.entries[0].confidence, 'unknown');
  assert.equal(result.entries[0].correlation, 'time-unverified');
});
test('shared access logs need the unique probe ID', () => {
  const line = '192.0.2.1 - - [04/Oct/2026:17:59:59 +0000] "GET / HTTP/1.1" 502 10 "-" "wirewhy/0.2.0 probe-123"';
  const source = { path: '/var/log/nginx/access.log', kind: 'nginx-access', siteScoped: false, ok: true, lines: [line] };
  assert.equal(analyzeLogs(raw([source]), 'https://example.com', 'different').entries.length, 0);
  const result = analyzeLogs(raw([source]), 'https://example.com', 'probe-123');
  assert.equal(result.entries[0].code, 'http.probe');
  assert.equal(result.entries[0].confidence, 'confirmed');
});
test('timestamps respect the server timezone and combined-log offsets', () => {
  assert.equal(logTime('2026/10/04 14:00:00 [error]', -240), Date.parse(now));
  assert.equal(logTime('[04/Oct/2026:14:00:00 -0400]'), Date.parse(now));
  assert.equal(logTime('2026-10-04T14:00:00-04:00 fatal'), Date.parse(now));
});
test('redacts headers, tokens, URL credentials, queries, request paths, and terminal escapes', () => {
  for (const line of [
    'Authorization: Bearer private-secret',
    '{"password":"private-secret","message":"failed"}',
    'error https://user:private-secret@example.com/private-secret?key=private-secret',
    'Error connecting to postgresql://user:private-secret@db.local/db',
    'Error connecting to mongodb+srv://user:private-secret@cluster.local/db',
    'request: "GET /private-secret?token=private-secret HTTP/1.1"',
    'cookie=session=private-secret',
    '\x1b[2JError: broken\x00'
  ]) {
    const output = redactLog(line);
    assert.ok(!output.includes('private-secret'));
    assert.ok(!output.includes('\x1b'));
    assert.ok(!output.includes('\x00'));
  }
});
test('missing log access stays explicit and does not fabricate an error', () => {
  const result = analyzeLogs(raw([{ path: '/var/log/nginx/error.log', ok: false, reason: 'Permission denied. Try --sudo.' }]), 'https://example.com');
  assert.equal(result.entries.length, 0);
  assert.ok(result.issues[0].includes('Permission denied'));
});
test('bounds the displayed log evidence', () => {
  const result = analyzeLogs(raw([{ path: '/var/log/nginx/error.log', kind: 'nginx-error', ok: true, lines: Array.from({ length: 300 }, () => error()) }]), 'https://example.com');
  assert.equal(result.entries.length, 1);
});
