'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { channel } = require('node:diagnostics_channel');
const { observe } = require('../src');
const { server } = require('./helpers');

test('observes simultaneous requests without replacing fetch or consuming bodies', async t => {
  const reports = [];
  const original = globalThis.fetch;
  const stop = observe({ onReport: report => reports.push(report), includeSuccessful: true });
  t.after(stop);
  const app = await server((req, res) => { res.writeHead(req.url === '/error' ? 503 : 200); res.end(req.url); });
  t.after(app.close);
  const bodies = await Promise.all(['/one', '/error', '/two'].map(async path => (await fetch(`${app.url}${path}`)).text()));
  assert.deepEqual(bodies, ['/one', '/error', '/two']);
  assert.equal(globalThis.fetch, original);
  assert.equal(reports.length, 3);
  assert.equal(reports.filter(report => report.request.status === 503).length, 1);
  assert.equal(reports.filter(report => report.outcome === 'ok').length, 2);
});
test('HTTP failure is visible as soon as headers arrive', async t => {
  const reports = [];
  const stop = observe({ onReport: report => reports.push(report) });
  t.after(stop);
  const app = await server((req, res) => { res.writeHead(401); res.flushHeaders(); });
  t.after(app.close);
  const response = await fetch(app.url);
  assert.equal(reports[0].findings[0].code, 'http.401');
  await response.body.cancel();
});
test('captures native transport failures once', async () => {
  const app = await server((req, res) => res.end());
  const url = app.url;
  await app.close();
  const reports = [];
  const stop = observe({ onReport: report => reports.push(report) });
  try {
    await assert.rejects(fetch(`${url}/reset/secret?token=secret`));
    assert.equal(reports.length, 1);
    assert.equal(reports[0].findings[0].code, 'connection.refused');
    assert.ok(!JSON.stringify(reports).includes('secret'));
  } finally { stop(); }
});
test('subscriber exceptions cannot affect application requests', async t => {
  const stops = [
    observe({ onReport: () => { throw new Error('subscriber failed'); } }),
    observe({ onReport: async () => { throw new Error('async subscriber failed'); } })
  ];
  t.after(() => stops.forEach(stop => stop()));
  const app = await server((req, res) => { res.writeHead(500); res.end('original'); });
  t.after(app.close);
  const response = await fetch(app.url);
  assert.equal(await response.text(), 'original');
});
test('unsubscribe removes every owned listener and is idempotent', async t => {
  const event = channel('undici:request:error');
  const reports = [];
  const stop = observe({ onReport: report => reports.push(report) });
  assert.equal(event.hasSubscribers, true);
  stop(); stop();
  assert.equal(event.hasSubscribers, false);
  const app = await server((req, res) => { res.writeHead(500); res.end(); });
  t.after(app.close);
  await (await fetch(app.url)).text();
  assert.equal(reports.length, 0);
});
test('malformed diagnostic messages do not escape subscribers', () => {
  const stop = observe({ onReport: () => {} });
  try { assert.doesNotThrow(() => channel('undici:request:headers').publish({})); }
  finally { stop(); }
});
