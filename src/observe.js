'use strict';
const { channel } = require('node:diagnostics_channel');
const { performance } = require('node:perf_hooks');
const { explain } = require('./report');

function observe(options = {}) {
  if (typeof options.onReport !== 'function') throw new TypeError('onReport must be a function');
  const requests = new WeakMap();
  const subscriptions = [];
  let active = true;
  function deliver(report) {
    if (!active) return;
    // Subscriber exceptions must not escape into Undici or create rejections.
    try { Promise.resolve(options.onReport(report)).catch(() => {}); } catch {}
  }
  function subscribe(name, callback) {
    const subscription = channel(name);
    const guarded = message => { if (active) { try { callback(message); } catch {} } };
    subscription.subscribe(guarded);
    subscriptions.push(() => subscription.unsubscribe(guarded));
  }
  const requestUrl = request => new URL(request.path, String(request.origin));
  subscribe('undici:request:create', ({ request }) => requests.set(request, { start: performance.now(), status: undefined, reported: false }));
  subscribe('undici:request:headers', ({ request, response }) => {
    const entry = requests.get(request);
    if (entry) {
      entry.status = response.statusCode;
      if (entry.status >= 400) {
        entry.reported = true;
        deliver(explain(null, { url: requestUrl(request), method: request.method, status: entry.status, durationMs: performance.now() - entry.start }));
      }
    }
  });
  subscribe('undici:request:error', ({ request, error }) => {
    const entry = requests.get(request);
    if (!entry || entry.reported) return;
    entry.reported = true;
    deliver(explain(error, { url: requestUrl(request), method: request.method, durationMs: performance.now() - entry.start }));
  });
  subscribe('undici:request:trailers', ({ request }) => {
    const entry = requests.get(request);
    if (!entry || entry.reported) return;
    entry.reported = true;
    if (entry.status >= 400 || options.includeSuccessful) deliver(explain(null, { url: requestUrl(request), method: request.method, status: entry.status, durationMs: performance.now() - entry.start }));
  });
  return () => { active = false; for (const unsubscribe of subscriptions) unsubscribe(); };
}
module.exports = { observe };
