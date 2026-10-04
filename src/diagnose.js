'use strict';
const { performance } = require('node:perf_hooks');
const { validUrl, errorCodes } = require('./privacy');
const { runtimeInfo } = require('./runtime');
const { explain, TLS_CODES } = require('./report');
const { resolveHost, tcpCheck, tlsCheck, validateTimeout } = require('./probes');

async function diagnose(input, options = {}) {
  let target = validUrl(input);
  const timeoutMs = validateTimeout(options.timeoutMs);
  const method = options.method || 'HEAD';
  if (!['GET', 'HEAD'].includes(method)) throw new TypeError('Diagnostics support GET and HEAD only');
  const started = performance.now();
  const checks = {};
  let status;
  let failure;
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
  try {
    for (let hop = 0; hop <= 5; hop++) {
      status = undefined;
      const response = await fetch(target, { method, redirect: 'manual', signal,
        ...(options.probeId ? { headers: { 'user-agent': `wirewhy/${require('../package.json').version} ${options.probeId}`, 'x-wirewhy-check': options.probeId } } : {}) });
      status = response.status;
      const location = response.headers.get('location');
      const redirect = [301, 302, 303, 307, 308].includes(status) && location;
      if (options.readBody && !redirect && response.body) {
        const reader = response.body.getReader();
        let bytes = 0;
        try {
          while (bytes < 1024 * 1024) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
          }
        } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
      } else await response.body?.cancel();
      if (redirect) {
        if (hop === 5) throw Object.assign(new Error('Redirect limit reached'), { code: 'REDIRECT_LIMIT' });
        target = validUrl(new URL(location, target));
        continue;
      }
      checks.nativeFetch = { ok: status < 400 };
      break;
    }
  } catch (error) {
    failure = error;
    checks.nativeFetch = { ok: false, codes: errorCodes(error) };
  }
  const nativeDurationMs = performance.now() - started;
  const runtime = runtimeInfo(target);
  if (failure && !options.signal?.aborted) {
    const host = target.hostname.replace(/^\[|\]$/g, '');
    const resolved = await resolveHost(host, timeoutMs, options.signal);
    checks.dns = { ok: resolved.ok, ...(resolved.codes ? { codes: resolved.codes } : {}) };
    if (resolved.ok) {
      const port = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
      const results = await Promise.all([4, 6].map(async family => {
        const address = resolved.addresses.find(item => item.family === family);
        return address ? tcpCheck(address, port, timeoutMs, options.signal) : { ok: null, reason: 'No address for this family.' };
      }));
      [checks.ipv4, checks.ipv6] = results;
    }
    const codes = errorCodes(failure);
    if (target.protocol === 'https:' && codes.some(code => TLS_CODES.includes(code)) && options.compareSystemCa !== false) {
      if (!runtime.systemCaSupported) checks.systemCa = { ok: null, reason: 'This Node version does not support --use-system-ca.' };
      else if (runtime.proxyConfigured && !runtime.noProxyMatch) checks.systemCa = { ok: null, reason: 'Skipped: a direct TLS probe would not reproduce the proxy route.' };
      else if (!resolved.ok || !resolved.addresses.length) checks.systemCa = { ok: null, reason: 'No resolved address available for the comparison.' };
      else {
        const address = resolved.addresses.find(item => item.family === 4) || resolved.addresses[0];
        [checks.defaultTls, checks.systemCa] = await Promise.all([
          tlsCheck(target, address, false, timeoutMs, options.signal),
          tlsCheck(target, address, true, timeoutMs, options.signal)
        ]);
      }
    }
  }
  const report = explain(failure, { url: target, method, status, checks, runtime, durationMs: nativeDurationMs });
  report.checkDurationMs = Math.round(performance.now() - started);
  if (!failure && status < 400) report.outcome = 'ok';
  return report;
}
module.exports = { diagnose };
