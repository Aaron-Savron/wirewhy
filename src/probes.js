'use strict';
const dns = require('node:dns').promises;
const net = require('node:net');
const { execFile } = require('node:child_process');
const { errorCodes } = require('./privacy');

function timeoutError() { return Object.assign(new Error('Diagnostic timeout'), { code: 'TIMEOUT' }); }
function validateTimeout(value = 5000) {
  if (!Number.isInteger(value) || value < 1 || value > 60000) throw new RangeError('timeoutMs must be an integer from 1 to 60000');
  return value;
}

function bounded(operation, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    let timer;
    const finish = (fn, value) => { clearTimeout(timer); signal?.removeEventListener('abort', abort); fn(value); };
    const abort = () => finish(reject, Object.assign(new Error('Cancelled'), { name: 'AbortError' }));
    if (signal?.aborted) return abort();
    signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => finish(reject, timeoutError()), timeoutMs);
    Promise.resolve().then(operation).then(value => finish(resolve, value), error => finish(reject, error));
  });
}

async function resolveHost(host, timeoutMs, signal) {
  try {
    const addresses = await bounded(() => dns.lookup(host, { all: true }), timeoutMs, signal);
    return { ok: true, addresses };
  } catch (error) { return { ok: false, codes: errorCodes(error) }; }
}

function tcpCheck(address, port, timeoutMs, signal) {
  return new Promise(resolve => {
    let socket;
    let timer;
    let settled = false;
    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      socket?.destroy();
      resolve(result);
    };
    const abort = () => finish({ ok: false, codes: ['ABORTED'] });
    if (signal?.aborted) return abort();
    signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => finish({ ok: false, codes: ['ETIMEDOUT'] }), timeoutMs);
    socket = net.connect({ host: address.address, family: address.family, port });
    socket.once('connect', () => finish({ ok: true }));
    socket.once('error', error => finish({ ok: false, codes: errorCodes(error) }));
  });
}

// A fresh process is necessary: Node reads CA flags during startup.
const tlsScript = `
const tls = require('node:tls');
const host = process.argv[1];
const name = process.argv[4];
const socket = tls.connect({ host, port: Number(process.argv[2]), servername: require('node:net').isIP(name) ? undefined : name, rejectUnauthorized: true });
let done = false;
function finish(result) { if (done) return; done = true; socket.destroy(); process.stdout.write(JSON.stringify(result)); }
socket.once('secureConnect', () => finish({ ok: true }));
socket.once('error', error => finish({ ok: false, code: error.code }));
socket.setTimeout(Number(process.argv[3]), () => finish({ ok: false, code: 'ETIMEDOUT' }));
`;

function tlsCheck(url, address, useSystemCa, timeoutMs, signal) {
  return new Promise(resolve => {
    if (signal?.aborted) return resolve({ ok: false, codes: ['ABORTED'] });
    const name = url.hostname.replace(/^\[|\]$/g, '');
    const trustFlags = process.execArgv.filter(arg => ['--use-system-ca', '--use-bundled-ca', '--use-openssl-ca'].includes(arg));
    if (useSystemCa && !trustFlags.includes('--use-system-ca')) trustFlags.push('--use-system-ca');
    execFile(process.execPath, [...trustFlags, '-e', tlsScript, address.address, url.port || '443', String(timeoutMs), name], {
      timeout: timeoutMs + 250,
      maxBuffer: 4096,
      signal,
      env: process.env,
      windowsHide: true
    }, (error, stdout) => {
      if (error) return resolve({ ok: false, codes: signal?.aborted ? ['ABORTED'] : error.killed ? ['ETIMEDOUT'] : errorCodes(error) });
      try {
        const result = JSON.parse(stdout);
        resolve({ ok: Boolean(result.ok), ...(!result.ok ? { codes: errorCodes({ code: result.code }) } : {}) });
      } catch { resolve({ ok: null, reason: 'TLS comparison produced no usable result.' }); }
    });
  });
}
module.exports = { resolveHost, tcpCheck, tlsCheck, validateTimeout };
