'use strict';
const { existsSync } = require('node:fs');

function bypassesProxy(url, noProxy) {
  if (!url || !noProxy) return false;
  let target;
  try { target = new URL(String(url)); } catch { return false; }
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const port = target.port || (target.protocol === 'https:' ? '443' : '80');
  return noProxy.split(',').some(entry => {
    let pattern = entry.trim().toLowerCase();
    if (pattern === '*') return true;
    if (!pattern) return false;
    const match = pattern.match(/^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/);
    if (!match) return pattern === host;
    if (match[2] && match[2] !== port) return false;
    pattern = match[1].replace(/^\[|\]$/g, '');
    if (pattern.startsWith('*.')) pattern = pattern.slice(1);
    if (pattern.startsWith('.')) return host.endsWith(pattern) || host === pattern.slice(1);
    return host === pattern;
  });
}

function runtimeInfo(url, env = process.env) {
  const flags = [...process.execArgv, env.NODE_OPTIONS || ''].join(' ');
  const proxyNames = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'];
  return {
    node: process.version,
    undici: process.versions.undici || null,
    platform: process.platform,
    arch: process.arch,
    proxyConfigured: proxyNames.some(name => Boolean(env[name])),
    proxyEnvEnabled: process.allowedNodeEnvironmentFlags.has('--use-env-proxy') && (env.NODE_USE_ENV_PROXY === '1' || /(?:^|\s)--use-env-proxy(?:\s|$)/.test(flags)),
    noProxyMatch: bypassesProxy(url, env.no_proxy || env.NO_PROXY),
    systemCaSupported: process.allowedNodeEnvironmentFlags.has('--use-system-ca'),
    systemCaEnabled: /(?:^|\s)--use-system-ca(?:\s|$)/.test(flags) || env.NODE_USE_SYSTEM_CA === '1',
    extraCaConfigured: Boolean(env.NODE_EXTRA_CA_CERTS),
    extraCaExists: env.NODE_EXTRA_CA_CERTS ? existsSync(env.NODE_EXTRA_CA_CERTS) : null,
    tlsVerificationDisabled: env.NODE_TLS_REJECT_UNAUTHORIZED === '0'
  };
}
module.exports = { runtimeInfo, bypassesProxy };
