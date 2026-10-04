'use strict';
const { existsSync, readFileSync, mkdirSync, writeFileSync, renameSync, unlinkSync } = require('node:fs');
const { homedir } = require('node:os');
const { join, resolve, dirname } = require('node:path');
const { randomUUID } = require('node:crypto');
const { validUrl } = require('./privacy');
const { validateServerOptions } = require('./server');
const { validateTimeout } = require('./probes');

function userConfigPath() {
  return process.env.WIREWHY_CONFIG ? resolve(process.env.WIREWHY_CONFIG) : join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'wirewhy', 'config.json');
}
function normalizeUrl(input) {
  const value = String(input).trim();
  if (!value) throw new TypeError('Provide a website URL');
  return validUrl(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value) ? value : `https://${value}`).href;
}
function validateConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected a site configuration object');
  const result = { url: normalizeUrl(value.url || '') };
  for (const name of ['ssh', 'sshConfig', 'nginxConfig', 'service', 'discoveredService', 'logs']) if (value[name] !== undefined) result[name] = value[name];
  for (const name of ['local', 'sudo']) {
    if (value[name] !== undefined && typeof value[name] !== 'boolean') throw new TypeError('Server switches must be boolean');
    if (value[name]) result[name] = true;
  }
  if (value.timeoutMs !== undefined) result.timeoutMs = validateTimeout(value.timeoutMs);
  if (value.method !== undefined) {
    if (!['GET', 'HEAD'].includes(value.method)) throw new TypeError('Method must be GET or HEAD');
    result.method = value.method;
  }
  if (result.ssh && result.local) throw new TypeError('Choose SSH or a local server, not both');
  if ((result.sudo || result.service || result.discoveredService || result.logs || result.sshConfig || result.nginxConfig || value.includeLogs) && !result.ssh && !result.local) throw new TypeError('Server options need --ssh or --local');
  validateServerOptions(result);
  return result;
}
function loadConfig() {
  const project = join(process.cwd(), 'wirewhy.config.json');
  const path = process.env.WIREWHY_CONFIG ? userConfigPath() : existsSync(project) ? project : userConfigPath();
  if (!existsSync(path)) return null;
  try {
    const config = readFileSync(path, 'utf8');
    if (config.length > 16384) throw new Error();
    return { ...validateConfig(JSON.parse(config)), configPath: path };
  } catch { throw new Error('Saved configuration is invalid. Run wirewhy setup or check wirewhy.config.json.'); }
}
function saveConfig(value, path = userConfigPath()) {
  const config = validateConfig(value);
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
    renameSync(temp, path);
  } finally { if (existsSync(temp)) unlinkSync(temp); }
  return { ...config, configPath: path };
}
module.exports = { normalizeUrl, validateConfig, loadConfig, saveConfig, userConfigPath };
