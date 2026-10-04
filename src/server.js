'use strict';
const { spawn } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { join, isAbsolute } = require('node:path');

function validateServerOptions(options = {}) {
  for (const name of ['local', 'sudo']) if (options[name] !== undefined && typeof options[name] !== 'boolean') throw new TypeError('Server switches must be boolean');
  if (options.ssh && options.local) throw new TypeError('Choose SSH or a local server, not both');
  if ((options.sudo || options.service || options.discoveredService || options.logs || options.sshConfig || options.nginxConfig || options.includeLogs) && !options.ssh && !options.local) throw new TypeError('Server options need --ssh or --local');
  if (options.ssh && (typeof options.ssh !== 'string' || !/^[a-zA-Z0-9_@.:[\]-]+$/.test(options.ssh) || options.ssh.startsWith('-') || options.ssh.length > 255)) throw new TypeError('SSH target must be an alias or user@host, without shell characters');
  if (options.sshConfig && (typeof options.sshConfig !== 'string' || !isAbsolute(options.sshConfig) || /[\0\r\n]/.test(options.sshConfig))) throw new TypeError('SSH config must be an absolute file path');
  if (options.nginxConfig && (typeof options.nginxConfig !== 'string' || !isAbsolute(options.nginxConfig) || /[\0\r\n]/.test(options.nginxConfig))) throw new TypeError('NGINX config must be an absolute file path');
  for (const service of [options.service, options.discoveredService]) {
    if (service && (typeof service !== 'string' || !/^[a-zA-Z0-9_.@:-]+$/.test(service) || service.startsWith('-') || service.length > 255)) throw new TypeError('App service must be a systemd unit name');
  }
  if (options.logs && (!Array.isArray(options.logs) || options.logs.length > 10 || options.logs.some(path => typeof path !== 'string' || !isAbsolute(path) || /[\0\r\n]/.test(path)))) throw new TypeError('Provide up to ten absolute log file paths');
  return options;
}

function collectServer(input, options = {}) {
  validateServerOptions(options);
  const url = new URL(String(input));
  const payload = Buffer.from(JSON.stringify({ hostname: url.hostname.toLowerCase(), service: options.service, discoveredService: options.discoveredService, logs: options.logs, collectLogs: options.collectLogs, nginxConfig: options.nginxConfig, originCheck: options.originCheck, originScheme: options.originScheme, probeId: options.probeId })).toString('base64');
  const script = readFileSync(join(__dirname, 'server-collector.py'));
  let command;
  let args;
  if (options.ssh) {
    command = 'ssh';
    args = [...(options.sshConfig ? ['-F', options.sshConfig] : []), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '--', options.ssh,
      `${options.sudo ? 'sudo -n -- ' : ''}python3 - '${payload}'`];
  } else {
    command = options.sudo ? 'sudo' : 'python3';
    args = options.sudo ? ['-n', '--', 'python3', '-', payload] : ['-', payload];
  }
  return new Promise(resolve => {
    if (options.signal?.aborted) return resolve({ error: 'Server check cancelled.', issues: [] });
    let stdout = ''; let stderr = ''; let done = false; let timer;
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    function finish(result) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
      resolve(result);
    }
    const abort = () => { child.kill(); finish({ error: 'Server check cancelled.', issues: [] }); };
    options.signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => { child.kill(); finish({ error: 'Server check timed out.', issues: [] }); }, 25000);
    child.stdout.on('data', data => {
      stdout += data;
      if (Buffer.byteLength(stdout) > 2 * 1024 * 1024) { child.kill(); finish({ error: 'Server evidence exceeded the size limit.', issues: [] }); }
    });
    child.stderr.on('data', data => { if (stderr.length < 16384) stderr += data; });
    child.stdin.on('error', () => {});
    child.once('error', () => finish({ error: `${command === 'ssh' ? 'SSH' : 'Python 3 or sudo'} is unavailable.`, issues: [] }));
    child.once('close', code => {
      if (code !== 0) {
        const reason = /bad owner|permissions on.*ssh_config/i.test(stderr) ? 'SSH config has invalid ownership or permissions. Use --ssh-config with your user config.'
          : /sudo:.*(?:password|not allowed|not in)/i.test(stderr) ? 'Non-interactive sudo is unavailable. Run with an account that can read NGINX config and logs.'
          : /python3.*(?:not found|No such file)/i.test(stderr) ? 'Python 3 is required on the server.'
          : 'Server connection or collection failed. Check SSH access and read permissions.';
        finish({ error: reason, issues: [] });
        return;
      }
      try { finish(JSON.parse(stdout)); } catch { finish({ error: 'Server returned no usable evidence.', issues: [] }); }
    });
    child.stdin.end(script);
  });
}
module.exports = { collectServer, validateServerOptions };
