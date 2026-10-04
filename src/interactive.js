'use strict';
const readline = require('node:readline/promises');
const { normalizeUrl, saveConfig } = require('./config');

async function setup(previous = {}) {
  const ui = readline.createInterface({ input: process.stdin, output: process.stderr });
  const controller = new AbortController();
  ui.on('SIGINT', () => controller.abort());
  const ask = async (label, fallback = '') => {
    const answer = await ui.question(`${label}${fallback ? ` [${fallback}]` : ''}: `, { signal: controller.signal });
    return answer.trim() || fallback;
  };
  try {
    process.stderr.write('Wirewhy\nSet a website once. Next time, just run wirewhy.\n\n');
    let url;
    while (!url) {
      try { url = normalizeUrl(await ask('Website URL', previous.url)); }
      catch (error) { if (error.name === 'AbortError') throw error; process.stderr.write('Enter a valid HTTP or HTTPS URL.\n'); }
    }
    const target = await ask('Server (SSH alias, local, or none)', previous.ssh || (previous.local ? 'local' : 'none'));
    const config = { url };
    if (target !== 'none') {
      if (target === 'local') config.local = true;
      else config.ssh = target;
      const sudo = await ask('Use non-interactive sudo for server reads? y/n', previous.sudo ? 'y' : 'n');
      config.sudo = /^y(?:es)?$/i.test(sudo);
      const service = await ask('App service (Enter to auto-detect)', previous.service);
      if (service) config.service = service;
      if (previous.sshConfig) config.sshConfig = previous.sshConfig;
      if (previous.nginxConfig) config.nginxConfig = previous.nginxConfig;
      if (previous.logs) config.logs = previous.logs;
    }
    const saved = saveConfig(config);
    process.stderr.write('\nSaved. Checking now...\n');
    return saved;
  } finally { ui.close(); }
}

function progress(enabled) {
  if (!enabled) return { update() {}, stop() {} };
  let label = 'Checking website';
  let frame = 0;
  const frames = ['|', '/', '-', '\\'];
  const render = () => process.stderr.write(`\r\x1b[2K${frames[frame++ % frames.length]} ${label}`);
  render();
  const timer = setInterval(render, 100);
  return { update(value) { label = value; render(); }, stop() { clearInterval(timer); process.stderr.write('\r\x1b[2K'); } };
}
module.exports = { setup, progress };
