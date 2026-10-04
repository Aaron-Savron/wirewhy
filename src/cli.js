#!/usr/bin/env node
'use strict';
const { spawn } = require('node:child_process');
const { writeFileSync, readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { diagnose, explain, formatReport, inspectSite, formatSiteReport } = require('./index');
const { validateTimeout } = require('./probes');
const { loadConfig, saveConfig, normalizeUrl, validateConfig } = require('./config');
const { setup, progress } = require('./interactive');

const help = `Usage:
  wirewhy                     Check your saved website and server
  wirewhy <url>               Check a website
  wirewhy setup               Save a website and server
  wirewhy site [url] [--ssh <host> | --local] [--sudo]
  wirewhy check <url> [--method HEAD|GET] [--timeout <ms>]
  wirewhy explain --url <url> < error.json
  wirewhy run [--all] [--format text|json|markdown] [--output reports.jsonl] -- <command> [args]

Options:
  --format text|json|markdown   Report format (default: text)
  --output <file>              Write a check report or append run reports
  --no-system-ca               Skip the system certificate-store comparison
  --ssh <host>                 Inspect a server through SSH
  --ssh-config <file>           Use a specific SSH config file
  --nginx-config <file>         Inspect a non-default NGINX config
  --local                     Inspect this machine's NGINX
  --sudo                      Use sudo -n for server reads
  --service <unit>             App systemd unit (otherwise auto-detect)
  --log <absolute-path>        App log file (repeatable)
  --logs                      Include recent logs even when the site is up
  --help                      Show help
  --version                   Show version

check sends HEAD by default. Follow-up checks use DNS, TCP, and TLS.
site uses GET and inspects logs automatically when the website is unavailable.
run observes native fetch and Undici; it preserves the command's exit code.
`;

function parse(args) {
  let command = args.shift();
  if (command?.startsWith('-')) { args.unshift(command); command = 'site'; }
  if (!['check', 'explain', 'run', 'site', 'setup'].includes(command)) {
    if (command && !command.startsWith('-') && (command.includes('.') || /^https?:\/\//.test(command) || command.startsWith('localhost'))) { args.unshift(command); command = 'site'; }
    else throw new Error('Expected a URL or command. Use --help for usage.');
  }
  const options = { format: 'text' };
  const positional = [];
  let child = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--' && command === 'run') { child = args.slice(i + 1); break; }
    if (['--format', '--output', '--timeout', '--method', '--url', '--ssh', '--ssh-config', '--nginx-config', '--service', '--log'].includes(arg)) {
      if (!args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`Missing value for ${arg}`);
      const value = args[++i];
      if (arg === '--log') (options.logs ||= []).push(resolve(value));
      else if (arg === '--ssh-config' || arg === '--nginx-config') options[arg === '--ssh-config' ? 'sshConfig' : 'nginxConfig'] = resolve(value);
      else options[arg.slice(2)] = value;
    } else if (arg === '--all' && command === 'run') options.all = true;
    else if (arg === '--no-system-ca' && ['check', 'site'].includes(command)) options.compareSystemCa = false;
    else if (['--local', '--sudo', '--logs'].includes(arg)) options[arg === '--logs' ? 'includeLogs' : arg.slice(2)] = true;
    else if (arg.startsWith('-')) throw new Error('Unknown option. Use --help for usage.');
    else positional.push(arg);
  }
  if (!['text', 'json', 'markdown'].includes(options.format)) throw new Error('Format must be text, json, or markdown');
  if (options.timeout !== undefined) options.timeoutMs = validateTimeout(Number(options.timeout));
  if (options.method && !['GET', 'HEAD'].includes(options.method)) throw new Error('Method must be HEAD or GET');
  if (command === 'run' && (!child.length || positional.length)) throw new Error('Use wirewhy run -- <command> [args]');
  if (command === 'check' && (positional.length !== 1 || options.url)) throw new Error('Use wirewhy check <url>');
  if (command === 'explain' && (!options.url || positional.length)) throw new Error('Use wirewhy explain --url <url> < error.json');
  if (['site', 'setup'].includes(command) && positional.length > 1) throw new Error('Provide one website URL');
  const hasServer = options.ssh || options.local || options.sudo || options.sshConfig || options.nginxConfig || options.service || options.logs || options.includeLogs;
  if (hasServer && ['explain', 'run'].includes(command)) throw new Error('Server options apply to site and check commands');
  if (hasServer && command === 'check') command = 'site';
  if (!['check', 'site', 'setup'].includes(command) && (options.method || options.timeout)) throw new Error('--method and --timeout apply to check or site');
  if (options.ssh && options.local) throw new Error('Choose --ssh or --local');
  return { command, options, target: positional[0], child };
}

function runCommand(command, args, options) {
  const env = { ...process.env, WIREWHY_FORMAT: options.format, WIREWHY_ALL: options.all ? '1' : '0' };
  if (options.output) env.WIREWHY_OUTPUT = resolve(options.output);
  else delete env.WIREWHY_OUTPUT;
  env.NODE_OPTIONS = `${env.NODE_OPTIONS || ''} --require ${JSON.stringify(require.resolve('./register'))}`.trim();
  const child = spawn(command, args, { env, stdio: 'inherit', shell: false });
  let spawnFailed = false;
  const signals = ['SIGINT', 'SIGTERM'];
  const handlers = signals.map(signal => {
    const handler = () => child.kill(signal);
    process.on(signal, handler);
    return handler;
  });
  child.once('error', () => { spawnFailed = true; console.error('wirewhy: unable to start command. Check that it is installed and executable.'); process.exitCode = 2; });
  child.once('close', (code, signal) => {
    signals.forEach((name, i) => process.removeListener(name, handlers[i]));
    process.exitCode = spawnFailed ? 2 : code === null ? ({ SIGINT: 130, SIGTERM: 143, SIGKILL: 137 }[signal] || 1) : code;
  });
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === '--help' || args[0] === '-h') { process.stdout.write(help); return; }
  if (args[0] === '--version') { console.log(require('../package.json').version); return; }
  let parsed;
  if (!args.length) {
    let config = loadConfig();
    if (!config) {
      if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('No saved website. Run wirewhy setup in a terminal, or wirewhy <url>.');
      config = await setup();
    }
    parsed = { command: 'site', options: { ...config, format: 'text' }, target: config.url };
  } else parsed = parse(args);
  let { command, options, target, child } = parsed;
  if (command === 'run') { runCommand(child[0], child.slice(1), options); return; }
  if (command === 'setup') {
    if (!target) {
      if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Use wirewhy setup <url> [server options], or run setup in a terminal.');
      const config = await setup(loadConfig() || {});
      target = config.url; options = { ...config, format: options.format }; command = 'site';
    } else {
      const saved = saveConfig({ ...options, url: normalizeUrl(target) });
      console.log(`Saved ${saved.url}. Run wirewhy to check it.`);
      return;
    }
  }
  if (command === 'site') {
    const saved = loadConfig();
    if (!target) {
      if (!saved) throw new Error('Provide a URL or run wirewhy setup');
      target = saved.url;
    }
    target = normalizeUrl(target);
    // Reuse server settings only for the configured origin.
    const matching = saved && new URL(saved.url).origin === new URL(target).origin;
    options = { ...(matching ? saved : {}), ...options };
    if (options.ssh && options.local) { if (parsed.options.local) delete options.ssh; else delete options.local; }
    const sameServer = matching && saved.ssh === options.ssh && Boolean(saved.local) === Boolean(options.local)
      && saved.sshConfig === options.sshConfig && saved.nginxConfig === options.nginxConfig;
    if (!sameServer) delete options.discoveredService;
    validateConfig({ ...options, url: target });
    const spinner = progress(options.format === 'text' && process.stderr.isTTY && process.stdout.isTTY);
    const controller = new AbortController();
    const abort = () => controller.abort();
    process.once('SIGINT', abort);
    let report;
    try { report = await inspectSite(target, { ...options, signal: controller.signal, onProgress: spinner.update }); }
    finally { spinner.stop(); process.removeListener('SIGINT', abort); }
    if (sameServer && report.server?.nginx?.siteMatched && report.server.app?.discovered
      && report.server.app.state === 'active' && saved.discoveredService !== report.server.app.service) {
      try { saveConfig({ ...saved, discoveredService: report.server.app.service }, saved.configPath); }
      catch { process.stderr.write('wirewhy: Could not remember the discovered app service. Use --service to check it after a crash.\n'); }
    }
    const output = `${formatSiteReport(report, options.format, process.stdout.isTTY && !process.env.NO_COLOR)}\n`;
    if (options.output) writeFileSync(options.output, output, { mode: 0o600 });
    else process.stdout.write(output);
    if (process.stdout.isTTY && options.format === 'text') console.log(saved?.url === target ? '\nRun wirewhy to check again. Change the site with wirewhy setup.' : '\nUse wirewhy setup to make this your default website.');
    process.exitCode = controller.signal.aborted ? 130 : report.outcome === 'ok' ? 0 : 1;
    return;
  }
  let report;
  if (command === 'check') report = await diagnose(target, options);
  else {
    const input = readFileSync(0, 'utf8');
    if (Buffer.byteLength(input) > 1024 * 1024) throw new Error('Error input must be smaller than 1 MB');
    let error;
    try { error = JSON.parse(input); } catch { throw new Error('Expected an error object as JSON on stdin'); }
    if (!error || typeof error !== 'object' || Array.isArray(error)) throw new Error('Expected an error object as JSON on stdin');
    report = explain(error, { url: options.url });
  }
  const output = `${formatReport(report, options.format)}\n`;
  if (options.output) writeFileSync(options.output, output, { mode: 0o600 });
  else process.stdout.write(output);
  process.exitCode = report.outcome === 'ok' ? 0 : 1;
}

main().catch(error => {
  if (error.name === 'AbortError') { process.stderr.write('\nCancelled.\n'); process.exitCode = 130; return; }
  // Do not echo arbitrary arguments or URLs in parser errors.
  const message = error instanceof RangeError ? 'Invalid timeout. Use an integer from 1 to 60000.' : error.code === 'ERR_INVALID_URL' ? 'Expected a valid HTTP URL.' : error.code ? 'Unable to read or write the requested file.' : error.message;
  console.error(`wirewhy: ${message.includes('Invalid URL') ? 'Expected a valid HTTP URL.' : message}`);
  process.exitCode = 2;
});
