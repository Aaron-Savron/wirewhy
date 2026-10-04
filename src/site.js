'use strict';
const { randomUUID } = require('node:crypto');
const { diagnose } = require('./diagnose');
const { collectServer, validateServerOptions } = require('./server');
const { analyzeLogs, redactLog } = require('./logs');
const { validUrl, safeUrl } = require('./privacy');

async function inspectSite(input, options = {}) {
  const url = validUrl(input);
  validateServerOptions(options);
  const probeId = `wirewhy-${randomUUID()}`;
  options.onProgress?.('Checking website');
  const website = await diagnose(url, { ...options, method: options.method || 'GET', probeId, readBody: true });
  const status = website.request.status;
  const availability = website.outcome === 'ok' ? 'up' : !website.error && [401, 403].includes(status) ? 'restricted' : 'unavailable';
  let server = null;
  let logs = { entries: [], issues: [] };
  if (options.ssh || options.local) {
    options.onProgress?.(availability === 'unavailable' || options.includeLogs ? 'Checking NGINX and recent site logs' : 'Checking NGINX health');
    const raw = await collectServer(url, { ...options, collectLogs: availability === 'unavailable' || options.includeLogs });
    logs = analyzeLogs(raw, url, probeId);
    server = {
      location: options.ssh || 'local',
      error: raw.error || null,
      nginx: raw.nginx ? { ...raw.nginx, configError: raw.nginx.configError ? redactLog(raw.nginx.configError) : null } : null,
      app: raw.app || null,
      issues: [...(raw.issues || []), ...logs.issues]
    };
  }
  const report = { kind: 'site', schemaVersion: 1, timestamp: new Date().toISOString(), url: safeUrl(url), availability, website, server, logs: logs.entries };
  const degraded = server?.nginx?.config === 'invalid' || server?.nginx?.process === 'stopped' || server?.nginx?.service === 'failed' || ['failed', 'inactive'].includes(server?.app?.state);
  report.outcome = availability === 'up' && !degraded ? 'ok' : 'failed';
  report.complete = Boolean(server && !server.error && server.nginx?.installed && server.nginx?.siteMatched
    && server.nginx?.config !== 'unavailable' && !['unknown', 'unavailable'].includes(server.nginx?.service)
    && !['unknown', 'unavailable'].includes(server.app?.state) && !server.issues.length);
  return report;
}

function formatSiteReport(report, format = 'text', color = false) {
  if (format === 'json') return JSON.stringify(report, null, 2);
  if (!['text', 'markdown'].includes(format)) throw new TypeError('Format must be text, json, or markdown');
  const paint = (text, code) => color && format === 'text' ? `\x1b[${code}m${text}\x1b[0m` : text;
  const badge = report.availability === 'up' ? paint('UP', 32) : report.availability === 'restricted' ? paint('RESTRICTED', 33) : paint('UNAVAILABLE', 31);
  const lines = [`Wirewhy  ${badge}  ${report.url}`, ''];
  const request = report.website.request;
  lines.push(`Website   ${request.status ? `HTTP ${request.status}${report.website.error ? '; response failed' : ''}` : report.website.error?.codes.join(', ') || 'Request failed'}${request.durationMs !== undefined ? `  (${request.durationMs} ms)` : ''}`);
  if (report.server) {
    lines.push(`Server    ${report.server.location}`);
    if (report.server.error) lines.push(`NGINX     Unchecked: ${report.server.error}`);
    else if (report.server.nginx) {
      const nginx = report.server.nginx;
      lines.push(`NGINX     ${nginx.installed ? `${nginx.process}; unit ${nginx.service}; config ${nginx.config}` : 'Not installed'}${nginx.version ? `  (${nginx.version})` : ''}`);
      if (nginx.configError) lines.push('', 'Config check:', ...nginx.configError.split('\n').filter(Boolean).map(line => `  ${line}`));
      if (report.server.app) lines.push(`App       ${report.server.app.service}: ${report.server.app.state}${report.server.app.discovered ? ' (discovered from the upstream port)' : ''}`);
      if (!nginx.siteMatched) lines.push('Site      No matching server_name found in the inspected config.');
    }
  }
  for (const finding of report.website.findings) {
    lines.push('', `[${finding.confidence}] ${finding.summary}`);
    if (finding.nextSteps[0]) lines.push(`  Next: ${finding.nextSteps[0]}`);
  }
  if (report.logs.length) {
    lines.push('', report.availability === 'up' ? 'Recent errors (the website currently responds):' : 'Relevant log evidence:');
    for (const entry of report.logs) {
      lines.push('', `[${entry.confidence}] ${entry.summary}`, `  ${entry.source}${entry.timestamp ? `  ${entry.timestamp}` : '  (time unverified)'}`);
      if (entry.correlation === 'service') lines.push('  Recent service error; not matched to this individual request.');
      for (const line of entry.excerpt.split('\n')) lines.push(`  | ${line}`);
      lines.push(`  Next: ${entry.nextStep}`);
    }
  } else if (report.availability === 'unavailable') {
    lines.push('', report.server ? 'No matching recent error log was found.' : 'Add --ssh <host> or --local to inspect NGINX and site logs.');
  }
  const issues = report.server?.issues || [];
  if (issues.length) lines.push('', 'Could not inspect:', ...issues.map(issue => `  ${issue}`));
  if (report.server?.error || issues.length || (report.server && !report.complete)) lines.push('', 'Website status is measured; server evidence is incomplete.');
  if (report.logs.length) lines.push('', 'Logs are redacted. Time and site matches indicate relevance, not proof of causation.');
  const output = lines.join('\n');
  return format === 'markdown' ? `\`\`\`text\n${output}\n\`\`\`` : output;
}
module.exports = { inspectSite, formatSiteReport };
