'use strict';

function redactLog(value) {
  return String(value)
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s"'<>]+/g, match => {
      try { const url = new URL(match); const origin = url.origin === 'null' ? `${url.protocol}//${url.host}` : url.origin; return `${origin}${url.pathname === '/' ? '/' : '/[path]'}${url.search ? '?[redacted]' : ''}`; }
      catch { return '[URL redacted]'; }
    })
    .replace(/((?:request|referer):\s*")[^"]*(")/gi, '$1[redacted]$2')
    .replace(/("(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+)[^\s"]+/g, '$1/[path]')
    .replace(/\b(client:\s*)[^,\s]+/gi, '$1[redacted]')
    .replace(/\b(?:Bearer|Basic)\s+[a-zA-Z0-9+/=._-]+/gi, '[credential redacted]')
    .replace(/\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g, '[token redacted]')
    .replace(/((?:["']?)(?:authorization|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token)(?:["']?)\s*[:=]\s*)[^\r\n]*/gi, '$1[redacted]')
    .replace(/([?&](?:[^=\s&]+)=)[^\s&"']+/g, '$1[redacted]')
    .slice(0, 3000);
}

function logTime(line, timezoneOffsetMinutes = 0) {
  const nginx = line.match(/^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
  if (nginx) return Date.UTC(+nginx[1], +nginx[2] - 1, +nginx[3], +nginx[4], +nginx[5], +nginx[6]) - timezoneOffsetMinutes * 60000;
  const iso = line.match(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/);
  if (iso) {
    const explicitZone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(iso[0]);
    return Date.parse(explicitZone ? iso[0] : `${iso[0].replace(' ', 'T')}Z`) - (explicitZone ? 0 : timezoneOffsetMinutes * 60000);
  }
  const combined = line.match(/\[(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})\]/);
  if (combined) {
    const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].indexOf(combined[2]);
    const offset = (+combined[8] * 60 + +combined[9]) * (combined[7] === '+' ? 1 : -1);
    if (month >= 0) return Date.UTC(+combined[3], month, +combined[1], +combined[4], +combined[5], +combined[6]) - offset * 60000;
  }
  return null;
}

function describeError(line) {
  if (/connect\(\) failed.*connection refused.*upstream/i.test(line)) return { code: 'upstream.refused', summary: 'NGINX could not connect to the upstream app.', next: 'Check the app service and its listening port.' };
  if (/upstream timed out/i.test(line)) return { code: 'upstream.timeout', summary: 'The upstream app did not respond before NGINX timed out.', next: 'Check app logs and slow requests before changing timeouts.' };
  if (/upstream prematurely closed|connection reset by peer.*upstream/i.test(line)) return { code: 'upstream.closed', summary: 'The upstream app closed the connection unexpectedly.', next: 'Check for an app crash, restart, or terminated request.' };
  if (/no space left on device/i.test(line)) return { code: 'disk.full', summary: 'A server operation failed because the disk was full.', next: 'Check disk usage and the affected volume.' };
  if (/out of memory|oom-kill|killed process.*memory/i.test(line)) return { code: 'app.oom', summary: 'The server reported an out-of-memory failure.', next: 'Check memory limits and the app’s memory usage.' };
  if (/permission denied/i.test(line)) return { code: 'server.permission', summary: 'The server could not access a required file or resource.', next: 'Check the owner and permissions of the resource named in the log.' };
  if (/uncaught|unhandled|traceback|(?:Type|Reference|Syntax|Range)Error|\bexception\b/i.test(line)) return { code: 'app.exception', summary: 'The app logged an exception.', next: 'Inspect the error and the stack location shown below.' };
  if (/\[(?:emerg|alert|crit|error)\]|\b(?:fatal|error)\b/i.test(line)) return { code: 'server.error', summary: 'The server logged an error.', next: 'Inspect the matched log entry and service status.' };
  return null;
}

function analyzeLogs(raw, input, probeId) {
  const target = new URL(String(input));
  const hostname = target.hostname.toLowerCase();
  const now = Date.parse(raw.collectedAt) || Date.now();
  const entries = [];
  const issues = [];
  for (const source of raw.logs || []) {
    if (!source.ok) { issues.push(`${redactLog(source.path)}: ${source.reason || 'Log unavailable.'}`); continue; }
    const lines = source.lines || [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const timestamp = logTime(line, raw.timezoneOffsetMinutes);
      if (timestamp !== null && (!Number.isFinite(timestamp) || now - timestamp > 10 * 60000 || timestamp - now > 60000)) continue;
      const hostField = line.match(/(?:\bhost|\bserver):\s*"?([^",\s]+)/i);
      const explicitHost = line.match(/\bhost:\s*"?([^",\s]+)/i);
      const host = (explicitHost?.[1] || hostField?.[1] || '').toLowerCase().replace(/:\d+$/, '');
      if (host && host !== hostname && host !== '_') continue;
      const request = line.match(/(?:request:\s*)?"(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+([^\s"]+)/);
      const matchingPath = request ? request[2].split('?')[0] === target.pathname : false;
      if (request && !matchingPath) continue;
      const exactProbe = Boolean(probeId && line.includes(probeId));
      const isAccess = source.kind === 'nginx-access';
      let description = describeError(line);
      if (isAccess) {
        const status = line.match(/"(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) [^"]*"\s+(\d{3})\b/);
        if (!exactProbe || !status || +status[1] < 400) continue;
        description = { code: 'http.probe', summary: `The diagnostic request returned HTTP ${status[1]}.`, next: 'Use the NGINX or app error entries to investigate the cause.' };
      }
      if (!description) continue;
      const siteMatch = host === hostname || source.siteScoped;
      const nginxServiceError = source.kind === 'nginx-journal' && ['failed', 'inactive'].includes(raw.nginx?.service);
      if (!siteMatch && !exactProbe && !nginxServiceError) continue;
      if (timestamp === null && !source.siteScoped) continue;
      const confidence = isAccess ? 'confirmed' : timestamp === null ? 'unknown' : host === hostname && matchingPath ? 'likely' : 'possible';
      const correlation = exactProbe ? 'probe' : timestamp === null ? 'time-unverified' : host === hostname && matchingPath ? 'site-request' : 'service';
      const context = [line];
      for (let next = i + 1; next < Math.min(lines.length, i + 5); next++) {
        if (!/(?:^\s+(?:at|File|\^)|\s+at\s+\S|Traceback)/.test(lines[next])) break;
        context.push(lines[next]);
      }
      entries.push({ source: redactLog(source.path), kind: source.kind, timestamp: timestamp === null ? null : new Date(timestamp).toISOString(), confidence, correlation,
        code: description.code, summary: description.summary, nextStep: description.next,
        excerpt: context.map(redactLog).join('\n'), score: (isAccess ? 0 : 10) + (confidence === 'likely' ? 5 : confidence === 'possible' ? 3 : 1), epoch: timestamp || 0 });
    }
  }
  entries.sort((a, b) => b.score - a.score || b.epoch - a.epoch);
  const seen = new Set();
  const selected = entries.filter(entry => {
    const key = `${entry.source}|${entry.code}|${entry.code.startsWith('upstream.') ? entry.summary : entry.excerpt}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 6).map(({ score, epoch, ...entry }) => entry);
  return { entries: selected, issues };
}
module.exports = { redactLog, logTime, describeError, analyzeLogs };
