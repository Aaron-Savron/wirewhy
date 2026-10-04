'use strict';

// Paths can contain reset tokens. Default reports keep only the origin.
function safeUrl(input) {
  try {
    const url = new URL(String(input));
    if (!['http:', 'https:'].includes(url.protocol)) return '[invalid URL]';
    return url.origin;
  } catch { return '[invalid URL]'; }
}

function safeCode(value) {
  return typeof value === 'string' && /^[A-Z][A-Z0-9_]{1,79}$/.test(value) ? value : undefined;
}

function errorCodes(error) {
  const codes = new Set();
  const seen = new Set();
  const queue = [error];
  for (let i = 0; i < queue.length && i < 32; i++) {
    const item = queue[i];
    if (!item || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    const code = safeCode(item.code);
    if (code) codes.add(code);
    if (item.name === 'TimeoutError') codes.add('TIMEOUT');
    if (item.name === 'AbortError') codes.add('ABORTED');
    if (item.cause) queue.push(item.cause);
    if (Array.isArray(item.errors)) queue.push(...item.errors.slice(0, 16));
  }
  return [...codes];
}

function validUrl(input) {
  const url = new URL(String(input));
  if (!['http:', 'https:'].includes(url.protocol)) throw new TypeError('Expected an http:// or https:// URL');
  if (url.username || url.password) throw new TypeError('URL credentials are not supported');
  return url;
}

module.exports = { safeUrl, errorCodes, validUrl };
