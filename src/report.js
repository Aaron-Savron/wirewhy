'use strict';
const { safeUrl, errorCodes } = require('./privacy');
const { runtimeInfo } = require('./runtime');

const TLS_CODES = ['UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_NOT_YET_VALID'];
const finding = (code, confidence, summary, evidence, nextSteps) => ({ code, confidence, summary, evidence, nextSteps });

function classify(report) {
  const { request, runtime, error, checks } = report;
  const codes = error?.codes || [];
  const has = (...values) => values.some(value => codes.includes(value));
  const findings = [];
  if (has('ENOTFOUND', 'EAI_AGAIN')) findings.push(finding('dns.failure', 'confirmed', 'Hostname resolution failed.', codes, ['Check the hostname and the resolver available to this process. EAI_AGAIN can be temporary.']));
  if (has('ECONNREFUSED')) {
    findings.push(finding('connection.refused', 'confirmed', 'A connection attempt was refused.', codes, ['Check that the service listens on the requested address and port.', 'Inside a container, localhost refers to that container.']));
  }
  const v4 = checks?.ipv4;
  const v6 = checks?.ipv6;
  if (v4?.ok && v6?.ok === false && v6.codes?.some(code => ['ECONNREFUSED', 'ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH'].includes(code))) findings.push(finding('network.ipv6', 'likely', 'IPv4 connects but IPv6 does not.', ['IPv4 TCP connection succeeded.', `IPv6 TCP connection failed: ${v6.codes.join(', ')}.`], ['Check the IPv6 route or listener. A TCP comparison does not prove which connection the original request used.']));
  if (has(...TLS_CODES)) {
    const trust = checks?.systemCa;
    if (trust?.ok && checks.defaultTls?.ok === false && checks.defaultTls.codes?.some(code => TLS_CODES.includes(code)) && !runtime.systemCaEnabled) findings.push(finding('tls.trust-store', 'confirmed', 'Default TLS validation failed, but system-CA validation passed.', [...codes, 'Both TLS probes connected to the same resolved address.'], ['Try starting the app with node --use-system-ca, then repeat the request.', 'Review which certificate authorities your app should trust.']));
    else findings.push(finding('tls.validation', 'confirmed', 'TLS certificate validation failed.', codes, [has('CERT_HAS_EXPIRED') ? 'Renew the expired certificate or check the system clock.' : has('ERR_TLS_CERT_ALTNAME_INVALID') ? 'Check that the URL hostname matches the certificate.' : 'Check the certificate chain and the certificate authorities trusted by Node.']));
  }
  if (has('TIMEOUT', 'ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT')) findings.push(finding('request.timeout', 'confirmed', 'The request exceeded a timeout.', codes, ['Identify whether the timeout occurred while connecting, waiting for headers, or reading the body.', 'Compare the observed timeout with the app and HTTP client settings.']));
  if (has('ABORTED')) findings.push(finding('request.aborted', 'confirmed', 'The request was cancelled.', codes, ['Check the caller’s AbortSignal and request lifecycle.']));
  if (has('ECONNRESET', 'EPIPE', 'UND_ERR_SOCKET')) findings.push(finding('connection.closed', 'confirmed', 'The connection closed before the request completed.', codes, ['Check server and proxy logs at the time of failure.', 'If failures follow idle periods, investigate pooled connections and keep-alive settings.']));
  if (has('UND_ERR_INVALID_ARG')) findings.push(finding('client.configuration', 'likely', 'The HTTP client rejected an argument or dispatcher.', codes, ['Check dispatcher configuration and installed Undici versions with npm ls undici.', 'Compare installed Undici versions with the bundled version shown in this report.']));
  if (runtime.proxyConfigured && !runtime.proxyEnvEnabled && !runtime.noProxyMatch && report.outcome === 'failed') findings.push(finding('proxy.configuration', 'possible', 'Proxy variables are set; native proxy support is not enabled.', ['Proxy environment variables are present.', 'A custom dispatcher may still provide proxy support.'], ['Check whether your HTTP client uses the configured proxy.', 'On supported Node versions, test --use-env-proxy.']));
  if (runtime.extraCaConfigured && runtime.extraCaExists === false) findings.push(finding('tls.extra-ca-missing', 'confirmed', 'The configured extra-CA file is missing.', ['NODE_EXTRA_CA_CERTS points to a file that does not exist.'], ['Check the file mount and NODE_EXTRA_CA_CERTS before starting Node.']));
  if (runtime.tlsVerificationDisabled) findings.push(finding('tls.verification-disabled', 'confirmed', 'TLS verification is disabled for this process.', ['NODE_TLS_REJECT_UNAUTHORIZED=0'], ['Enable certificate validation before treating a successful HTTPS check as proof of trust.']));
  if (request.status >= 400) findings.push(finding(`http.${request.status}`, 'confirmed', `The server returned HTTP ${request.status}.`, [`Response status: ${request.status}`], [request.status === 429 ? 'Check provider rate limits and Retry-After.' : request.status === 401 || request.status === 403 ? 'Check credentials, permissions, and upstream access rules.' : request.status >= 500 ? 'Check upstream service logs and availability.' : 'Check the endpoint, method, and request parameters.']));
  if (report.outcome === 'failed' && findings.length === 0) findings.push(finding('request.unknown', 'unknown', 'The available evidence does not identify the cause.', codes.length ? codes : ['No recognized error code was exposed.'], ['Run wirewhy check against the origin from the same host or container.', 'Capture the failure with wirewhy run for request lifecycle evidence.']));
  return findings;
}

function explain(error, options = {}) {
  const codes = errorCodes(error);
  const report = {
    schemaVersion: 1,
    timestamp: new Date().toISOString(),
    outcome: error ? 'failed' : options.status ? (options.status >= 400 ? 'failed' : 'ok') : 'failed',
    request: { url: safeUrl(options.url), method: /^[A-Z]{1,16}$/.test(options.method || '') ? options.method : 'GET' },
    runtime: options.runtime || runtimeInfo(options.url),
    error: error ? { codes } : null,
    checks: options.checks || {},
    findings: []
  };
  if (options.status) report.request.status = options.status;
  if (Number.isFinite(options.durationMs)) report.request.durationMs = Math.round(options.durationMs);
  report.findings = classify(report);
  return report;
}

function formatReport(report, format = 'text') {
  if (format === 'json') return JSON.stringify(report, null, 2);
  if (!['text', 'markdown'].includes(format)) throw new TypeError('Format must be text, json, or markdown');
  const lines = [`Wirewhy: ${report.outcome === 'ok' ? 'OK' : 'FAILED'} ${report.request.method} ${report.request.url}`, `Node ${report.runtime.node}; Undici ${report.runtime.undici || 'unknown'}; ${report.runtime.platform}/${report.runtime.arch}`];
  if (report.request.status) lines.push(`HTTP ${report.request.status}`);
  if (report.request.durationMs !== undefined) lines.push(`Duration: ${report.request.durationMs} ms`);
  for (const item of report.findings) {
    lines.push('', `[${item.confidence}] ${item.summary}`);
    for (const evidence of item.evidence) lines.push(`  Evidence: ${evidence}`);
    for (const step of item.nextSteps) lines.push(`  Next: ${step}`);
  }
  if (report.findings.length === 0) lines.push('', 'No failure detected by this check.');
  if (Object.keys(report.checks).length) {
    lines.push('', 'Checks:');
    for (const [name, check] of Object.entries(report.checks)) lines.push(`  ${name}: ${check.ok === true ? 'passed' : check.ok === false ? 'failed' : 'skipped'}${check.codes?.length ? ` (${check.codes.join(', ')})` : ''}${check.reason ? ` (${check.reason})` : ''}`);
  }
  lines.push('', 'Report omits URL paths, query strings, headers, bodies, and raw error messages.');
  const text = lines.join('\n');
  return format === 'markdown' ? `\`\`\`text\n${text}\n\`\`\`` : text;
}
module.exports = { explain, classify, formatReport, TLS_CODES };
