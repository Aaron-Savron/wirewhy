import { diagnose, explain, formatReport, observe, inspectSite, formatSiteReport, type Report } from 'wirewhy';
import 'wirewhy/register';
const report: Report = await diagnose('https://example.com', { method: 'HEAD', signal: new AbortController().signal });
formatReport(report, 'markdown');
explain(new Error('failure'), { url: new URL('https://example.com'), status: 500 });
const stop = observe({ onReport: async report => { formatReport(report); } });
stop();
const site = await inspectSite('https://example.com', { ssh: 'web', sudo: true, service: 'app.service', logs: ['/var/log/app.log'] });
formatSiteReport(site, 'json');
// @ts-expect-error active checks do not support POST
diagnose('https://example.com', { method: 'POST' });
