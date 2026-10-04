'use strict';
const { observe, formatReport } = require('./index');
const { appendFileSync } = require('node:fs');
const format = ['json', 'markdown'].includes(process.env.WIREWHY_FORMAT) ? process.env.WIREWHY_FORMAT : 'text';
const installed = Symbol.for('wirewhy.register');
if (!globalThis[installed]) {
  globalThis[installed] = observe({
    includeSuccessful: process.env.WIREWHY_ALL === '1',
    onReport: report => {
      if (process.env.WIREWHY_OUTPUT) {
        try { appendFileSync(process.env.WIREWHY_OUTPUT, `${JSON.stringify(report)}\n`, { mode: 0o600 }); }
        catch { process.stderr.write('wirewhy: unable to write report file\n'); }
      } else process.stderr.write(`${formatReport(report, format)}\n`);
    }
  });
}
