import api = require('wirewhy');
api.diagnose('https://example.com').then(report => api.formatReport(report));
api.observe({ onReport: report => { api.formatReport(report, 'json'); } });
