'use strict';
const { diagnose } = require('./diagnose');
const { explain, formatReport } = require('./report');
const { observe } = require('./observe');
const { inspectSite, formatSiteReport } = require('./site');
module.exports = { diagnose, explain, formatReport, observe, inspectSite, formatSiteReport };
