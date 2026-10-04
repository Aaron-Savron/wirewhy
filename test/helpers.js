'use strict';
const http = require('node:http');
const https = require('node:https');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

async function server(handler, secure = false) {
  const app = secure ? https.createServer({ key: readFileSync(join(__dirname, 'fixtures/key.pem')), cert: readFileSync(join(__dirname, 'fixtures/cert.pem')) }, handler) : http.createServer(handler);
  const sockets = new Set();
  app.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => { app.once('error', reject); app.listen(0, '127.0.0.1', resolve); });
  return {
    app,
    url: `${secure ? 'https' : 'http'}://127.0.0.1:${app.address().port}`,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => app.close(resolve));
    }
  };
}
module.exports = { server };
