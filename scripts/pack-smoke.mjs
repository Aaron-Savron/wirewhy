import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const directory = mkdtempSync(join(tmpdir(), 'wirewhy-package-'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
function run(command, args, cwd = directory) {
  // npm.cmd needs cmd.exe on Windows. Arguments here are controlled by this script.
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', shell: command.endsWith('.cmd'), stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr || `Command exited with ${result.status}`);
  return result.stdout;
}
try {
  const [packed] = JSON.parse(run(npm, ['pack', '--json', '--pack-destination', directory], root));
  assert.ok(!packed.files.some(file => /^(test|node_modules)\/|__pycache__|\.pyc$/.test(file.path)));
  assert.ok(packed.files.some(file => file.path === 'src/server-collector.py'));
  const consumer = join(directory, 'consumer');
  const { mkdirSync } = await import('node:fs');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), '{"name":"wirewhy-smoke","private":true}');
  run(npm, ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', join(directory, packed.filename)], consumer);
  for (const [extension, source] of [
    ['cjs', `const { explain, formatReport } = require('wirewhy'); if (!formatReport(explain({code:'ENOTFOUND'})).includes('Hostname resolution failed')) process.exit(1);`],
    ['mjs', `import { explain, formatReport } from 'wirewhy'; if (!formatReport(explain({code:'ENOTFOUND'})).includes('Hostname resolution failed')) process.exit(1);`]
  ]) {
    const file = join(consumer, `smoke.${extension}`);
    writeFileSync(file, source);
    run(process.execPath, [file], consumer);
  }
  run(process.execPath, ['--require', 'wirewhy/register', '-e', 'console.log("preload works")'], consumer);
  const version = run(process.execPath, [join(consumer, 'node_modules/wirewhy/src/cli.js'), '--version'], consumer).trim();
  const { readFileSync } = await import('node:fs');
  assert.equal(version, JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version);
  const siteSmoke = join(consumer, 'site-smoke.mjs');
  writeFileSync(siteSmoke, `
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { inspectSite, formatSiteReport } from 'wirewhy';
const server = createServer((req, res) => res.end('working page'));
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
try {
  const url = 'http://127.0.0.1:' + server.address().port;
  const report = await inspectSite(url);
  assert.equal(report.availability, 'up');
  assert.ok(formatSiteReport(report).includes('HTTP 200'));
  const config = new URL('./site.json', import.meta.url);
  writeFileSync(config, JSON.stringify({url}));
  const { stdout } = await promisify(execFile)(process.execPath, ['node_modules/wirewhy/src/cli.js'], {
    env: {...process.env, WIREWHY_CONFIG: fileURLToPath(config)}, timeout: 10000
  });
  assert.ok(stdout.includes('HTTP 200'));
} finally { server.closeAllConnections(); server.close(); }
`);
  run(process.execPath, [siteSmoke], consumer);
  copyFileSync(join(root, 'test/types.mts'), join(consumer, 'types.mts'));
  copyFileSync(join(root, 'test/types.cts'), join(consumer, 'types.cts'));
  run(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '--noEmit', '--strict', '--noUncheckedSideEffectImports', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--target', 'es2022', 'types.mts', 'types.cts'], consumer);
  console.log(`Tarball verified: ${packed.files.length} files, CommonJS, ESM, preload, bare CLI, site checks, collector, and TypeScript.`);
} finally {
  rmSync(directory, { recursive: true, force: true });
}
