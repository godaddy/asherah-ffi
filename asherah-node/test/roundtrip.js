const assert = require('assert');
const path = require('path');
const fs = require('fs');
let addon;
const binaryName = 'asherah_node.node';
const targetDir = process.env.NAPI_RS_CARGO_TARGET_DIR || process.env.CARGO_TARGET_DIR;
const candidates = [];

if (targetDir) {
  candidates.push(
    path.resolve(targetDir, 'debug', binaryName),
    path.resolve(targetDir, 'release', binaryName),
  );
}

candidates.push(
  path.resolve(__dirname, '../target/debug', binaryName),
  path.resolve(__dirname, '../target/release', binaryName),
  path.resolve(__dirname, '../../target/debug', binaryName),
  path.resolve(__dirname, '../../target/release', binaryName),
  path.resolve(__dirname, '../npm/index.js'),
  path.resolve(__dirname, '../index.node'),
);
for (const candidate of candidates) {
  if (!fs.existsSync(candidate)) {
    continue;
  }
  try {
    addon = require(candidate);
    break;
  } catch (err) {
    if (err.code === 'MODULE_NOT_FOUND' || err.code === 'ERR_MODULE_NOT_FOUND' || err.code === 'ERR_DLOPEN_FAILED') {
      continue;
    }
    throw err;
  }
}
if (!addon) {
  throw new Error('Could not locate compiled asherah-node addon. Run `npm run build` first.');
}

function main() {
  const cfg = {
    serviceName: 'svc',
    productId: 'prod',
    metastore: 'memory',
    kms: 'static',
    enableSessionCaching: false,
  };
  addon.setup(cfg);
  const pid = 'p1';
  const drr = addon.encrypt(pid, Buffer.from('hello-napi'));
  assert.ok(typeof drr === 'string' && drr.includes('"Key"'));
  const out = addon.decrypt(pid, drr);
  assert.strictEqual(out.toString(), 'hello-napi');

  const drr2 = addon.encryptString(pid, 'string-payload');
  const round = addon.decryptString(pid, drr2);
  assert.strictEqual(round, 'string-payload');

  addon.shutdown();

  addon.setup(cfg);
  const next = addon.encrypt(pid, Buffer.from('second-pass'));
  const recovered = addon.decrypt(pid, next);
  assert.strictEqual(recovered.toString(), 'second-pass');
  addon.shutdown();
  console.log('asherah-node roundtrip OK');
}

main();
