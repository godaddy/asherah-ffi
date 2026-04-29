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
  if (!fs.existsSync(candidate)) continue;
  try {
    addon = require(candidate);
    break;
  } catch (err) {
    if (err.code === 'MODULE_NOT_FOUND' || err.code === 'ERR_MODULE_NOT_FOUND' || err.code === 'ERR_DLOPEN_FAILED') continue;
    throw err;
  }
}
if (!addon) {
  throw new Error('Could not locate compiled asherah-node addon. Run `npm run build` first.');
}

function baseConfig(extra) {
  return Object.assign({
    serviceName: 'svc',
    productId: 'prod',
    metastore: 'memory',
    kms: 'static',
    enableSessionCaching: true,
    staticMasterKeyHex: '22'.repeat(32),
  }, extra || {});
}

function roundTripUnderEvictionChurn() {
  addon.setup(baseConfig({ sessionCacheMaxSize: 4 }));
  try {
    for (let i = 0; i < 64; i++) {
      const partition = `churn-${i}`;
      const payload = `payload-${i}`;
      const ct = addon.encryptString(partition, payload);
      assert.strictEqual(addon.decryptString(partition, ct), payload);
    }
  } finally {
    addon.shutdown();
  }
}

function hotPartitionsRoundTripRepeatedly() {
  addon.setup(baseConfig({ sessionCacheMaxSize: 2 }));
  try {
    for (let i = 0; i < 16; i++) {
      const ctA = addon.encryptString('hot-a', 'a');
      assert.strictEqual(addon.decryptString('hot-a', ctA), 'a');
      const ctB = addon.encryptString('hot-b', 'b');
      assert.strictEqual(addon.decryptString('hot-b', ctB), 'b');
    }
  } finally {
    addon.shutdown();
  }
}

function defaultBoundRoundTripsPastThousand() {
  addon.setup(baseConfig());
  try {
    for (let i = 0; i < 1100; i++) {
      const partition = `default-${i}`;
      const payload = `p${i}`;
      const ct = addon.encryptString(partition, payload);
      assert.strictEqual(addon.decryptString(partition, ct), payload);
    }
  } finally {
    addon.shutdown();
  }
}

function sessionCachingDisabledRoundTrips() {
  addon.setup(baseConfig({ enableSessionCaching: false }));
  try {
    for (let i = 0; i < 8; i++) {
      const ct = addon.encryptString(`nocache-${i}`, 'x');
      assert.strictEqual(addon.decryptString(`nocache-${i}`, ct), 'x');
    }
  } finally {
    addon.shutdown();
  }
}

roundTripUnderEvictionChurn();
console.log('asherah-node session-cache eviction churn OK');
hotPartitionsRoundTripRepeatedly();
console.log('asherah-node session-cache hot-partition reuse OK');
defaultBoundRoundTripsPastThousand();
console.log('asherah-node session-cache default-bound past-1000 OK');
sessionCachingDisabledRoundTrips();
console.log('asherah-node session-cache disabled-caching round-trip OK');
