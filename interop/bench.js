/*
 Benchmarks comparing published asherah (npm) vs local asherah-node (napi-rs)

 Usage:
   npm run setup-local
   npm run bench
*/
const path = require('path');
const fs = require('fs');

let oldAsherah;
try { oldAsherah = require('asherah'); }
catch (e) { console.error('Please `npm install asherah` first.'); process.exit(1); }

let newAsherah;
const npmLoader = path.resolve(__dirname, '..', 'asherah-node', 'npm', 'index.js');
if (fs.existsSync(npmLoader)) {
  newAsherah = require(npmLoader);
} else {
  const dev = path.resolve(__dirname, '..', 'target', 'debug', process.platform === 'win32' ? 'asherah_node.node' : 'asherah_node.node');
  try { newAsherah = require(dev); } catch (e) {
    console.error('Could not find local asherah-node build. Run `npm run setup-local` from interop/.');
    process.exit(1);
  }
}

if (!process.env.STATIC_MASTER_KEY_HEX) {
  process.env.STATIC_MASTER_KEY_HEX = '22'.repeat(32);
}

const cfgNew = {
  serviceName: 'svc',
  productId: 'prod',
  metastore: 'memory',
  kms: 'static',
  enableSessionCaching: false,
};
const cfgOld = {
  ServiceName: 'svc',
  ProductID: 'prod',
  Metastore: 'memory',
  KMS: 'static',
  EnableSessionCaching: false,
};

function benchPair(lib, pid, payloads) {
  const startEnc = process.hrtime.bigint();
  const drrs = payloads.map((p) => lib.encrypt(pid, p));
  const endEnc = process.hrtime.bigint();
  const startDec = process.hrtime.bigint();
  const outs = drrs.map((d) => lib.decrypt(pid, d));
  const endDec = process.hrtime.bigint();
  return {
    encNs: Number(endEnc - startEnc),
    decNs: Number(endDec - startDec),
    outs,
  };
}

function kb(n) { return Buffer.alloc(n, 7); }

function main() {
  oldAsherah.setup(cfgOld);
  newAsherah.setup(cfgNew);
  const pid = 'bench';
  const N = 2000;
  const sizes = [64, 1024, 8*1024];
  for (const size of sizes) {
    const payloads = Array.from({ length: N }, () => kb(size));
    const oldR = benchPair(oldAsherah, pid, payloads);
    const newR = benchPair(newAsherah, pid, payloads);
    const encOldMs = oldR.encNs / 1e6, decOldMs = oldR.decNs / 1e6;
    const encNewMs = newR.encNs / 1e6, decNewMs = newR.decNs / 1e6;
    console.log(`size=${size}B N=${N}`);
    console.log(`  old  encrypt: ${(encOldMs).toFixed(1)} ms (${(N/(encOldMs/1000)).toFixed(0)}/s)`);
    console.log(`  old  decrypt: ${(decOldMs).toFixed(1)} ms (${(N/(decOldMs/1000)).toFixed(0)}/s)`);
    console.log(`  new  encrypt: ${(encNewMs).toFixed(1)} ms (${(N/(encNewMs/1000)).toFixed(0)}/s)`);
    console.log(`  new  decrypt: ${(decNewMs).toFixed(1)} ms (${(N/(decNewMs/1000)).toFixed(0)}/s)`);
  }
  oldAsherah.shutdown();
  newAsherah.shutdown();
}

main();
