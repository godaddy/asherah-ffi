/*
 Benchmarks comparing published asherah (npm, Go FFI) vs local asherah-node (napi-rs, Rust)

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

function benchOp(lib, pid, payload, iterations) {
  // Warmup
  const warmup = Math.min(500, Math.floor(iterations / 4));
  for (let i = 0; i < warmup; i++) {
    const drr = lib.encrypt(pid, payload);
    lib.decrypt(pid, drr);
  }

  // Benchmark encrypt
  const startEnc = process.hrtime.bigint();
  let lastDrr;
  for (let i = 0; i < iterations; i++) {
    lastDrr = lib.encrypt(pid, payload);
  }
  const encNs = Number(process.hrtime.bigint() - startEnc);

  // Benchmark decrypt
  const startDec = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    lib.decrypt(pid, lastDrr);
  }
  const decNs = Number(process.hrtime.bigint() - startDec);

  return {
    encUs: encNs / 1000 / iterations,
    decUs: decNs / 1000 / iterations,
  };
}

function pad(s, n) { return s.length >= n ? s : ' '.repeat(n - s.length) + s; }

function main() {
  oldAsherah.setup(cfgOld);
  newAsherah.setup(cfgNew);

  const pid = 'bench';
  const iterations = 5000;
  const sizes = [64, 1024, 8192];

  console.log('=== Node.js Binding Benchmark ===');
  console.log(`    iterations: ${iterations}, warmup: ${Math.min(500, Math.floor(iterations / 4))}\n`);

  const results = [];
  for (const size of sizes) {
    const payload = Buffer.alloc(size, 0x07);
    const oldR = benchOp(oldAsherah, pid, payload, iterations);
    const newR = benchOp(newAsherah, pid, payload, iterations);
    results.push({ size, oldR, newR });
  }

  // Header
  console.log(
    pad('Size', 7) + '  ' +
    pad('Go encrypt', 12) + '  ' + pad('Rust encrypt', 12) + '  ' + pad('Speedup', 8) + '  ' +
    pad('Go decrypt', 12) + '  ' + pad('Rust decrypt', 12) + '  ' + pad('Speedup', 8)
  );
  console.log('-'.repeat(83));

  for (const { size, oldR, newR } of results) {
    const encSpeedup = oldR.encUs / newR.encUs;
    const decSpeedup = oldR.decUs / newR.decUs;
    console.log(
      pad(size + 'B', 7) + '  ' +
      pad(oldR.encUs.toFixed(2) + ' µs', 12) + '  ' + pad(newR.encUs.toFixed(2) + ' µs', 12) + '  ' +
      pad(encSpeedup.toFixed(1) + 'x', 8) + '  ' +
      pad(oldR.decUs.toFixed(2) + ' µs', 12) + '  ' + pad(newR.decUs.toFixed(2) + ' µs', 12) + '  ' +
      pad(decSpeedup.toFixed(1) + 'x', 8)
    );
  }

  console.log('\nGo = canonical godaddy/asherah-node (Go FFI via cobhan)');
  console.log('Rust = asherah-node napi-rs (Rust native)\n');

  oldAsherah.shutdown();
  newAsherah.shutdown();
}

main();
