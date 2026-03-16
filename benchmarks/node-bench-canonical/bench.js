#!/usr/bin/env node

const { Bench } = require('tinybench');
const asherah = require('asherah');

process.env.STATIC_MASTER_KEY_HEX ??= '22'.repeat(32);

asherah.setup({
  ServiceName: 'bench-svc',
  ProductID: 'bench-prod',
  Metastore: 'memory',
  KMS: 'static',
  EnableSessionCaching: false,
});

const partition = 'bench-partition';

async function run() {
  for (const size of [64, 1024, 8192]) {
    const payload = Buffer.alloc(size, 0x41);
    const ct = asherah.encrypt(partition, payload);

    // Verify round-trip correctness
    const pt = asherah.decrypt(partition, ct);
    if (!payload.equals(pt)) {
      throw new Error(`Round-trip verification failed for ${size}B`);
    }

    const bench = new Bench({ warmupIterations: 1000, iterations: 5000 });
    bench
      .add(`encrypt ${size}B`, () => { asherah.encrypt(partition, payload); })
      .add(`decrypt ${size}B`, () => { asherah.decrypt(partition, ct); });
    await bench.run();

    console.log(`=== ${size}B ===`);
    for (const task of bench.tasks) {
      const r = task.result;
      const meanNs = r.latency.mean * 1e6;
      const sdNs = r.latency.sd * 1e6;
      console.log(`  ${task.name.padEnd(16)} ${meanNs.toFixed(0).padStart(8)} ns  ±${sdNs.toFixed(0).padStart(6)} ns`);
    }
  }
  asherah.shutdown();
}

run();
