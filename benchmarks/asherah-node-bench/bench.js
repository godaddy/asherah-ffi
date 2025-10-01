#!/usr/bin/env node
/* eslint-disable no-console */

const { performance } = require('perf_hooks');
const asherah = require('asherah-node');

const iterations = Number.parseInt(process.env.BENCH_ITERS ?? '20000', 10);
const payloadSize = Number.parseInt(process.env.BENCH_PAYLOAD ?? '4096', 10);

const config = {
  serviceName: process.env.BENCH_SERVICE ?? 'bench_svc',
  productId: process.env.BENCH_PRODUCT ?? 'bench_prod',
  metastore: 'memory',
  kms: 'static',
  enableSessionCaching: false,
};

process.env.STATIC_MASTER_KEY_HEX ??= '22'.repeat(32);

const partitionId = 'partition-1';
const payload = Buffer.alloc(payloadSize, 0x41);

function formatResult(label, totalMs) {
  const avgUs = (totalMs * 1000) / iterations;
  const opsPerSec = (iterations / totalMs) * 1000;
  return `${label.padEnd(16)} ${avgUs.toFixed(2).padStart(10)} µs | ${opsPerSec.toFixed(0).padStart(8)} ops/s`;
}

function measure(name, fn) {
  const start = performance.now();
  fn();
  const end = performance.now();
  console.log(formatResult(name, end - start));
}

function main() {
  console.log(`# asherah-node benchmark`);
  console.log(`runtime     : ${process.release?.name ?? 'node'} ${process.version}`);
  console.log(`iterations  : ${iterations}`);
  console.log(`payload size: ${payloadSize} bytes\n`);

  asherah.setup(config);

  let lastCipher = '';
  measure('encrypt(bytes)', () => {
    for (let i = 0; i < iterations; i += 1) {
      lastCipher = asherah.encrypt(partitionId, payload);
    }
  });
  measure('decrypt(bytes)', () => {
    for (let i = 0; i < iterations; i += 1) {
      const pt = asherah.decrypt(partitionId, lastCipher);
      if (pt.length !== payload.length) {
        throw new Error('unexpected plaintext length');
      }
    }
  });

  let lastCipherString = '';
  const stringPayload = 'x'.repeat(payloadSize);
  measure('encrypt(string)', () => {
    for (let i = 0; i < iterations; i += 1) {
      lastCipherString = asherah.encryptString(partitionId, stringPayload);
    }
  });

  measure('decrypt(string)', () => {
    for (let i = 0; i < iterations; i += 1) {
      const out = asherah.decryptString(partitionId, lastCipherString);
      if (out.length !== stringPayload.length) {
        throw new Error('unexpected decrypted string');
      }
    }
  });

  asherah.shutdown();
}

main();
