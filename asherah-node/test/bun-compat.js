#!/usr/bin/env bun
/**
 * Bun-specific compatibility tests.
 *
 * Exercises NAPI features that are known to be fragile in Bun:
 * - ThreadsafeFunction callbacks (metrics hook, log hook)
 * - Async operations via napi tokio_rt integration
 * - Heavy concurrent async under Bun's event loop
 * - Buffer interop (Bun uses JavaScriptCore, not V8)
 * - Factory/Session lifecycle under Bun's GC
 *
 * This file is intentionally separate from roundtrip.js/e2e-consumer.js
 * so that Bun-specific failures are immediately visible in CI without
 * blocking the Node.js test results.
 */

const assert = require('assert');
const path = require('path');

const asherah = require(path.resolve(__dirname, '../npm/index.js'));

const isBun = typeof Bun !== 'undefined';
if (!isBun) {
  console.error('ERROR: bun-compat.js must be run with Bun, not Node.js');
  process.exit(1);
}

console.log(`=== Bun Compatibility Tests (Bun ${Bun.version}) ===`);

async function main() {
  await testSyncRoundtrip();
  await testAsyncRoundtrip();
  await testBufferInterop();
  await testThreadsafeMetricsHook();
  await testThreadsafeLogHook();
  await testConcurrentAsync();
  await testHeavyConcurrentAsync();
  await testSetupShutdownCycles();
  await testFactorySessionLifecycle();
  await testSyncAsyncInterop();
  await testLargePayloads();

  console.log('=== All Bun Compatibility Tests Passed ===');
}

async function testSyncRoundtrip() {
  asherah.setup({
    serviceName: 'bun-sync',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
  });

  const drr = asherah.encryptString('p1', 'bun-sync-test');
  assert.ok(typeof drr === 'string' && drr.includes('"Key"'));
  const recovered = asherah.decryptString('p1', drr);
  assert.strictEqual(recovered, 'bun-sync-test');

  // Buffer API
  const bufDrr = asherah.encrypt('p1', Buffer.from('bun-buffer'));
  const bufOut = asherah.decrypt('p1', bufDrr);
  assert.ok(Buffer.isBuffer(bufOut));
  assert.strictEqual(bufOut.toString(), 'bun-buffer');

  asherah.shutdown();
  console.log('  PASS: sync roundtrip');
}

async function testAsyncRoundtrip() {
  await asherah.setupAsync({
    serviceName: 'bun-async',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // String async
  const drr = await asherah.encryptStringAsync('p1', 'bun-async-test');
  assert.ok(typeof drr === 'string' && drr.includes('"Key"'));
  const recovered = await asherah.decryptStringAsync('p1', drr);
  assert.strictEqual(recovered, 'bun-async-test');

  // Buffer async
  const bufDrr = await asherah.encryptAsync('p1', Buffer.from('bun-async-buf'));
  const bufOut = await asherah.decryptAsync('p1', bufDrr);
  assert.ok(Buffer.isBuffer(bufOut));
  assert.strictEqual(bufOut.toString(), 'bun-async-buf');

  await asherah.shutdownAsync();
  console.log('  PASS: async roundtrip');
}

async function testBufferInterop() {
  // Bun uses JavaScriptCore — Buffer behavior may differ from V8
  asherah.setup({
    serviceName: 'bun-buffer',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // All 256 byte values
  const allBytes = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) allBytes[i] = i;
  const binDrr = asherah.encrypt('p1', allBytes);
  const binOut = asherah.decrypt('p1', binDrr);
  assert.ok(Buffer.isBuffer(binOut));
  assert.strictEqual(binOut.length, 256);
  for (let i = 0; i < 256; i++) {
    assert.strictEqual(binOut[i], i, `byte ${i} mismatch`);
  }

  // Empty buffer
  const emptyDrr = asherah.encrypt('p1', Buffer.alloc(0));
  const emptyOut = asherah.decrypt('p1', emptyDrr);
  assert.strictEqual(emptyOut.length, 0);

  // Uint8Array (not Buffer) — Bun may pass these differently through NAPI
  const u8 = new Uint8Array([1, 2, 3, 4, 5]);
  const u8Drr = asherah.encrypt('p1', Buffer.from(u8));
  const u8Out = asherah.decrypt('p1', u8Drr);
  assert.deepStrictEqual([...u8Out], [1, 2, 3, 4, 5]);

  asherah.shutdown();
  console.log('  PASS: buffer interop (all bytes, empty, Uint8Array)');
}

async function testThreadsafeMetricsHook() {
  // ThreadsafeFunction is the #1 NAPI feature that breaks in Bun.
  // Metrics hook registration/deregistration must not crash.
  // Note: metrics events only fire when metrics are enabled at the factory
  // level (a separate concern), so we just verify the hook lifecycle is safe.
  const events = [];
  asherah.setMetricsHook(function (event) {
    events.push(event);
  });

  asherah.setup({
    serviceName: 'bun-metrics',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
  });

  const drr = asherah.encryptString('p1', 'metrics-test');
  asherah.decryptString('p1', drr);

  await new Promise(resolve => setTimeout(resolve, 100));

  asherah.shutdown();
  asherah.setMetricsHook(null);
  console.log(`  PASS: ThreadsafeFunction metrics hook lifecycle (${events.length} events)`);
}

async function testThreadsafeLogHook() {
  // Log hook uses ThreadsafeFunction to deliver log events from Rust threads.
  // With verbose=true, we should receive log messages from the setup path.
  const logMessages = [];
  asherah.set_log_hook(function (event) {
    logMessages.push(event);
  });

  asherah.setup({
    serviceName: 'bun-log',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
    verbose: true,
  });

  const drr = asherah.encryptString('p1', 'log-test');
  asherah.decryptString('p1', drr);

  // Give ThreadsafeFunction callbacks time to fire
  await new Promise(resolve => setTimeout(resolve, 200));

  // Log hook should receive messages — verifies ThreadsafeFunction works in Bun
  assert.ok(logMessages.length > 0,
    `expected log messages with verbose=true, got ${logMessages.length} (ThreadsafeFunction may be broken)`);

  asherah.shutdown();
  asherah.set_log_hook(null);
  console.log(`  PASS: ThreadsafeFunction log hook (${logMessages.length} messages received)`);
}

async function testConcurrentAsync() {
  await asherah.setupAsync({
    serviceName: 'bun-concurrent',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // 20 concurrent encrypt/decrypt across different partitions
  const promises = [];
  for (let i = 0; i < 20; i++) {
    const partition = `part-${i}`;
    const payload = `concurrent-${i}`;
    promises.push(
      asherah.encryptStringAsync(partition, payload)
        .then(drr => asherah.decryptStringAsync(partition, drr))
        .then(recovered => {
          assert.strictEqual(recovered, payload, `partition ${i} roundtrip failed`);
        })
    );
  }
  await Promise.all(promises);

  await asherah.shutdownAsync();
  console.log('  PASS: concurrent async (20 partitions)');
}

async function testHeavyConcurrentAsync() {
  // This is the stress test — 200 concurrent operations.
  // Bun's event loop integration with napi tokio_rt is the concern.
  await asherah.setupAsync({
    serviceName: 'bun-heavy',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
    enableSessionCaching: true,
  });

  const promises = [];
  for (let i = 0; i < 200; i++) {
    const partition = `heavy-${i % 25}`;
    const payload = `heavy-${i}`;
    promises.push(
      asherah.encryptStringAsync(partition, payload)
        .then(drr => asherah.decryptStringAsync(partition, drr))
        .then(recovered => {
          assert.strictEqual(recovered, payload, `heavy op ${i} failed`);
        })
    );
  }
  await Promise.all(promises);

  await asherah.shutdownAsync();
  console.log('  PASS: heavy concurrent async (200 ops, 25 partitions)');
}

async function testSetupShutdownCycles() {
  // Rapid setup/shutdown — tests that Bun properly releases NAPI resources
  for (let i = 0; i < 5; i++) {
    await asherah.setupAsync({
      serviceName: `bun-cycle-${i}`,
      productId: 'bun-prod',
      metastore: 'memory',
      kms: 'static',
    });

    const enc = await asherah.encryptStringAsync('cycle', `cycle-${i}`);
    const dec = await asherah.decryptStringAsync('cycle', enc);
    assert.strictEqual(dec, `cycle-${i}`);

    await asherah.shutdownAsync();
  }
  console.log('  PASS: setup/shutdown cycles x5');
}

async function testFactorySessionLifecycle() {
  // Factory/Session API with explicit close() — tests reference tracking under Bun's GC
  const factory = new asherah.SessionFactory({
    serviceName: 'bun-factory',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // Multiple sessions
  const sessions = [];
  for (let i = 0; i < 5; i++) {
    sessions.push(factory.getSession(`fs-${i}`));
  }

  // Encrypt with each session
  const drrs = [];
  for (let i = 0; i < sessions.length; i++) {
    drrs.push(sessions[i].encrypt(Buffer.from(`session-${i}`)));
  }

  // Decrypt with each session
  for (let i = 0; i < sessions.length; i++) {
    const out = sessions[i].decrypt(drrs[i]);
    assert.strictEqual(out.toString(), `session-${i}`);
  }

  // Close sessions, then factory
  for (const s of sessions) s.close();
  factory.close();

  // Verify closed state
  let caught = false;
  try {
    factory.getSession('after-close');
  } catch (e) {
    caught = true;
  }
  assert.ok(caught, 'getSession after close should throw');

  console.log('  PASS: Factory/Session lifecycle');
}

async function testSyncAsyncInterop() {
  await asherah.setupAsync({
    serviceName: 'bun-interop',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // Encrypt sync, decrypt async
  const enc1 = asherah.encryptString('interop', 'sync-to-async');
  const dec1 = await asherah.decryptStringAsync('interop', enc1);
  assert.strictEqual(dec1, 'sync-to-async');

  // Encrypt async, decrypt sync
  const enc2 = await asherah.encryptStringAsync('interop', 'async-to-sync');
  const dec2 = asherah.decryptString('interop', enc2);
  assert.strictEqual(dec2, 'async-to-sync');

  // Encrypt sync buffer, decrypt async buffer
  const enc3 = asherah.encrypt('interop', Buffer.from('buf-sync-async'));
  const dec3 = await asherah.decryptAsync('interop', enc3);
  assert.strictEqual(dec3.toString(), 'buf-sync-async');

  await asherah.shutdownAsync();
  console.log('  PASS: sync/async interop');
}

async function testLargePayloads() {
  asherah.setup({
    serviceName: 'bun-large',
    productId: 'bun-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // 1MB payload — tests buffer handling at scale under Bun
  const oneMb = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < oneMb.length; i++) oneMb[i] = i % 256;
  const largeDrr = asherah.encrypt('p1', oneMb);
  const largeOut = asherah.decrypt('p1', largeDrr);
  assert.strictEqual(largeOut.length, oneMb.length);
  assert.ok(oneMb.equals(largeOut), '1MB data mismatch');

  // 4MB payload — pushes NAPI buffer transfer
  const fourMb = Buffer.alloc(4 * 1024 * 1024);
  for (let i = 0; i < fourMb.length; i++) fourMb[i] = i % 256;
  const xlDrr = asherah.encrypt('p1', fourMb);
  const xlOut = asherah.decrypt('p1', xlDrr);
  assert.strictEqual(xlOut.length, fourMb.length);
  assert.ok(fourMb.equals(xlOut), '4MB data mismatch');

  asherah.shutdown();
  console.log('  PASS: large payloads (1MB, 4MB)');
}

main().catch(err => {
  console.error('BUN COMPAT FAIL:', err);
  process.exit(1);
});
