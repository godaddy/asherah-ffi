#!/usr/bin/env node
/**
 * End-to-end test that simulates a real consumer:
 * - Loads through npm/index.js (the wrapper consumers get via require('asherah'))
 * - Uses normalizeConfig, PascalCase configs, null values
 * - Tests async-from-async patterns (the #1 real-world usage)
 * - Tests the full lifecycle: setup → encrypt → decrypt → shutdown
 * - Tests error paths with useful error messages
 */

const assert = require('assert');
const path = require('path');

// Load through the npm wrapper — same as require('asherah') for consumers
const asherah = require(path.resolve(__dirname, '../npm/index.js'));

async function main() {
  console.log('=== E2E Consumer Tests ===');
  console.log('Loaded module exports:', Object.keys(asherah).sort().join(', '));

  // 1. Async setup with minimal config (most common consumer pattern)
  await testMinimalAsyncSetup();

  // 2. PascalCase config with null optional fields
  await testPascalCaseWithNulls();

  // 3. Full config with all fields populated
  await testFullConfig();

  // 4. Concurrent async encrypt/decrypt across partitions
  await testConcurrentAsync();

  // 5. Error messages are useful
  testErrorMessages();

  // 6. Setup/shutdown cycle (consumers restart services)
  await testSetupShutdownCycle();

  // 7. Sync/async interop — encrypt sync, decrypt async and vice versa
  await testSyncAsyncInterop();

  // 8. Heavy concurrent async — 100 simultaneous operations
  await testHeavyConcurrentAsync();

  console.log('=== All E2E Consumer Tests Passed ===');
}

async function testMinimalAsyncSetup() {
  // This is how most consumers call it — from an async function
  await asherah.setupAsync({
    serviceName: 'e2e-consumer',
    productId: 'e2e-product',
    metastore: 'memory',
  });

  const encrypted = asherah.encryptString('user-123', 'sensitive data');
  assert.ok(typeof encrypted === 'string', 'encrypted should be string');
  assert.ok(encrypted.length > 10, 'encrypted should have content');

  const decrypted = asherah.decryptString('user-123', encrypted);
  assert.strictEqual(decrypted, 'sensitive data');

  await asherah.shutdownAsync();
  console.log('  PASS: minimal async setup');
}

async function testPascalCaseWithNulls() {
  // Go/Cobhan consumers send PascalCase with null for unused fields
  await asherah.setupAsync({
    ServiceName: 'e2e-pascal',
    ProductID: 'e2e-prod',
    Metastore: 'memory',
    KMS: 'static',
    ConnectionString: null,
    DynamoDBEndpoint: null,
    DynamoDBRegion: null,
    DynamoDBTableName: null,
    SessionCacheMaxSize: null,
    SessionCacheDuration: null,
    ExpireAfter: null,
    CheckInterval: null,
    RegionMap: null,
    PreferredRegion: null,
    EnableRegionSuffix: null,
    EnableSessionCaching: null,
    Verbose: null,
  });

  const drr = asherah.encrypt('partition', Buffer.from('pascal-null-test'));
  assert.ok(typeof drr === 'string');
  const pt = asherah.decrypt('partition', drr);
  assert.strictEqual(pt.toString(), 'pascal-null-test');

  await asherah.shutdownAsync();
  console.log('  PASS: PascalCase config with null values');
}

async function testFullConfig() {
  // All non-AWS config fields set explicitly
  await asherah.setupAsync({
    serviceName: 'e2e-full',
    productId: 'e2e-full-prod',
    metastore: 'memory',
    kms: 'static',
    enableSessionCaching: true,
    sessionCacheMaxSize: 100,
    sessionCacheDuration: 3600,
    expireAfter: 86400,
    checkInterval: 60,
    verbose: false,
    enableRegionSuffix: false,
  });

  const enc = await asherah.encryptStringAsync('full-cfg', 'full-config-test');
  const dec = await asherah.decryptStringAsync('full-cfg', enc);
  assert.strictEqual(dec, 'full-config-test');

  await asherah.shutdownAsync();
  console.log('  PASS: full config with all fields');
}

async function testConcurrentAsync() {
  await asherah.setupAsync({
    serviceName: 'e2e-concurrent',
    productId: 'e2e-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // 10 concurrent encrypt/decrypt across different partitions
  const promises = [];
  for (let i = 0; i < 10; i++) {
    const partition = `partition-${i}`;
    const payload = `concurrent-payload-${i}`;
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
  console.log('  PASS: concurrent async across partitions');
}

function testErrorMessages() {
  // Setup not called — encrypt should give useful error
  let caught = false;
  try {
    asherah.encrypt('part', Buffer.from('test'));
  } catch (e) {
    caught = true;
    assert.ok(e.message.length > 5, `error message should be descriptive, got: "${e.message}"`);
  }
  assert.ok(caught, 'encrypt without setup should throw');

  // Decrypt with garbage JSON
  asherah.setup({
    serviceName: 'err-test',
    productId: 'err-prod',
    metastore: 'memory',
    kms: 'static',
  });
  caught = false;
  try {
    asherah.decrypt('part', 'not-json');
  } catch (e) {
    caught = true;
    assert.ok(e.message.length > 5, `error message should be descriptive, got: "${e.message}"`);
  }
  assert.ok(caught, 'decrypt with bad JSON should throw');
  asherah.shutdown();

  console.log('  PASS: error messages are descriptive');
}

async function testSetupShutdownCycle() {
  // Consumers restart their app — setup/shutdown should work multiple times
  for (let cycle = 0; cycle < 3; cycle++) {
    await asherah.setupAsync({
      serviceName: `cycle-${cycle}`,
      productId: 'cycle-prod',
      metastore: 'memory',
      kms: 'static',
    });

    const enc = await asherah.encryptStringAsync('cycle-p', `cycle-${cycle}`);
    const dec = await asherah.decryptStringAsync('cycle-p', enc);
    assert.strictEqual(dec, `cycle-${cycle}`);

    await asherah.shutdownAsync();
  }
  console.log('  PASS: setup/shutdown cycle x3');
}

async function testSyncAsyncInterop() {
  await asherah.setupAsync({
    serviceName: 'e2e-interop',
    productId: 'e2e-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // Encrypt sync, decrypt async
  const enc1 = asherah.encryptString('interop-p', 'sync-to-async');
  const dec1 = await asherah.decryptStringAsync('interop-p', enc1);
  assert.strictEqual(dec1, 'sync-to-async');

  // Encrypt async, decrypt sync
  const enc2 = await asherah.encryptStringAsync('interop-p', 'async-to-sync');
  const dec2 = asherah.decryptString('interop-p', enc2);
  assert.strictEqual(dec2, 'async-to-sync');

  await asherah.shutdownAsync();
  console.log('  PASS: sync/async interop');
}

async function testHeavyConcurrentAsync() {
  await asherah.setupAsync({
    serviceName: 'e2e-heavy',
    productId: 'e2e-prod',
    metastore: 'memory',
    kms: 'static',
  });

  // 100 concurrent async operations across 20 partitions
  const promises = [];
  for (let i = 0; i < 100; i++) {
    const partition = `heavy-${i % 20}`;
    const payload = `heavy-payload-${i}`;
    promises.push(
      asherah.encryptStringAsync(partition, payload)
        .then(drr => asherah.decryptStringAsync(partition, drr))
        .then(recovered => {
          assert.strictEqual(recovered, payload, `heavy op ${i} roundtrip failed`);
        })
    );
  }
  await Promise.all(promises);

  await asherah.shutdownAsync();
  console.log('  PASS: heavy concurrent async (100 ops, 20 partitions)');
}

main().catch(err => {
  console.error('E2E FAIL:', err);
  process.exit(1);
});
