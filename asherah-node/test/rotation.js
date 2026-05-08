// Rotation, revocation, and sync↔async interop tests for the
// asherah-node binding.
//
// The Rust core has comprehensive rotation/revocation coverage in
// asherah/tests/. The Node binding had **zero** rotation tests —
// `roundtrip.js` and `e2e-consumer.js` only check happy-path
// encrypt/decrypt. Without these tests, an FFI marshalling bug or a
// Node-specific config-mapping regression that breaks key rotation
// would slip through.
//
// Tests are kept minimal and avoid requiring Docker — `metastore: 'memory'`
// + `kms: 'test-debug-static'` produces a hermetic factory.

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
// Prefer the freshly-built `../index.node` over `../npm/index.js`
// because npm/index.js falls back to npm/<platform>/ binaries which
// are stale during local development. CI builds populate
// `npm/<platform>/` from artifacts, so the npm/index.js candidate
// remains last for that path.
candidates.push(
  path.resolve(__dirname, '../target/debug', binaryName),
  path.resolve(__dirname, '../target/release', binaryName),
  path.resolve(__dirname, '../../target/debug', binaryName),
  path.resolve(__dirname, '../../target/release', binaryName),
  path.resolve(__dirname, '../index.node'),
  path.resolve(__dirname, '../npm/index.js'),
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
if (!addon) throw new Error('Could not locate compiled asherah-node addon. Run `npm run build` first.');

// Pull `Key.ParentKeyMeta.Created` out of a DRR JSON string. The
// Rust core uses Pascal-cased JSON field names for cross-language
// compatibility with the Go reference.
function ikCreated(drrJson) {
  const drr = JSON.parse(drrJson);
  assert.ok(drr.Key && drr.Key.ParentKeyMeta, `DRR missing Key.ParentKeyMeta: ${drrJson}`);
  return drr.Key.ParentKeyMeta.Created;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function setupShortExpiry(suffix) {
  // Use a unique service/product per test to avoid sharing the
  // process-global metastore / SK cache across tests within one
  // setup/shutdown cycle.
  addon.setup({
    serviceName: `rot-${suffix}-svc`,
    productId: `rot-${suffix}-prod`,
    metastore: 'memory',
    kms: 'test-debug-static',
    expireAfter: 1,
    checkInterval: 1,
    enableSessionCaching: false,
  });
}

// ──────────── Sync rotation ────────────

async function testSyncRotation() {
  // "sync rotation" refers to the sync encrypt/decrypt API; the wait
  // between encrypts uses an async sleep so the event loop yields and
  // CI timing is deterministic. Earlier versions used a busy-wait,
  // which made first/second encrypt timestamps unstable on slow Linux
  // CI runners.
  setupShortExpiry('sync');
  try {
    const drr1 = addon.encrypt('p1', Buffer.from('before'));
    const ik1 = ikCreated(drr1);

    await sleep(3000);

    const drr2 = addon.encrypt('p1', Buffer.from('after'));
    const ik2 = ikCreated(drr2);

    assert.ok(
      ik2 > ik1,
      `expected IK rotation across expiry: ik2=${ik2} should be > ik1=${ik1}`,
    );
    assert.strictEqual(addon.decrypt('p1', Buffer.from(drr1)).toString(), 'before');
    assert.strictEqual(addon.decrypt('p1', Buffer.from(drr2)).toString(), 'after');
    console.log('asherah-node sync rotation OK');
  } finally {
    addon.shutdown();
  }
}

// ──────────── Async rotation ────────────

async function testAsyncRotation() {
  setupShortExpiry('async');
  try {
    const drr1 = await addon.encryptAsync('p1', Buffer.from('before-async'));
    const ik1 = ikCreated(drr1);

    await sleep(3000);

    const drr2 = await addon.encryptAsync('p1', Buffer.from('after-async'));
    const ik2 = ikCreated(drr2);

    assert.ok(
      ik2 > ik1,
      `async path must rotate IK across expiry: ik2=${ik2} should be > ik1=${ik1}`,
    );
    assert.strictEqual(
      (await addon.decryptAsync('p1', Buffer.from(drr1))).toString(),
      'before-async',
    );
    assert.strictEqual(
      (await addon.decryptAsync('p1', Buffer.from(drr2))).toString(),
      'after-async',
    );
    console.log('asherah-node async rotation OK');
  } finally {
    await addon.shutdownAsync();
  }
}

// ──────────── Sync↔async interop after rotation ────────────

async function testSyncAsyncInteropAfterRotation() {
  setupShortExpiry('interop');
  try {
    const drrSyncPre = addon.encrypt('p1', Buffer.from('sync-pre'));
    const drrAsyncPre = await addon.encryptAsync('p1', Buffer.from('async-pre'));

    await sleep(3000);

    const drrSyncPost = addon.encrypt('p1', Buffer.from('sync-post'));
    const drrAsyncPost = await addon.encryptAsync('p1', Buffer.from('async-post'));

    // Confirm rotation happened — at least one of the post-DRRs has
    // a strictly newer IK than the pre-DRRs.
    const preMax = Math.max(ikCreated(drrSyncPre), ikCreated(drrAsyncPre));
    const postMin = Math.min(ikCreated(drrSyncPost), ikCreated(drrAsyncPost));
    assert.ok(
      postMin > preMax,
      `interop path must rotate: postMin=${postMin} should be > preMax=${preMax}`,
    );

    // 8 round-trips: every encrypt × every decrypt path.
    const cases = [
      [drrSyncPre, 'sync-pre'],
      [drrAsyncPre, 'async-pre'],
      [drrSyncPost, 'sync-post'],
      [drrAsyncPost, 'async-post'],
    ];
    for (const [drr, expected] of cases) {
      assert.strictEqual(
        addon.decrypt('p1', Buffer.from(drr)).toString(),
        expected,
        `sync decrypt of ${expected} after rotation`,
      );
      assert.strictEqual(
        (await addon.decryptAsync('p1', Buffer.from(drr))).toString(),
        expected,
        `async decrypt of ${expected} after rotation`,
      );
    }
    console.log('asherah-node sync/async interop after rotation OK');
  } finally {
    await addon.shutdownAsync();
  }
}

// ──────────── Multiple rotation cycles ────────────

async function testMultipleRotationCycles() {
  setupShortExpiry('multi');
  try {
    const history = [];
    for (let i = 0; i < 3; i += 1) {
      const payload = `cycle-${i}`;
      const drr = await addon.encryptAsync('p1', Buffer.from(payload));
      history.push({ drr, payload, ik: ikCreated(drr) });
      await sleep(3000);
    }
    // Each cycle's IK must be strictly newer than the previous.
    for (let i = 1; i < history.length; i += 1) {
      assert.ok(
        history[i].ik > history[i - 1].ik,
        `cycle ${i}: ik=${history[i].ik} should be > prev ik=${history[i - 1].ik}`,
      );
    }
    // Every historical DRR still decrypts.
    for (const { drr, payload } of history) {
      assert.strictEqual(
        (await addon.decryptAsync('p1', Buffer.from(drr))).toString(),
        payload,
      );
    }
    console.log('asherah-node multiple rotation cycles OK');
  } finally {
    await addon.shutdownAsync();
  }
}

async function main() {
  await testSyncRotation();
  await testAsyncRotation();
  await testSyncAsyncInteropAfterRotation();
  await testMultipleRotationCycles();
  console.log('asherah-node rotation tests OK');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
