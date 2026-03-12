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
  // --- Native camelCase API tests ---
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

  // --- Canonical godaddy/asherah-node compat API tests ---

  // Test PascalCase config with debug aliases
  addon.setup({
    ServiceName: 'compat-svc',
    ProductID: 'compat-prod',
    Metastore: 'test-debug-memory',
    KMS: 'test-debug-static',
    EnableSessionCaching: false,
  });
  assert.strictEqual(addon.get_setup_status(), true);

  // Test snake_case encrypt/decrypt aliases
  const compat_drr = addon.encrypt_string('cp1', 'compat-payload');
  assert.ok(typeof compat_drr === 'string' && compat_drr.includes('"Key"'));
  const compat_out = addon.decrypt_string('cp1', compat_drr);
  assert.strictEqual(compat_out, 'compat-payload');

  addon.shutdown();
  assert.strictEqual(addon.get_setup_status(), false);
  console.log('asherah-node compat API OK');

  // --- Test PascalCase config with standard values ---
  addon.setup({
    ServiceName: 'std-svc',
    ProductID: 'std-prod',
    Metastore: 'memory',
    KMS: 'static',
    EnableSessionCaching: false,
    // Go-specific fields should be silently ignored
    DisableZeroCopy: true,
    NullDataCheck: true,
  });
  const std_drr = addon.encryptString('sp1', 'standard');
  const std_out = addon.decryptString('sp1', std_drr);
  assert.strictEqual(std_out, 'standard');
  addon.shutdown();
  console.log('asherah-node PascalCase standard config OK');

  // --- Test set_max_stack_alloc_item_size and set_safety_padding_overhead ---
  addon.set_max_stack_alloc_item_size(2048);
  addon.set_safety_padding_overhead(256);
  console.log('asherah-node compat stubs OK');

  // --- FFI boundary tests ---
  testFfiBoundary();
}

function testFfiBoundary() {
  const cfg = {
    serviceName: 'ffi-test',
    productId: 'prod',
    metastore: 'memory',
    kms: 'static',
    enableSessionCaching: false,
  };
  addon.setup(cfg);

  const pid = 'ffi-boundary';

  // Unicode: CJK
  const cjk = '你好世界こんにちは세계';
  const cjkDrr = addon.encryptString(pid, cjk);
  assert.strictEqual(addon.decryptString(pid, cjkDrr), cjk);

  // Unicode: Emoji
  const emoji = '🦀🔐🎉💾🌍';
  const emojiDrr = addon.encryptString(pid, emoji);
  assert.strictEqual(addon.decryptString(pid, emojiDrr), emoji);

  // Unicode: Mixed scripts
  const mixed = 'Hello 世界 مرحبا Привет 🌍';
  const mixedDrr = addon.encryptString(pid, mixed);
  assert.strictEqual(addon.decryptString(pid, mixedDrr), mixed);

  // Unicode: Combining characters (é as e + combining acute)
  const combining = 'e\u0301 n\u0303 a\u0308';
  const combDrr = addon.encryptString(pid, combining);
  assert.strictEqual(addon.decryptString(pid, combDrr), combining);

  // Unicode: ZWJ emoji sequence (family)
  const family = '👨\u200D👩\u200D👧\u200D👦';
  const familyDrr = addon.encryptString(pid, family);
  assert.strictEqual(addon.decryptString(pid, familyDrr), family);

  console.log('asherah-node unicode roundtrip OK');

  // Binary: all 256 byte values (Buffer roundtrip)
  const allBytes = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) allBytes[i] = i;
  const binDrr = addon.encrypt(pid, allBytes);
  const binRecovered = addon.decrypt(pid, binDrr);
  assert.ok(Buffer.isBuffer(binRecovered), 'decrypt should return Buffer');
  assert.strictEqual(binRecovered.length, 256, 'all 256 bytes should survive');
  for (let i = 0; i < 256; i++) {
    assert.strictEqual(binRecovered[i], i, `byte ${i} mismatch`);
  }
  console.log('asherah-node binary 0x00-0xFF roundtrip OK');

  // Empty payload
  const emptyDrr = addon.encrypt(pid, Buffer.alloc(0));
  const emptyRecovered = addon.decrypt(pid, emptyDrr);
  assert.strictEqual(emptyRecovered.length, 0, 'empty payload roundtrip');
  console.log('asherah-node empty payload OK');

  // Large payload: 1MB
  const oneMb = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < oneMb.length; i++) oneMb[i] = i % 256;
  const largeDrr = addon.encrypt(pid, oneMb);
  const largeRecovered = addon.decrypt(pid, largeDrr);
  assert.strictEqual(largeRecovered.length, oneMb.length, '1MB length mismatch');
  assert.ok(oneMb.equals(largeRecovered), '1MB data mismatch');
  console.log('asherah-node 1MB payload OK');

  // Error: decrypt with invalid JSON
  let caught = false;
  try {
    addon.decrypt(pid, 'not valid json');
  } catch (e) {
    caught = true;
  }
  assert.ok(caught, 'decrypt with invalid JSON should throw');

  // Error: decrypt with wrong partition
  const wrongDrr = addon.encrypt('partition-a', Buffer.from('secret'));
  caught = false;
  try {
    addon.decrypt('partition-b', wrongDrr);
  } catch (e) {
    caught = true;
  }
  assert.ok(caught, 'decrypt with wrong partition should throw');
  console.log('asherah-node error handling OK');

  addon.shutdown();
  console.log('asherah-node FFI boundary tests OK');
}

function testCompatApi() {
  // Load via npm/index.js to get the compat wrapper layer
  const compat = require(path.resolve(__dirname, '../npm/index.js'));

  // Test PascalCase config with canonical metastore/KMS values
  const compatCfg = {
    ServiceName: 'compat-svc',
    ProductID: 'compat-prod',
    Metastore: 'test-debug-memory',
    KMS: 'test-debug-static',
    EnableSessionCaching: false,
  };

  compat.setup(compatCfg);
  assert.strictEqual(compat.get_setup_status(), true, 'get_setup_status should return true after setup');

  // Test snake_case encrypt/decrypt string roundtrip
  const pid = 'compat-partition';
  const drr = compat.encrypt_string(pid, 'compat-payload');
  assert.ok(typeof drr === 'string' && drr.includes('"Key"'));
  const decrypted = compat.decrypt_string(pid, drr);
  assert.strictEqual(decrypted, 'compat-payload');

  compat.shutdown();
  assert.strictEqual(compat.get_setup_status(), false, 'get_setup_status should return false after shutdown');

  console.log('asherah-node compat API OK');
}

main();
testCompatApi();
