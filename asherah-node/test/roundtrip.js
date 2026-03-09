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
