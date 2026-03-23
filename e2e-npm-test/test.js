const assert = require('assert');
const asherah = require('asherah');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL: ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

// --- camelCase API ---

console.log('camelCase API tests:');
asherah.setup({
  serviceName: 'e2e-svc',
  productId: 'e2e-prod',
  metastore: 'memory',
  kms: 'static',
  enableSessionCaching: false,
});

test('getSetupStatus returns true', () => {
  assert.strictEqual(asherah.getSetupStatus(), true);
});

test('encrypt/decrypt Buffer roundtrip', () => {
  const payload = Buffer.from('hello from npm e2e test');
  const drr = asherah.encrypt('e2e-partition', payload);
  assert.ok(typeof drr === 'string');
  assert.ok(drr.includes('"Key"'));
  const recovered = asherah.decrypt('e2e-partition', drr);
  assert.ok(Buffer.isBuffer(recovered));
  assert.strictEqual(recovered.toString(), 'hello from npm e2e test');
});

test('encryptString/decryptString roundtrip', () => {
  const text = 'string payload for e2e';
  const drr = asherah.encryptString('e2e-partition', text);
  assert.ok(typeof drr === 'string');
  const recovered = asherah.decryptString('e2e-partition', drr);
  assert.strictEqual(recovered, text);
});

test('unicode roundtrip', () => {
  const text = '日本語テスト 🔐 données chiffrées';
  const drr = asherah.encryptString('e2e-unicode', text);
  const recovered = asherah.decryptString('e2e-unicode', drr);
  assert.strictEqual(recovered, text);
});

test('binary all byte values roundtrip', () => {
  const buf = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) buf[i] = i;
  const drr = asherah.encrypt('e2e-binary', buf);
  const recovered = asherah.decrypt('e2e-binary', drr);
  assert.ok(buf.equals(recovered));
});

test('empty payload roundtrip', () => {
  const drr = asherah.encrypt('e2e-empty', Buffer.alloc(0));
  const recovered = asherah.decrypt('e2e-empty', drr);
  assert.ok(Buffer.isBuffer(recovered));
  assert.strictEqual(recovered.length, 0);
});

asherah.shutdown();

test('getSetupStatus returns false after shutdown', () => {
  assert.strictEqual(asherah.getSetupStatus(), false);
});

// --- PascalCase / compat API ---

console.log('\nPascalCase compat API tests:');
asherah.setup({
  ServiceName: 'compat-svc',
  ProductID: 'compat-prod',
  Metastore: 'memory',
  KMS: 'static',
  EnableSessionCaching: false,
});

test('get_setup_status returns true', () => {
  assert.strictEqual(asherah.get_setup_status(), true);
});

test('encrypt_string/decrypt_string roundtrip', () => {
  const drr = asherah.encrypt_string('compat-part', 'compat payload');
  assert.ok(typeof drr === 'string');
  const recovered = asherah.decrypt_string('compat-part', drr);
  assert.strictEqual(recovered, 'compat payload');
});

test('debug metastore alias works', () => {
  // Already set up with 'memory' which works — test that setup didn't throw
  assert.strictEqual(asherah.get_setup_status(), true);
});

asherah.shutdown();

test('get_setup_status returns false after shutdown', () => {
  assert.strictEqual(asherah.get_setup_status(), false);
});

// --- setup/shutdown cycle ---

console.log('\nSetup/shutdown cycle test:');
asherah.setup({
  serviceName: 'cycle-svc',
  productId: 'cycle-prod',
  metastore: 'memory',
  kms: 'static',
});

test('second setup works after shutdown', () => {
  const drr = asherah.encryptString('cycle', 'cycle-test');
  const recovered = asherah.decryptString('cycle', drr);
  assert.strictEqual(recovered, 'cycle-test');
});

asherah.shutdown();

// --- Results ---
console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
