const asherah = require('asherah');

console.log('Loaded from:', asherah.__binary);
console.log('Exports:', Object.keys(asherah).sort().join(', '));

// Setup with memory metastore
asherah.setup({
  serviceName: 'test-e2e',
  productId: 'test-product',
  metastore: 'memory',
  kms: 'static',
  verbose: false,
});
console.log('Setup OK, status:', asherah.getSetupStatus());

// Roundtrip encrypt/decrypt
const encrypted = asherah.encryptString('partition1', 'hello from beta.6');
console.log('Encrypted:', typeof encrypted === 'string' ? 'JSON string (' + encrypted.length + ' chars)' : typeof encrypted);

const decrypted = asherah.decryptString('partition1', encrypted);
console.log('Decrypted:', decrypted);

if (decrypted !== 'hello from beta.6') {
  console.error('FAIL: roundtrip mismatch');
  process.exit(1);
}

// Test PascalCase compat API
asherah.shutdown();
asherah.setup({
  ServiceName: 'test-compat',
  ProductID: 'compat-product',
  Metastore: 'test-debug-memory',
  KMS: 'test-debug-static',
});
const enc2 = asherah.encrypt_string('part2', 'compat test');
const dec2 = asherah.decrypt_string('part2', enc2);
if (dec2 !== 'compat test') {
  console.error('FAIL: compat roundtrip mismatch');
  process.exit(1);
}
console.log('Compat API OK');

asherah.shutdown();
console.log('ALL TESTS PASSED');
