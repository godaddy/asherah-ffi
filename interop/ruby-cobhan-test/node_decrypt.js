#!/usr/bin/env node
// Read encrypted test vectors from file and decrypt with asherah-node.

const fs = require('fs');
const path = require('path');

const asherah = require(path.join(__dirname, '../../asherah-node/npm'));

const inputFile = process.argv[2];
if (!inputFile) {
  console.error('Usage: node_decrypt.js <input_file>');
  process.exit(1);
}

const dbPath = process.env.ASHERAH_SQLITE_PATH;
if (!dbPath) {
  console.error('ASHERAH_SQLITE_PATH must be set');
  process.exit(1);
}

asherah.setup({
  serviceName: 'cross-lang-service',
  productId: 'cross-lang-product',
  kms: 'static',
  metastore: 'sqlite',
  connectionString: dbPath,
  enableSessionCaching: true,
});

const data = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
const sourceImpl = data.implementation;
const vectors = data.vectors;

let pass = 0;
let fail = 0;

for (const [name, vec] of Object.entries(vectors)) {
  const expectedPlaintext = Buffer.from(vec.plaintext_b64, 'base64');
  const encryptedJson = vec.encrypted_json;

  try {
    // decrypt takes a JSON string, returns a Buffer
    const decrypted = asherah.decrypt('cross-lang-partition', encryptedJson);

    if (Buffer.compare(decrypted, expectedPlaintext) === 0) {
      console.log(`  PASS  ${sourceImpl} -> Node.js: ${name}`);
      pass++;
    } else {
      console.log(`  FAIL  ${sourceImpl} -> Node.js: ${name} (content mismatch)`);
      console.log(`        expected ${expectedPlaintext.length} bytes, got ${decrypted.length} bytes`);
      fail++;
    }
  } catch (e) {
    console.log(`  FAIL  ${sourceImpl} -> Node.js: ${name} (${e.message})`);
    fail++;
  }
}

asherah.shutdown();

console.log();
console.log(`  ${sourceImpl} -> Node.js: ${pass}/${pass + fail} passed`);
process.exit(fail > 0 ? 1 : 0);
