#!/usr/bin/env node
// Encrypt test vectors with asherah-node and write to file.

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const asherah = require(path.join(__dirname, '../../asherah-node/npm'));

const outputFile = process.argv[2];
if (!outputFile) {
  console.error('Usage: node_encrypt.js <output_file>');
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

// Use byte-based encrypt/decrypt for exact binary round-trips.
// plaintext is a Buffer, encrypted_json is the JSON string output.
const testVectors = {
  ascii:    Buffer.from('Hello cross-language test!', 'utf8'),
  utf8:     Buffer.from('Ünïcödé 日本語 🔑', 'utf8'),
  empty:    Buffer.alloc(0),
  binary:   Buffer.from(Array.from({length: 256}, (_, i) => i)),
  '1kb':    crypto.randomBytes(1024),
  '8kb':    crypto.randomBytes(8192),
};

const results = {};
for (const [name, plaintext] of Object.entries(testVectors)) {
  const encrypted = asherah.encrypt('cross-lang-partition', plaintext);
  // encrypted is a Buffer containing the JSON DataRowRecord
  results[name] = {
    plaintext_b64: plaintext.toString('base64'),
    encrypted_json: encrypted.toString('utf8'),
  };
}

asherah.shutdown();

fs.writeFileSync(outputFile, JSON.stringify({
  implementation: 'Node.js',
  vectors: results,
}, null, 2));

process.stderr.write(`  Node.js: encrypted ${Object.keys(results).length} test vectors -> ${outputFile}\n`);
