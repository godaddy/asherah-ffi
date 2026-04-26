#!/usr/bin/env node
//
// Drive canonical asherah-node 3.0.12 (Go cobhan core) and our Rust addon
// against a shared MySQL metastore so both impls see the same intermediate
// keys. Used to prove wire-level interop with canonical Go core for arbitrary
// payloads — including empty.
//
// Usage:
//   mysql_bidirectional.js <encrypter:legacy|new> <decrypter:legacy|new> <partition> <payload-b64>
//
// Required env:
//   MYSQL_URL      = mysql://user[:pass]@host:port/db   (used by our addon)
//   MYSQL_DSN      = user[:pass]@tcp(host:port)/db      (used by canonical addon)
//   STATIC_MASTER_KEY_HEX = 64-char hex (32-byte AES-256 master key)
//   SERVICE_NAME, PRODUCT_ID
//
// Output: base64-encoded recovered plaintext on stdout, or exits non-zero on
// any error.
'use strict';

const path = require('path');

function loadNewAddon() {
  // Mirror the path search used by node_module_runner.js / interop.js.
  // CI builds the addon via `npm run build` in asherah-node which writes
  // index.node alongside the package. The named binaries (asherah.node,
  // asherah_node.node) live in cargo target dirs depending on build flow.
  const envTarget = process.env.NAPI_RS_CARGO_TARGET_DIR || process.env.CARGO_TARGET_DIR;
  const candidates = [];
  for (const binaryName of ['asherah.node', 'asherah_node.node']) {
    if (envTarget) {
      candidates.push(
        path.resolve(envTarget, 'debug', binaryName),
        path.resolve(envTarget, 'release', binaryName),
      );
    }
    candidates.push(
      path.resolve(__dirname, '..', '..', 'target', 'debug', binaryName),
      path.resolve(__dirname, '..', '..', 'target', 'release', binaryName),
      path.resolve(__dirname, '..', '..', 'asherah-node', 'target', 'debug', binaryName),
      path.resolve(__dirname, '..', '..', 'asherah-node', 'target', 'release', binaryName),
      path.resolve(__dirname, '..', '..', 'asherah-node', 'dist', binaryName),
      path.resolve(__dirname, '..', '..', 'asherah-node', 'npm', binaryName),
    );
  }
  candidates.push(
    path.resolve(__dirname, '..', '..', 'asherah-node', 'index.node'),
    path.resolve(__dirname, '..', '..', 'asherah-node', 'npm', 'index.js'),
  );
  for (const candidate of candidates) {
    try { return require(candidate); } catch (_) {}
  }
  throw new Error(
    'Could not locate compiled asherah-node addon. Searched: ' +
    candidates.join(', ')
  );
}

function loadLegacyAddon() {
  return require(path.resolve(
    __dirname, '..', 'legacy-node', 'node_modules', 'asherah', 'dist', 'asherah.node',
  ));
}

function configForNew() {
  // Both impls default the static master key to the UTF-8 bytes of
  // "thisIsAStaticMasterKeyForTesting" (32 chars) when no key is provided,
  // so we omit staticMasterKeyHex on purpose to match canonical's default.
  return {
    serviceName: process.env.SERVICE_NAME,
    productId: process.env.PRODUCT_ID,
    metastore: 'rdbms',
    connectionString: process.env.MYSQL_URL,
    sqlMetastoreDbType: 'mysql',
    kms: 'static',
    enableSessionCaching: false,
    verbose: false,
  };
}

function configForLegacy() {
  return {
    ServiceName: process.env.SERVICE_NAME,
    ProductID: process.env.PRODUCT_ID,
    Metastore: 'rdbms',
    ConnectionString: process.env.MYSQL_DSN,
    KMS: 'static',
    EnableSessionCaching: false,
    Verbose: false,
  };
}

function setup(flavour) {
  if (flavour === 'legacy') {
    const addon = loadLegacyAddon();
    addon.setup(configForLegacy());
    return addon;
  }
  const addon = loadNewAddon();
  addon.setup(configForNew());
  return addon;
}

function teardown(addon) {
  if (addon && typeof addon.shutdown === 'function') addon.shutdown();
}

function main() {
  if (process.argv.length < 6) {
    console.error('Usage: mysql_bidirectional.js <encrypter> <decrypter> <partition> <payload-b64>');
    process.exit(2);
  }
  const encrypter = process.argv[2];
  const decrypter = process.argv[3];
  const partition = process.argv[4];
  const payload = Buffer.from(process.argv[5], 'base64');

  // Step 1: encrypter setups, encrypts, shuts down. The IK is now persisted
  // in MySQL and is visible to any other addon configured with the same
  // ServiceName/ProductID/master-key/MySQL.
  const encAddon = setup(encrypter);
  let ciphertextBytes;
  try {
    const ct = encAddon.encrypt(partition, Buffer.from(payload));
    ciphertextBytes = typeof ct === 'string' ? Buffer.from(ct, 'utf8') : Buffer.from(ct);
  } finally {
    teardown(encAddon);
  }

  // Step 2: decrypter setups (in this same Node process — that's fine because
  // the previous addon was shut down), decrypts the ciphertext.
  const decAddon = setup(decrypter);
  let recovered;
  try {
    recovered = decAddon.decrypt(partition, ciphertextBytes);
  } finally {
    teardown(decAddon);
  }
  process.stdout.write(Buffer.from(recovered).toString('base64'));
}

main();
