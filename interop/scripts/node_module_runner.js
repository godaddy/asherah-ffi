#!/usr/bin/env node
const path = require('path');

function loadNewAddon() {
  const binaryName = 'asherah_node.node';
  const envTarget = process.env.NAPI_RS_CARGO_TARGET_DIR || process.env.CARGO_TARGET_DIR;
  const candidates = [];

  if (envTarget) {
    candidates.push(
      path.resolve(envTarget, 'debug', binaryName),
      path.resolve(envTarget, 'release', binaryName),
    );
  }

  candidates.push(
    path.resolve(__dirname, '..', '..', 'asherah-node', 'target', 'debug', binaryName),
    path.resolve(__dirname, '..', '..', 'asherah-node', 'target', 'release', binaryName),
    path.resolve(__dirname, '..', '..', 'target', 'debug', binaryName),
    path.resolve(__dirname, '..', '..', 'target', 'release', binaryName),
    path.resolve(__dirname, '..', '..', 'asherah-node', 'index.node'),
  );

  for (const file of candidates) {
    try {
      return require(file);
    } catch (_) {
      // try next candidate
    }
  }

  throw new Error('Could not locate compiled asherah-node addon. Run `npm run build` first.');
}

function boolEnv(name, defaultValue) {
  const raw = process.env[name];
  if (raw === undefined || raw === null) {
    return defaultValue;
  }
  const normalized = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  return defaultValue;
}

function configForNewAddon() {
  const sqlitePath = process.env.SQLITE_PATH;
  const metastore = sqlitePath ? 'rdbms' : (process.env.Metastore || 'memory');
  const config = {
    serviceName: process.env.SERVICE_NAME || 'service',
    productId: process.env.PRODUCT_ID || 'product',
    metastore,
    kms: process.env.KMS || 'static',
    enableSessionCaching: boolEnv('SESSION_CACHE', false),
    verbose: false,
  };

  if (process.env.EXPIRE_AFTER_SECS) {
    config.expireAfter = Number(process.env.EXPIRE_AFTER_SECS);
  }
  if (process.env.REVOKE_CHECK_INTERVAL_SECS) {
    config.checkInterval = Number(process.env.REVOKE_CHECK_INTERVAL_SECS);
  }
  const connectionString = process.env.CONNECTION_STRING || sqlitePath;
  if (connectionString) {
    config.connectionString = connectionString;
  }
  if (process.env.AWS_ENDPOINT_URL) {
    config.dynamoDBEndpoint = process.env.AWS_ENDPOINT_URL;
  }
  if (process.env.AWS_REGION) {
    config.dynamoDBRegion = process.env.AWS_REGION;
  }
  if (process.env.DDB_TABLE) {
    config.dynamoDBTableName = process.env.DDB_TABLE;
  }
  if (process.env.SESSION_CACHE_MAX_SIZE) {
    config.sessionCacheMaxSize = Number(process.env.SESSION_CACHE_MAX_SIZE);
  }
  if (process.env.SESSION_CACHE_DURATION_SECS) {
    config.sessionCacheDuration = Number(process.env.SESSION_CACHE_DURATION_SECS);
  }
  if (process.env.REGION_MAP) {
    config.regionMap = JSON.parse(process.env.REGION_MAP);
  }
  if (process.env.PREFERRED_REGION) {
    config.preferredRegion = process.env.PREFERRED_REGION;
  }
  if (process.env.DDB_REGION_SUFFIX) {
    config.enableRegionSuffix = process.env.DDB_REGION_SUFFIX === '1';
  }

  return config;
}

function configForLegacyAddon() {
  const sqlitePath = process.env.SQLITE_PATH;
  const metastore = sqlitePath ? 'rdbms' : (process.env.Metastore || 'memory');
  return {
    ServiceName: process.env.SERVICE_NAME || 'service',
    ProductID: process.env.PRODUCT_ID || 'product',
    ExpireAfter: process.env.EXPIRE_AFTER_SECS ? Number(process.env.EXPIRE_AFTER_SECS) : null,
    CheckInterval: process.env.REVOKE_CHECK_INTERVAL_SECS ? Number(process.env.REVOKE_CHECK_INTERVAL_SECS) : null,
    Metastore: metastore,
    ConnectionString: process.env.CONNECTION_STRING || sqlitePath || null,
    DynamoDBEndpoint: process.env.AWS_ENDPOINT_URL || null,
    DynamoDBRegion: process.env.AWS_REGION || null,
    DynamoDBTableName: process.env.DDB_TABLE || null,
    SessionCacheMaxSize: process.env.SESSION_CACHE_MAX_SIZE ? Number(process.env.SESSION_CACHE_MAX_SIZE) : null,
    SessionCacheDuration: process.env.SESSION_CACHE_DURATION_SECS ? Number(process.env.SESSION_CACHE_DURATION_SECS) : null,
    KMS: process.env.KMS || 'static',
    RegionMap: process.env.REGION_MAP ? JSON.parse(process.env.REGION_MAP) : null,
    PreferredRegion: process.env.PREFERRED_REGION || null,
    EnableRegionSuffix: process.env.DDB_REGION_SUFFIX ? process.env.DDB_REGION_SUFFIX === '1' : null,
    EnableSessionCaching: boolEnv('SESSION_CACHE', false),
    Verbose: false,
  };
}

function requireArgs(n) {
  if (process.argv.length < n) {
    console.error('Usage: node_module_runner.js <new|legacy> <encrypt|decrypt> <partition> <payload-b64>');
    process.exit(1);
  }
}

function main() {
  requireArgs(6);
  const flavour = process.argv[2];
  const action = process.argv[3];
  const partition = process.argv[4];
  const payloadB64 = process.argv[5];

  const payload = Buffer.from(payloadB64, 'base64');
  let addon;
  let config;

  if (flavour === 'legacy') {
    const legacyModulePath = path.resolve(
      __dirname,
      '..',
      'legacy-node',
      'node_modules',
      'asherah',
      'dist',
      'asherah.node',
    );
    if (process.env.ASHERAH_INTEROP_DEBUG) {
      console.error(`legacy module path: ${legacyModulePath}`);
    }
    addon = require(legacyModulePath);
    config = configForLegacyAddon();
  } else if (flavour === 'new') {
    addon = loadNewAddon();
    config = configForNewAddon();
  } else {
    console.error(`Unknown module flavour: ${flavour}`);
    process.exit(1);
  }

  if (typeof addon.setup !== 'function') {
    console.error('Selected module does not expose a setup function');
    process.exit(1);
  }

  addon.setup(config);

  try {
    if (action === 'roundtrip') {
      const ciphertext = addon.encrypt(partition, Buffer.from(payload));
      const decryptInput = flavour === 'legacy' ? Buffer.from(ciphertext) : Buffer.from(ciphertext).toString('utf8');
      const plaintext = flavour === 'legacy'
        ? addon.decrypt(partition, decryptInput)
        : addon.decrypt(partition, decryptInput);
      const bufferOut = Buffer.from(plaintext);
      process.stdout.write(bufferOut.toString('base64'));
    } else if (action === 'encrypt') {
      const ciphertext = addon.encrypt(partition, Buffer.from(payload));
      // New module returns a string, legacy returns Buffer
      const bufferOut = typeof ciphertext === 'string' ? Buffer.from(ciphertext, 'utf8') : Buffer.from(ciphertext);
      process.stdout.write(bufferOut.toString('base64'));
    } else if (action === 'decrypt') {
      let plaintext;
      if (flavour === 'legacy') {
        plaintext = addon.decrypt(partition, Buffer.from(payload));
      } else {
        const json = Buffer.from(payload).toString('utf8');
        plaintext = addon.decrypt(partition, json);
      }
      const bufferOut = Buffer.from(plaintext);
      process.stdout.write(bufferOut.toString('base64'));
    } else {
      console.error(`Unknown action: ${action}`);
      process.exit(1);
    }
  } finally {
    if (typeof addon.shutdown === 'function') {
      addon.shutdown();
    }
  }
}

main();
