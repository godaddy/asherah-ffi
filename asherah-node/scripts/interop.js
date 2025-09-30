#!/usr/bin/env node
const path = require('path');

function loadAddon() {
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
    path.resolve(__dirname, '..', 'target', 'debug', binaryName),
    path.resolve(__dirname, '..', 'target', 'release', binaryName),
    path.resolve(__dirname, '..', '..', 'target', 'debug', binaryName),
    path.resolve(__dirname, '..', '..', 'target', 'release', binaryName),
    path.resolve(__dirname, '..', 'index.node'),
    path.resolve(__dirname, '..', 'npm', 'index.js'),
  );

  for (const file of candidates) {
    try {
      const loaded = require(file);
      if (process.env.ASHERAH_INTEROP_DEBUG) {
        console.error(`loaded addon ${file}`);
      }
      return loaded;
    } catch (err) {
      // try next
    }
  }
  throw new Error('Could not locate compiled asherah-node addon. Run `npm run build` first.');
}

function configFromEnv() {
  const sqlitePath = process.env.SQLITE_PATH;
  const metastore = sqlitePath ? 'rdbms' : (process.env.Metastore || 'memory');
  return {
    serviceName: process.env.SERVICE_NAME || 'service',
    productId: process.env.PRODUCT_ID || 'product',
    expireAfter: process.env.EXPIRE_AFTER_SECS ? Number(process.env.EXPIRE_AFTER_SECS) : undefined,
    checkInterval: process.env.REVOKE_CHECK_INTERVAL_SECS ? Number(process.env.REVOKE_CHECK_INTERVAL_SECS) : undefined,
    metastore,
    connectionString: process.env.CONNECTION_STRING || sqlitePath,
    dynamoDbEndpoint: process.env.AWS_ENDPOINT_URL,
    dynamoDbRegion: process.env.AWS_REGION,
    dynamoDbTableName: process.env.DDB_TABLE,
    sessionCacheMaxSize: process.env.SESSION_CACHE_MAX_SIZE ? Number(process.env.SESSION_CACHE_MAX_SIZE) : undefined,
    sessionCacheDuration: process.env.SESSION_CACHE_DURATION_SECS ? Number(process.env.SESSION_CACHE_DURATION_SECS) : undefined,
    kms: process.env.KMS || 'static',
    regionMap: process.env.REGION_MAP ? JSON.parse(process.env.REGION_MAP) : undefined,
    preferredRegion: process.env.PREFERRED_REGION,
    enableRegionSuffix: process.env.DDB_REGION_SUFFIX ? process.env.DDB_REGION_SUFFIX === '1' : undefined,
    enableSessionCaching: process.env.SESSION_CACHE ? ['1','true','yes','on'].includes(process.env.SESSION_CACHE.toLowerCase()) : undefined,
    verbose: false,
  };
}

function requireArgs(n) {
  if (process.argv.length < n) {
    console.error('Usage: interop.js <encrypt|decrypt> <partition> <base64>');
    process.exit(1);
  }
}

function main() {
  requireArgs(5);
  const action = process.argv[2];
  const partition = process.argv[3];
  const payloadB64 = process.argv[4];

  const addon = loadAddon();
  const cfg = configFromEnv();
  if (process.env.ASHERAH_INTEROP_DEBUG) {
    console.error(`SQLITE_PATH=${process.env.SQLITE_PATH || ''}`);
    console.error(`Metastore=${cfg.metastore}`);
    console.error(`ConnectionString=${cfg.connectionString || ''}`);
  }
  addon.setup(cfg);

  try {
    if (action === 'encrypt') {
      const data = Buffer.from(payloadB64, 'base64');
      const json = addon.encrypt(partition, data);
      process.stdout.write(Buffer.from(json, 'utf8').toString('base64'));
    } else if (action === 'decrypt') {
      const json = Buffer.from(payloadB64, 'base64').toString('utf8');
      const buf = addon.decrypt(partition, json);
      process.stdout.write(Buffer.from(buf).toString('base64'));
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
