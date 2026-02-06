#!/usr/bin/env node
// Helper to interop with Node Asherah SDK for cross-language tests.
// Usage:
//  node gen.js encrypt <service> <product> <partition> <masterHex> <payloadB64>
//    -> prints JSON: { metastore: [EKR...], drr: {...} }
//  node gen.js decrypt <service> <product> <partition> <masterHex>  (reads bundle JSON on stdin)
//    -> prints plaintext base64

const fs = require('fs');

function loadAsherah(masterHex) {
  let asherah;
  try { asherah = require('asherah'); } catch (e) {
    console.error('asherah npm module not installed. Run `npm install` in cucumber/js');
    process.exit(2);
  }
  if (asherah.setenv) {
    // Go cobhan reads the static master key from env; set the common variants for compatibility.
    const env = {
      STATIC_MASTER_KEY_HEX: masterHex,
      STATIC_MASTER_KEY: masterHex,
      ASHERAH_STATIC_MASTER_KEY_HEX: masterHex,
      ASHERAH_STATIC_MASTER_KEY: masterHex,
      ASHERAH_KMS_STATIC_KEY_HEX: masterHex,
      ASHERAH_KMS_STATIC_KEY: masterHex,
      ASHERAH_MASTER_KEY_HEX: masterHex,
      ASHERAH_MASTER_KEY: masterHex,
      KMS_STATIC_KEY_HEX: masterHex,
      KMS_STATIC_KEY: masterHex
    };
    try { asherah.setenv(JSON.stringify(env)); } catch (e) {}
  }
  return asherah;
}

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) arr[i/2] = parseInt(hex.slice(i, i+2), 16);
  return Buffer.from(arr);
}

async function encrypt(service, product, partition, masterHex, payloadB64) {
  // Configure Node Asherah to use shared RDBMS metastore and StaticKMS with provided master key
  const pg = process.env.POSTGRES_URL;
  const my = process.env.MYSQL_URL;
  let connection = null;
  if (pg) connection = pg; else if (my) {
    const u = new URL(my);
    const host = u.hostname; const port = u.port || '3306'; const user = u.username; const pass = u.password; const db = u.pathname.replace(/^\//, '') || '';
    connection = `${user}:${pass}@tcp(${host}:${port})/${db}`;
  } else { console.error('Set POSTGRES_URL or MYSQL_URL for shared metastore'); process.exit(4); }
  const config = {
    KMS: 'static',
    Metastore: 'rdbms',
    ServiceName: service,
    ProductID: product,
    Verbose: false,
    EnableSessionCaching: true,
    ExpireAfter: null,
    CheckInterval: null,
    ConnectionString: connection,
    ReplicaReadConsistency: null,
    DynamoDBEndpoint: null,
    DynamoDBRegion: null,
    DynamoDBTableName: null,
    SessionCacheMaxSize: null,
    SessionCacheDuration: null,
    RegionMap: null,
    PreferredRegion: null,
    EnableRegionSuffix: null
  };
  const asherah = loadAsherah(masterHex);
  asherah.setup(config);
  const payload = Buffer.from(payloadB64, 'base64');
  let drr = asherah.encrypt(partition, payload);
  if (typeof drr === 'string') {
    drr = JSON.parse(drr);
  }
  // Metastore is shared via DB; no need to export entries
  const bundle = { metastore: [], drr };
  console.log(JSON.stringify(bundle));
}

async function decrypt(service, product, partition, masterHex) {
  const pg = process.env.POSTGRES_URL;
  const my = process.env.MYSQL_URL;
  let connection = null;
  if (pg) connection = pg; else if (my) {
    const u = new URL(my);
    const host = u.hostname; const port = u.port || '3306'; const user = u.username; const pass = u.password; const db = u.pathname.replace(/^\//, '') || '';
    connection = `${user}:${pass}@tcp(${host}:${port})/${db}`;
  } else { console.error('Set POSTGRES_URL or MYSQL_URL'); process.exit(4); }
  const config = {
    KMS: 'static',
    Metastore: 'rdbms',
    ServiceName: service,
    ProductID: product,
    Verbose: false,
    EnableSessionCaching: true,
    ExpireAfter: null,
    CheckInterval: null,
    ConnectionString: connection,
    ReplicaReadConsistency: null,
    DynamoDBEndpoint: null,
    DynamoDBRegion: null,
    DynamoDBTableName: null,
    SessionCacheMaxSize: null,
    SessionCacheDuration: null,
    RegionMap: null,
    PreferredRegion: null,
    EnableRegionSuffix: null
  };
  const asherah = loadAsherah(masterHex);
  asherah.setup(config);
  const json = await new Promise(resolve => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => data += chunk);
    process.stdin.on('end', () => resolve(data));
  });
  const bundle = JSON.parse(json);
  const drr = typeof bundle.drr === 'string' ? bundle.drr : JSON.stringify(bundle.drr);
  const pt = asherah.decrypt(partition, drr);
  process.stdout.write(Buffer.from(pt).toString('base64'));
}

(async () => {
  const [cmd, service, product, partition, masterHex, payloadB64] = process.argv.slice(2);
  if (cmd === 'encrypt') {
    await encrypt(service, product, partition, masterHex, payloadB64);
  } else if (cmd === 'decrypt') {
    await decrypt(service, product, partition, masterHex);
  } else {
    console.error('unknown cmd');
    process.exit(1);
  }
})();
