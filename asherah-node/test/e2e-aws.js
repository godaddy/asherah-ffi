#!/usr/bin/env node
/**
 * End-to-end test that exercises AWS KMS + DynamoDB/MySQL from Node.js async context.
 * This catches "Cannot start a runtime from within a runtime" panics that only
 * occur when setupAsync calls factory_from_config with real AWS KMS/DynamoDB.
 *
 * Requires Docker: spins up LocalStack (KMS + DynamoDB) and MySQL containers.
 *
 * Usage:
 *   node test/e2e-aws.js              # auto-start containers
 *   LOCALSTACK_URL=... MYSQL_URL=... node test/e2e-aws.js  # use existing
 */

const assert = require('assert');
const path = require('path');
const { execSync } = require('child_process');

const asherah = require(path.resolve(__dirname, '../npm/index.js'));

// Container management
let localstackContainer = null;
let mysqlContainer = null;
let postgresContainer = null;

function dockerRun(image, envArgs, port, readyLog, label) {
  const args = [
    'run', '-d', '--rm',
    '--label', 'asherah-e2e-test',
    ...envArgs,
    '-p', `127.0.0.1::${port}`,
    image,
  ];
  const id = execSync(`docker ${args.join(' ')}`, { encoding: 'utf8' }).trim();
  // Get mapped port
  let hostPort = null;
  for (let i = 0; i < 60; i++) {
    try {
      const portLine = execSync(`docker port ${id} ${port}/tcp`, { encoding: 'utf8' }).trim();
      hostPort = portLine.split(':').pop();
      if (hostPort) break;
    } catch {}
    execSync('sleep 1');
  }
  if (!hostPort) throw new Error(`Failed to get port for ${label}`);

  // Wait for ready
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    try {
      const logs = execSync(`docker logs ${id} 2>&1`, { encoding: 'utf8' });
      if (logs.includes(readyLog)) break;
    } catch {}
    execSync('sleep 1');
  }
  return { id, port: hostPort };
}

function dockerExec(id, cmd) {
  return execSync(`docker exec ${id} ${cmd}`, { encoding: 'utf8', timeout: 30000 });
}

function cleanup() {
  if (localstackContainer) {
    try { execSync(`docker rm -f ${localstackContainer}`, { stdio: 'ignore' }); } catch {}
  }
  if (mysqlContainer) {
    try { execSync(`docker rm -f ${mysqlContainer}`, { stdio: 'ignore' }); } catch {}
  }
  if (postgresContainer) {
    try { execSync(`docker rm -f ${postgresContainer}`, { stdio: 'ignore' }); } catch {}
  }
  // Clean up any orphaned containers
  try {
    const orphans = execSync('docker ps -a --filter label=asherah-e2e-test -q', { encoding: 'utf8' }).trim();
    if (orphans) execSync(`docker rm -f ${orphans}`, { stdio: 'ignore' });
  } catch {}
}

async function setupLocalStack() {
  let endpoint = process.env.LOCALSTACK_URL;
  if (endpoint) {
    console.log(`  Using existing LocalStack: ${endpoint}`);
    return endpoint;
  }

  console.log('  Starting LocalStack container...');
  const ls = dockerRun(
    'localstack/localstack:latest',
    ['-e', 'SERVICES=kms,dynamodb'],
    4566,
    'Ready.',
    'localstack'
  );
  localstackContainer = ls.id;
  endpoint = `http://127.0.0.1:${ls.port}`;
  console.log(`  LocalStack ready: ${endpoint}`);
  return endpoint;
}

async function createKmsKey(endpoint) {
  // Use AWS CLI in LocalStack container or curl
  const result = execSync(
    `docker exec ${localstackContainer} awslocal kms create-key --region us-east-1 --output json`,
    { encoding: 'utf8', timeout: 15000 }
  );
  const meta = JSON.parse(result).KeyMetadata;
  const arn = meta.Arn;
  console.log(`  Created KMS key: ${arn}`);
  return arn;
}

async function createDynamoDbTable(endpoint, tableName) {
  try {
    execSync(
      `docker exec ${localstackContainer} awslocal dynamodb create-table ` +
      `--table-name ${tableName} ` +
      `--attribute-definitions AttributeName=Id,AttributeType=S AttributeName=Created,AttributeType=N ` +
      `--key-schema AttributeName=Id,KeyType=HASH AttributeName=Created,KeyType=RANGE ` +
      `--billing-mode PAY_PER_REQUEST ` +
      `--region us-east-1 --output json`,
      { encoding: 'utf8', timeout: 15000 }
    );
    console.log(`  Created DynamoDB table: ${tableName}`);
  } catch (e) {
    if (e.stderr && e.stderr.includes('ResourceInUseException')) {
      console.log(`  DynamoDB table already exists: ${tableName}`);
    } else {
      throw e;
    }
  }
}

async function setupMySQL() {
  let mysqlUrl = process.env.MYSQL_URL;
  if (mysqlUrl) {
    console.log(`  Using existing MySQL: ${mysqlUrl}`);
    return mysqlUrl;
  }

  console.log('  Starting MySQL container...');
  const my = dockerRun(
    'mysql:8.1',
    ['-e', 'MYSQL_DATABASE=test', '-e', 'MYSQL_ALLOW_EMPTY_PASSWORD=yes'],
    3306,
    'port: 3306',
    'mysql'
  );
  mysqlContainer = my.id;

  // Wait for MySQL to accept connections
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    try {
      dockerExec(my.id, 'mysqladmin -h 127.0.0.1 -u root ping --silent');
      break;
    } catch {}
    execSync('sleep 1');
  }

  // Create encryption_key table
  dockerExec(my.id,
    `mysql -h 127.0.0.1 -u root test -e "` +
    `DROP TABLE IF EXISTS encryption_key; ` +
    `CREATE TABLE encryption_key (id VARCHAR(255) NOT NULL, created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, ` +
    `key_record JSON NOT NULL, PRIMARY KEY(id, created), INDEX(created)) ENGINE=InnoDB"`
  );

  mysqlUrl = `mysql://root@127.0.0.1:${my.port}/test`;
  console.log(`  MySQL ready: ${mysqlUrl}`);
  return mysqlUrl;
}

async function setupPostgres() {
  let pgUrl = process.env.POSTGRES_URL;
  if (pgUrl) {
    console.log(`  Using existing Postgres: ${pgUrl}`);
    return pgUrl;
  }

  console.log('  Starting Postgres container...');
  const pg = dockerRun(
    'postgres:16',
    ['-e', 'POSTGRES_PASSWORD=postgres', '-e', 'POSTGRES_DB=test'],
    5432,
    'database system is ready to accept connections',
    'postgres'
  );
  postgresContainer = pg.id;

  // Wait for Postgres to accept connections
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    try {
      dockerExec(pg.id, 'pg_isready -h 127.0.0.1 -U postgres');
      break;
    } catch {}
    execSync('sleep 1');
  }

  // Create encryption_key table
  dockerExec(pg.id,
    `psql -h 127.0.0.1 -U postgres -d test -c "` +
    `CREATE TABLE IF NOT EXISTS encryption_key (` +
    `id TEXT NOT NULL, created TIMESTAMP NOT NULL, ` +
    `key_record JSONB NOT NULL, PRIMARY KEY(id, created))"`
  );

  pgUrl = `postgres://postgres:postgres@127.0.0.1:${pg.port}/test`;
  console.log(`  Postgres ready: ${pgUrl}`);
  return pgUrl;
}

// ── Tests ──

async function testAsyncSetupWithAwsKmsDynamoDb(endpoint, keyId, tableName) {
  console.log('  Test: setupAsync with AWS KMS + DynamoDB (async context)');

  // This is the exact call path that panicked before the block_in_place fix.
  // Use PascalCase config to match the Go/Cobhan convention that asherah-config expects.
  // AWS_ENDPOINT_URL is set in main() — DynamoDB and KMS clients read it directly.
  await asherah.setupAsync({
    ServiceName: 'e2e-aws-ddb',
    ProductID: 'e2e-aws',
    KMS: 'aws',
    RegionMap: { 'us-east-1': keyId },
    PreferredRegion: 'us-east-1',
    Metastore: 'dynamodb',
    DynamoDBRegion: 'us-east-1',
    EnableSessionCaching: true,
  });

  // Sync encrypt/decrypt (first call = cache miss → DynamoDB store for SK + IK)
  const ct1 = asherah.encryptString('ddb-partition', 'dynamodb-sync-test');
  const pt1 = asherah.decryptString('ddb-partition', ct1);
  assert.strictEqual(pt1, 'dynamodb-sync-test');

  // Async encrypt/decrypt (cache hit on same partition)
  const ct2 = await asherah.encryptStringAsync('ddb-partition', 'dynamodb-async-cached');
  const pt2 = await asherah.decryptStringAsync('ddb-partition', ct2);
  assert.strictEqual(pt2, 'dynamodb-async-cached');

  // Async encrypt on NEW partition (cache miss → async DynamoDB store)
  const ct3 = await asherah.encryptStringAsync('ddb-partition-2', 'dynamodb-async-miss');
  const pt3 = await asherah.decryptStringAsync('ddb-partition-2', ct3);
  assert.strictEqual(pt3, 'dynamodb-async-miss');

  // Sync encrypt → async decrypt (cross-mode interop)
  const ct4 = asherah.encryptString('ddb-interop', 'sync-to-async');
  const pt4 = await asherah.decryptStringAsync('ddb-interop', ct4);
  assert.strictEqual(pt4, 'sync-to-async');

  // Async encrypt → sync decrypt (cross-mode interop)
  const ct5 = await asherah.encryptStringAsync('ddb-interop', 'async-to-sync');
  const pt5 = asherah.decryptString('ddb-interop', ct5);
  assert.strictEqual(pt5, 'async-to-sync');

  // Concurrent async across multiple partitions (cache misses)
  const promises = [];
  for (let i = 0; i < 10; i++) {
    const partition = `ddb-concurrent-${i}`;
    const payload = `concurrent-${i}`;
    promises.push(
      asherah.encryptStringAsync(partition, payload)
        .then(drr => asherah.decryptStringAsync(partition, drr))
        .then(recovered => {
          assert.strictEqual(recovered, payload, `partition ${i} roundtrip failed`);
        })
    );
  }
  await Promise.all(promises);

  // Binary data roundtrip (async)
  const binData = Buffer.alloc(1024, 0xAB);
  const binCt = await asherah.encryptAsync('ddb-binary', binData);
  const binPt = await asherah.decryptAsync('ddb-binary', binCt);
  assert.ok(Buffer.from(binPt).equals(binData), 'binary roundtrip failed');

  await asherah.shutdownAsync();
  console.log('  PASS: AWS KMS + DynamoDB (async context)');
}

async function testAsyncSetupWithAwsKmsMySQL(endpoint, keyId, mysqlUrl) {
  console.log('  Test: setupAsync with AWS KMS + MySQL (async context)');

  await asherah.setupAsync({
    ServiceName: 'e2e-aws-mysql',
    ProductID: 'e2e-aws',
    KMS: 'aws',
    RegionMap: { 'us-east-1': keyId },
    PreferredRegion: 'us-east-1',
    Metastore: 'rdbms',
    ConnectionString: mysqlUrl,
    EnableSessionCaching: true,
  });

  // Async encrypt/decrypt (cache miss → MySQL store for SK + IK)
  const ct1 = await asherah.encryptStringAsync('mysql-partition', 'mysql-async-miss');
  const pt1 = await asherah.decryptStringAsync('mysql-partition', ct1);
  assert.strictEqual(pt1, 'mysql-async-miss');

  // Sync encrypt/decrypt (cache hit)
  const ct2 = asherah.encryptString('mysql-partition', 'mysql-sync-cached');
  const pt2 = asherah.decryptString('mysql-partition', ct2);
  assert.strictEqual(pt2, 'mysql-sync-cached');

  // Async on new partition (cache miss)
  const ct3 = await asherah.encryptStringAsync('mysql-p2', 'mysql-async-miss-2');
  const pt3 = await asherah.decryptStringAsync('mysql-p2', ct3);
  assert.strictEqual(pt3, 'mysql-async-miss-2');

  // Cross-mode interop
  const ct4 = asherah.encryptString('mysql-interop', 'sync-to-async');
  const pt4 = await asherah.decryptStringAsync('mysql-interop', ct4);
  assert.strictEqual(pt4, 'sync-to-async');

  const ct5 = await asherah.encryptStringAsync('mysql-interop', 'async-to-sync');
  const pt5 = asherah.decryptString('mysql-interop', ct5);
  assert.strictEqual(pt5, 'async-to-sync');

  await asherah.shutdownAsync();
  console.log('  PASS: AWS KMS + MySQL (async context)');
}

async function testAsyncSetupWithAwsKmsPostgres(endpoint, keyId, pgUrl) {
  console.log('  Test: setupAsync with AWS KMS + Postgres (async context)');

  await asherah.setupAsync({
    ServiceName: 'e2e-aws-pg',
    ProductID: 'e2e-aws',
    KMS: 'aws',
    RegionMap: { 'us-east-1': keyId },
    PreferredRegion: 'us-east-1',
    Metastore: 'rdbms',
    ConnectionString: pgUrl,
    EnableSessionCaching: true,
  });

  // Async encrypt/decrypt (cache miss → Postgres store)
  const ct1 = await asherah.encryptStringAsync('pg-partition', 'postgres-async-miss');
  const pt1 = await asherah.decryptStringAsync('pg-partition', ct1);
  assert.strictEqual(pt1, 'postgres-async-miss');

  // Sync encrypt/decrypt (cache hit)
  const ct2 = asherah.encryptString('pg-partition', 'postgres-sync-cached');
  const pt2 = asherah.decryptString('pg-partition', ct2);
  assert.strictEqual(pt2, 'postgres-sync-cached');

  // New partition async (cache miss)
  const ct3 = await asherah.encryptStringAsync('pg-p2', 'postgres-async-miss-2');
  const pt3 = await asherah.decryptStringAsync('pg-p2', ct3);
  assert.strictEqual(pt3, 'postgres-async-miss-2');

  // Cross-mode interop
  const ct4 = asherah.encryptString('pg-interop', 'sync-to-async');
  const pt4 = await asherah.decryptStringAsync('pg-interop', ct4);
  assert.strictEqual(pt4, 'sync-to-async');

  const ct5 = await asherah.encryptStringAsync('pg-interop', 'async-to-sync');
  const pt5 = asherah.decryptString('pg-interop', ct5);
  assert.strictEqual(pt5, 'async-to-sync');

  await asherah.shutdownAsync();
  console.log('  PASS: AWS KMS + Postgres (async context)');
}

async function testSyncSetupWithAwsKmsDynamoDb(endpoint, keyId, tableName) {
  console.log('  Test: setup (sync) with AWS KMS + DynamoDB');

  asherah.setup({
    ServiceName: 'e2e-aws-ddb-sync',
    ProductID: 'e2e-aws',
    KMS: 'aws',
    RegionMap: { 'us-east-1': keyId },
    PreferredRegion: 'us-east-1',
    Metastore: 'dynamodb',
    DynamoDBRegion: 'us-east-1',
    EnableSessionCaching: true,
  });

  const ct = asherah.encryptString('ddb-sync-p', 'sync-ddb-test');
  const pt = asherah.decryptString('ddb-sync-p', ct);
  assert.strictEqual(pt, 'sync-ddb-test');

  asherah.shutdown();
  console.log('  PASS: AWS KMS + DynamoDB (sync)');
}

async function testSetupShutdownCycleAwsKms(endpoint, keyId, tableName) {
  console.log('  Test: setup/shutdown cycle with AWS KMS');

  for (let i = 0; i < 3; i++) {
    await asherah.setupAsync({
      ServiceName: `e2e-cycle-${i}`,
      ProductID: 'e2e-aws',
      KMS: 'aws',
      RegionMap: { 'us-east-1': keyId },
      PreferredRegion: 'us-east-1',
      Metastore: 'dynamodb',
      DynamoDBRegion: 'us-east-1',
    });

    const ct = await asherah.encryptStringAsync('cycle-p', `cycle-${i}`);
    const pt = await asherah.decryptStringAsync('cycle-p', ct);
    assert.strictEqual(pt, `cycle-${i}`);

    await asherah.shutdownAsync();
  }
  console.log('  PASS: setup/shutdown cycle x3 with AWS KMS');
}

async function main() {
  console.log('=== E2E AWS KMS + DynamoDB/MySQL/Postgres Tests ===');
  console.log('  (Requires Docker)\n');

  process.env.AWS_ACCESS_KEY_ID = 'test';
  process.env.AWS_SECRET_ACCESS_KEY = 'test';
  process.env.AWS_DEFAULT_REGION = 'us-east-1';

  try {
    const endpoint = await setupLocalStack();
    process.env.AWS_ENDPOINT_URL = endpoint;

    const keyId = await createKmsKey(endpoint);
    const tableName = 'EncryptionKey';
    await createDynamoDbTable(endpoint, tableName);

    const mysqlUrl = await setupMySQL();
    const pgUrl = await setupPostgres();

    console.log();
    await testAsyncSetupWithAwsKmsDynamoDb(endpoint, keyId, tableName);
    await testSyncSetupWithAwsKmsDynamoDb(endpoint, keyId, tableName + '_sync');
    await testAsyncSetupWithAwsKmsMySQL(endpoint, keyId, mysqlUrl);
    await testAsyncSetupWithAwsKmsPostgres(endpoint, keyId, pgUrl);
    await testSetupShutdownCycleAwsKms(endpoint, keyId, tableName + '_cycle');

    console.log('\n=== All E2E AWS Tests Passed ===');
  } finally {
    cleanup();
  }
}

main().catch(err => {
  console.error('E2E AWS FAIL:', err);
  cleanup();
  process.exit(1);
});
