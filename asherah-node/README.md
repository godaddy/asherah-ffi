# asherah

Node.js bindings for the Asherah envelope encryption and key rotation library.

Prebuilt native binaries are published to npm for Linux (x64/ARM64, glibc and
musl), macOS (x64/ARM64), and Windows (x64/ARM64). The correct binary is
selected automatically at install time. No compilation needed.

## Installation

```bash
npm install asherah
```

Requires Node.js >= 18.

## Quick Start (Static API)

The static API uses a global singleton. Call `setup()` once, then `encrypt`/`decrypt` from anywhere.

```js
const asherah = require('asherah');

// Static master key for local development only.
// In production, use kms: 'aws' with a region map.
process.env.STATIC_MASTER_KEY_HEX = '22'.repeat(32);

asherah.setup({
  serviceName: 'my-service',
  productId: 'my-product',
  metastore: 'memory',   // testing only
  kms: 'static',         // testing only
  enableSessionCaching: true,
});

// Encrypt raw bytes
const ciphertext = asherah.encrypt('my-partition', Buffer.from('secret data'));
const plaintext = asherah.decrypt('my-partition', ciphertext);
console.log(plaintext.toString()); // 'secret data'

// Or use the string convenience methods
const ct = asherah.encryptString('my-partition', 'hello world');
const pt = asherah.decryptString('my-partition', ct);
console.log(pt); // 'hello world'

asherah.shutdown();
```

## Session-Based API

The `SessionFactory` / `AsherahSession` pattern is preferred for production. It
avoids the global singleton and gives you explicit control over session
lifetimes.

```js
const { SessionFactory } = require('asherah');

process.env.STATIC_MASTER_KEY_HEX = '22'.repeat(32);

const factory = new SessionFactory({
  serviceName: 'my-service',
  productId: 'my-product',
  metastore: 'memory',   // testing only
  kms: 'static',         // testing only
});

const session = factory.getSession('my-partition');

const ct = session.encrypt(Buffer.from('secret'));
const pt = session.decrypt(ct);
console.log(pt.toString()); // 'secret'

// String variants
const ct2 = session.encryptString('hello');
const pt2 = session.decryptString(ct2);
console.log(pt2); // 'hello'

session.close();
factory.close();
```

You can also create a factory from environment variables:

```js
const factory = SessionFactory.fromEnv();
```

## Async API

Every sync function has an async counterpart that returns a Promise and never
blocks the Node.js event loop.

```js
const asherah = require('asherah');

process.env.STATIC_MASTER_KEY_HEX = '22'.repeat(32);

await asherah.setupAsync({
  serviceName: 'my-service',
  productId: 'my-product',
  metastore: 'memory',   // testing only
  kms: 'static',         // testing only
});

const ct = await asherah.encryptStringAsync('my-partition', 'secret');
const pt = await asherah.decryptStringAsync('my-partition', ct);
console.log(pt); // 'secret'

await asherah.shutdownAsync();
```

## Async Behavior

Async operations run on a Rust tokio runtime, separate from the Node.js event
loop. The exact execution strategy depends on the metastore:

| Metastore | Async Encrypt/Decrypt | Blocks Event Loop? |
|-----------|----------------------|-------------------|
| In-Memory | Runs on tokio worker thread | No |
| DynamoDB  | True async AWS SDK calls on tokio | No |
| MySQL     | `spawn_blocking` (sync driver on tokio thread pool) | No |
| Postgres  | `spawn_blocking` (sync driver on tokio thread pool) | No |

**Async never blocks the Node.js event loop.** The tradeoff is ~12us overhead
per async call vs ~1us for sync (hot cache, 64B payload). Use sync in tight
loops where latency matters; use async when you need to keep the event loop
responsive.

## Configuration

Pass a config object to `setup()`, `setupAsync()`, or the `SessionFactory`
constructor. Both camelCase and PascalCase field names are accepted (PascalCase
is auto-mapped for backward compatibility with the canonical Go-based package).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `serviceName` | `string` | **(required)** | Service identifier for key hierarchy |
| `productId` | `string` | **(required)** | Product identifier for key hierarchy |
| `metastore` | `string` | **(required)** | `"rdbms"`, `"dynamodb"`, `"memory"` (testing) |
| `kms` | `string` | `"static"` | `"static"` or `"aws"` |
| `connectionString` | `string` | | Connection string for sqlite or rdbms metastore |
| `sqlMetastoreDBType` | `string` | | `"mysql"` or `"postgres"` (for rdbms metastore) |
| `enableSessionCaching` | `boolean` | `true` | Cache sessions by partition ID |
| `sessionCacheMaxSize` | `number` | `1000` | Max cached sessions |
| `sessionCacheDuration` | `number` | | Session cache TTL in milliseconds |
| `regionMap` | `object` | | `{ "us-west-2": "arn:aws:kms:..." }` for AWS KMS multi-region |
| `preferredRegion` | `string` | | Preferred AWS region for KMS |
| `enableRegionSuffix` | `boolean` | | Append region suffix to system key IDs |
| `expireAfter` | `number` | | Key expiration in milliseconds |
| `checkInterval` | `number` | | Key rotation check interval in milliseconds |
| `dynamoDBEndpoint` | `string` | | Custom DynamoDB endpoint URL |
| `dynamoDBRegion` | `string` | | DynamoDB region |
| `dynamoDBTableName` | `string` | | DynamoDB table name |
| `replicaReadConsistency` | `string` | | DynamoDB read consistency |
| `verbose` | `boolean` | `false` | Enable debug logging |
| `enableCanaries` | `boolean` | | Enable canary key verification |
| `disableZeroCopy` | `boolean` | | Disable zero-copy optimizations |
| `nullDataCheck` | `boolean` | | Verify data is not null before decrypt |
| `poolMaxOpen` | `number` | `0` | Max open DB connections (0 = unlimited) |
| `poolMaxIdle` | `number` | `2` | Max idle connections to retain |
| `poolMaxLifetime` | `number` | `0` | Max connection lifetime in seconds (0 = unlimited) |
| `poolMaxIdleTime` | `number` | `0` | Max idle time per connection in seconds (0 = unlimited) |

### Environment Variables

- `STATIC_MASTER_KEY_HEX` -- 64 hex chars (32 bytes) for static KMS. **Testing only.**
- `ASHERAH_NODE_DEBUG=1` -- Enable native debug logging.
- `ASHERAH_POOL_MAX_OPEN` -- Max open DB connections (overrides config).
- `ASHERAH_POOL_MAX_IDLE` -- Max idle connections (overrides config).
- `ASHERAH_POOL_MAX_LIFETIME` -- Max connection lifetime in seconds (overrides config).
- `ASHERAH_POOL_MAX_IDLE_TIME` -- Max idle time per connection in seconds (overrides config).

## Performance

This is a native Rust implementation compiled via napi-rs. Typical latencies on
Apple M4 Max (in-memory metastore, session caching enabled, 64-byte payload):

| Operation | Sync | Async |
|-----------|------|-------|
| Encrypt   | ~970 ns | ~12 us |
| Decrypt   | ~1,200 ns | ~12 us |

See `scripts/benchmark.sh` for head-to-head comparisons with the canonical
Go-based implementation.

## Migration from Canonical (v3.x)

This package is a drop-in replacement for the Go-based `asherah` npm package
(v3.x). The JavaScript wrapper provides full backward compatibility:

- **PascalCase config** -- `ServiceName`, `ProductID`, `Metastore`, etc. are
  auto-mapped to camelCase equivalents.
- **snake_case function aliases** -- `set_log_hook`, `get_setup_status`,
  `encrypt_string`, `decrypt_string_async`, etc. all work.
- **Metastore/KMS aliases** -- `"test-debug-memory"`, `"test-debug-static"`,
  etc. are normalized to their short forms.
- **`set_log_hook` callback signature** -- Both the canonical
  `(level: number, message: string)` and the native
  `(event: { level, message, target })` signatures are supported.

To migrate, update your package version. No code changes required.

## Supported Platforms

| Platform | Architecture | Notes |
|----------|-------------|-------|
| Linux    | x64         | glibc (most distros) |
| Linux    | x64         | musl (Alpine) |
| Linux    | ARM64       | glibc |
| Linux    | ARM64       | musl (Alpine) |
| macOS    | x64         | Intel Macs |
| macOS    | ARM64       | Apple Silicon |
| Windows  | x64         | MSVC |
| Windows  | ARM64       | MSVC |

## API Reference

### Setup / Teardown

- `setup(config)` -- Initialize the global Asherah instance.
- `setupAsync(config)` -- Async variant of `setup`.
- `shutdown()` -- Shut down and release all resources.
- `shutdownAsync()` -- Async variant of `shutdown`.
- `getSetupStatus()` -- Returns `true` if `setup` has been called.

### Encrypt / Decrypt (Static API)

- `encrypt(partitionId, data: Buffer)` -- Returns JSON string (DataRowRecord).
- `encryptAsync(partitionId, data: Buffer)` -- Async variant.
- `encryptString(partitionId, data: string)` -- String-in, string-out convenience.
- `encryptStringAsync(partitionId, data: string)` -- Async variant.
- `decrypt(partitionId, dataRowRecord: string | Buffer)` -- Returns `Buffer`.
- `decryptAsync(partitionId, dataRowRecord: string | Buffer)` -- Async variant.
- `decryptString(partitionId, dataRowRecord: string)` -- Returns `string`.
- `decryptStringAsync(partitionId, dataRowRecord: string)` -- Async variant.

### Session-Based API

- `new SessionFactory(config)` -- Create a factory with explicit config.
- `SessionFactory.fromEnv()` -- Create a factory from environment variables.
- `factory.getSession(partitionId)` -- Get a session for a partition.
- `factory.close()` -- Close the factory and release resources.
- `session.encrypt(data: Buffer)` -- Returns JSON string.
- `session.encryptString(data: string)` -- String convenience.
- `session.decrypt(dataRowRecord: string)` -- Returns `Buffer`.
- `session.decryptString(dataRowRecord: string)` -- Returns `string`.
- `session.close()` -- Close the session.

### Hooks

- `setLogHook(callback)` / `set_log_hook(callback)` -- Receive log events.
  Pass `null` to disable.
- `setMetricsHook(callback)` -- Receive metrics events
  (`{ type, durationNs?, name? }`). Pass `null` to disable.

### Utility

- `setenv(lines: string)` -- Set environment variables from `KEY=VALUE` lines.
- `setMaxStackAllocItemSize(n)` -- No-op (compatibility stub).
- `setSafetyPaddingOverhead(n)` -- No-op (compatibility stub).

## Features

- Synchronous and asynchronous encrypt/decrypt APIs
- Session-based API with factory pattern
- Compatible with Go, Python, Ruby, Java, and .NET Asherah implementations
- SQLite, MySQL, PostgreSQL, and DynamoDB metastore support
- AWS KMS and static key management
- Log and metrics hooks
- Automatic key rotation with configurable intervals

## License

Licensed under the Apache License, Version 2.0.
