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

## Documentation

Task-oriented walkthroughs under [`docs/`](./docs/):

| Guide | When to read |
|---|---|
| [Getting started](./docs/getting-started.md) | First-time install through round-trip encrypt/decrypt. |
| [Framework integration](./docs/framework-integration.md) | Express, Fastify, NestJS, Koa, AWS Lambda, worker patterns. |
| [AWS production setup](./docs/aws-production-setup.md) | KMS keys, DynamoDB, IAM policy, region routing. |
| [Testing](./docs/testing.md) | Jest/Vitest fixtures, Testcontainers, mocking patterns. |
| [Troubleshooting](./docs/troubleshooting.md) | Common errors with what to check first. |

## Choosing an API style

Two API styles are exposed; both are fully supported and produce the same
wire format. New code should prefer the **Factory / Session API**.

| Style | When to use |
|---|---|
| **Static / module-level** (`asherah.setup`, `asherah.encrypt`, …) | Drop-in compatibility with the canonical `godaddy/asherah-node` package. Simplest call surface. Singleton lifecycle (`setup()` once, `shutdown()` once). |
| **Factory / Session** (`new SessionFactory(...)`, `factory.getSession(...)`) | Recommended for new code. Explicit lifecycle, no hidden singleton, multi-tenant isolation is obvious in code. |

A complete runnable example exercising both styles plus async, log hook, and
metrics hook is in [`samples/node/index.mjs`](../samples/node/index.mjs).

## Quick start (static API)

```js
const asherah = require('asherah');

process.env.STATIC_MASTER_KEY_HEX = '22'.repeat(32); // testing only

asherah.setup({
  serviceName: 'my-service',
  productId: 'my-product',
  metastore: 'memory',   // testing only — use 'rdbms' or 'dynamodb' in production
  kms: 'static',         // testing only — use 'aws' in production
});

const ct = asherah.encryptString('user-42', 'secret');
const pt = asherah.decryptString('user-42', ct);

asherah.shutdown();
```

## Quick start (factory / session API)

```js
const { SessionFactory } = require('asherah');

const factory = new SessionFactory({
  serviceName: 'my-service',
  productId: 'my-product',
  metastore: 'memory',
  kms: 'static',
});
const session = factory.getSession('user-42');
try {
  const ct = session.encryptString('secret');
  const pt = session.decryptString(ct);
} finally {
  session.close();
  factory.close();
}
```

## Async API

Every sync function has a `*Async` counterpart that returns a `Promise` and
runs on the Rust tokio runtime — the Node event loop is not blocked.

```js
await asherah.setupAsync(config);
const ct = await asherah.encryptStringAsync('user-42', 'secret');
const pt = await asherah.decryptStringAsync('user-42', ct);
await asherah.shutdownAsync();
```

| Metastore | Async path | Blocks event loop? |
|-----------|------------|---------------------|
| In-memory | tokio worker thread | No |
| DynamoDB  | true async AWS SDK calls on tokio | No |
| MySQL     | `spawn_blocking` (sync driver on tokio thread pool) | No |
| Postgres  | `spawn_blocking` (sync driver on tokio thread pool) | No |

Tradeoff: ~12µs async vs ~1µs sync per call (hot cache, 64 B payload). Use
sync in tight loops where latency matters; async when you need to keep the
event loop responsive.

## Observability hooks

### Log hook

Receive every log event from the Rust core (encrypt/decrypt path, metastore
drivers, KMS clients).

```js
asherah.setLogHook((event) => {
  // event = { level, message, target }
  // level ∈ 'trace' | 'debug' | 'info' | 'warn' | 'error'
  if (event.level === 'warn' || event.level === 'error') {
    console.error(`[asherah ${event.level}] ${event.message}`);
  }
});

// later, to deregister:
asherah.setLogHook(null);
```

The snake_case alias `set_log_hook` also accepts the canonical
`(level: number, message: string)` signature for backward compatibility with
the Go-based `asherah` npm package.

```js
asherah.set_log_hook((level, message) => {
  // level is a number 0..4 (0=trace, 1=debug, 2=info, 3=warn, 4=error)
  console.log(`[level ${level}] ${message}`);
});
```

Log events are delivered via N-API ThreadsafeFunction — they run on the Node
main thread, so synchronous code in the callback is safe.

### Metrics hook

Receive timing events for encrypt/decrypt/store/load and counter events for
cache hit/miss/stale.

```js
asherah.setMetricsHook((event) => {
  switch (event.type) {
    case 'encrypt':
    case 'decrypt':
    case 'store':
    case 'load':
      // event = { type, durationNs }
      myHistogram.observe(event.type, event.durationNs / 1e6);
      break;
    case 'cache_hit':
    case 'cache_miss':
    case 'cache_stale':
      // event = { type, name }
      myCounter.inc({ result: event.type, cache: event.name });
      break;
  }
});

// later:
asherah.setMetricsHook(null);
```

Metrics collection is enabled automatically when a hook is installed, and
disabled when cleared.

## Input contract

**Partition ID** (`null`, `undefined`, `""`): always rejected as
programming errors with `TypeError` (sync) or rejected `Promise`
(async). No row is ever written to the metastore under a degenerate
partition ID.

**Plaintext** to encrypt:
- `null` / `undefined` → `TypeError` from N-API marshalling (sync) or
  rejected `Promise` (async).
- Empty `string` (`""`) and `Buffer.alloc(0)` are **valid** plaintexts.
  `encrypt(...)` / `encryptString(...)` produces a real `DataRowRecord`
  envelope; the matching `decrypt(...)` returns exactly `""` or an
  empty `Buffer`.

**Ciphertext** to decrypt:
- `null` / `undefined` → `TypeError`.
- Empty `string` / empty `Buffer` → `Error` from native layer (not
  valid `DataRowRecord` JSON).

**Do not short-circuit empty plaintext encryption in caller code** —
empty data is real data, encrypting it produces a genuine envelope, and
skipping encryption leaks the fact that the value was empty. See
[docs/input-contract.md](../docs/input-contract.md) for the full
rationale.

## Configuration

All fields can be passed in `camelCase` (native) or `PascalCase` (canonical Go
SDK) — both are auto-mapped. Pass to `setup()`, `setupAsync()`, or the
`SessionFactory` constructor.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `serviceName` | `string` | **required** | Service identifier for the key hierarchy. |
| `productId` | `string` | **required** | Product identifier for the key hierarchy. |
| `metastore` | `'memory' \| 'rdbms' \| 'dynamodb'` | **required** | `'memory'` is testing-only and does not persist across processes. |
| `kms` | `'static' \| 'aws'` | `'static'` | `'static'` is testing-only (uses a hard-coded master key). |
| `connectionString` | `string` | | Connection string for `rdbms` metastore. |
| `sqlMetastoreDbType` | `'mysql' \| 'postgres'` | | SQL driver. |
| `enableSessionCaching` | `boolean` | `true` | Cache `Session` objects by partition ID. |
| `sessionCacheMaxSize` | `number` | `1000` | Max cached sessions. |
| `sessionCacheDuration` | `number` | | Session cache TTL in seconds. |
| `regionMap` | `Record<string, string>` | | AWS KMS multi-region key ARN map. |
| `preferredRegion` | `string` | | Preferred AWS region from `regionMap`. |
| `awsProfileName` | `string` | | AWS shared-credentials profile name (`~/.aws/config`); forwarded to [`aws-config` `profile_name`](https://docs.rs/aws-config/latest/aws_config/struct.ConfigLoader.html#method.profile_name). Optional string, same passthrough semantics as `preferredRegion`. |
| `enableRegionSuffix` | `boolean` | | Append AWS region suffix to key IDs. |
| `expireAfter` | `number` | 90 days | Intermediate-key expiration in seconds. |
| `checkInterval` | `number` | 60 minutes | Revoke-check interval in seconds. |
| `dynamoDbEndpoint` | `string` | | DynamoDB endpoint URL (for local DynamoDB). |
| `dynamoDbRegion` | `string` | | AWS region for DynamoDB. |
| `dynamoDbTableName` | `string` | `'EncryptionKey'` | DynamoDB table name. |
| `dynamoDbSigningRegion` | `string` | | Region used for SigV4 signing. |
| `replicaReadConsistency` | `'eventual' \| 'global' \| 'session'` | | DynamoDB read consistency. |
| `verbose` | `boolean` | `false` | Emit verbose log events (use a log hook to consume). |
| `enableCanaries` | `boolean` | `false` | Enable in-memory canary buffers around plaintexts. |
| `disableZeroCopy` | `boolean` | | Compatibility shim — accepted but no effect. |
| `nullDataCheck` | `boolean` | | Compatibility shim — accepted but no effect. |
| `poolMaxOpen` | `number` | `0` | Max open DB connections (0 = unlimited). |
| `poolMaxIdle` | `number` | `2` | Max idle DB connections to retain. |
| `poolMaxLifetime` | `number` | `0` | Max connection lifetime in seconds (0 = unlimited). |
| `poolMaxIdleTime` | `number` | `0` | Max idle time in seconds per connection (0 = unlimited). |

### Environment variables

| Variable | Effect |
|---|---|
| `STATIC_MASTER_KEY_HEX` | 64 hex chars (32 bytes) for static KMS. **Testing only.** |
| `ASHERAH_NODE_DEBUG=1` | Enable native-side debug logging. |
| `ASHERAH_POOL_MAX_OPEN` | Override `poolMaxOpen`. |
| `ASHERAH_POOL_MAX_IDLE` | Override `poolMaxIdle`. |
| `ASHERAH_POOL_MAX_LIFETIME` | Override `poolMaxLifetime`. |
| `ASHERAH_POOL_MAX_IDLE_TIME` | Override `poolMaxIdleTime`. |

## Performance

Native Rust implementation compiled via napi-rs. Typical latencies on Apple
M4 Max (in-memory metastore, session caching enabled, 64-byte payload):

| Operation | Sync | Async |
|-----------|------|-------|
| Encrypt   | ~970 ns | ~12 µs |
| Decrypt   | ~1.2 µs | ~12 µs |

See `scripts/benchmark.sh` for head-to-head comparisons with the canonical
Go-based implementation.

## Migration from the canonical Go-based `asherah` (v3.x)

Drop-in replacement. The npm wrapper provides full backward compatibility:

- **PascalCase config** — `ServiceName`, `ProductID`, `Metastore`, etc. are
  auto-mapped to camelCase.
- **snake_case function aliases** — `set_log_hook`, `set_metrics_hook`,
  `get_setup_status`, `encrypt_string`, `decrypt_string_async`, etc.
- **Metastore/KMS aliases** — `'test-debug-memory'`, `'test-debug-static'`
  normalize to the short forms.
- **`set_log_hook` signature variants** — both the canonical
  `(level: number, message: string)` and the structured
  `(event: { level, message, target })` are supported.

To migrate: change your dependency from `asherah@^3` to this package. No code
changes required.

## Supported platforms

| Platform | Architecture | Notes |
|----------|--------------|-------|
| Linux    | x64          | glibc (most distros) |
| Linux    | x64          | musl (Alpine) |
| Linux    | ARM64        | glibc |
| Linux    | ARM64        | musl (Alpine) |
| macOS    | x64          | Intel |
| macOS    | ARM64        | Apple Silicon |
| Windows  | x64          | MSVC |
| Windows  | ARM64        | MSVC |

## API Reference

> Full TSDoc lives in `index.d.ts` and surfaces in your IDE on hover. The
> tables below summarize each API; the type file is the source of truth.

### Static / module-level API (legacy compatibility)

#### Lifecycle

| Function | Description |
|---|---|
| `setup(config)` | Initialize the global instance. Throws if already configured. |
| `setupAsync(config)` | Async variant. Returns `Promise<void>`. |
| `shutdown()` | Tear down the global instance and clear cached sessions. Idempotent. |
| `shutdownAsync()` | Async variant. Returns `Promise<void>`. |
| `getSetupStatus()` | `boolean` — true if `setup()` has been called and `shutdown()` has not. |
| `setenv(envJson)` | Apply env vars from a JSON string before `setup()`. Mirrors the canonical SDK. |

#### Encrypt / decrypt

| Function | Param 1 | Param 2 | Returns |
|---|---|---|---|
| `encrypt(partitionId, data)` | `string` (non-empty) | `Buffer` (empty OK) | `string` (DRR JSON) |
| `encryptAsync(partitionId, data)` | `string` | `Buffer` | `Promise<string>` |
| `encryptString(partitionId, data)` | `string` | `string` (empty OK) | `string` (DRR JSON) |
| `encryptStringAsync(partitionId, data)` | `string` | `string` | `Promise<string>` |
| `decrypt(partitionId, drr)` | `string` | `string` (DRR JSON) | `Buffer` |
| `decryptAsync(partitionId, drr)` | `string` | `string` | `Promise<Buffer>` |
| `decryptString(partitionId, drr)` | `string` | `string` | `string` |
| `decryptStringAsync(partitionId, drr)` | `string` | `string` | `Promise<string>` |

All accept the snake_case aliases `encrypt_async`, `encrypt_string`,
`encrypt_string_async`, `decrypt_async`, `decrypt_string`,
`decrypt_string_async`, `setup_async`, `shutdown_async`, `get_setup_status`.

#### Hooks

| Function | Description |
|---|---|
| `setLogHook(cb)` / `set_log_hook(cb)` | Register a structured-event log callback. Pass `null` to deregister. The snake_case alias also accepts the canonical `(level, message)` signature. |
| `setMetricsHook(cb)` / `set_metrics_hook(cb)` | Register a metrics callback. Pass `null` to deregister. |

### Factory / Session API (recommended)

#### `class SessionFactory`

| Member | Description |
|---|---|
| `new SessionFactory(config)` | Construct from inline config. |
| `static SessionFactory.fromEnv()` | Construct from environment variables. |
| `factory.getSession(partitionId)` | Get a per-partition session. Throws on null/empty partition. |
| `factory.close()` | Release native resources. After close, `getSession()` throws. |

#### `class AsherahSession`

| Member | Description |
|---|---|
| `session.encrypt(data)` | `Buffer` → DRR JSON `string`. Empty `Buffer` is valid. |
| `session.encryptString(data)` | `string` → DRR JSON `string`. Empty `string` is valid. |
| `session.decrypt(drr)` | DRR JSON `string` → `Buffer`. |
| `session.decryptString(drr)` | DRR JSON `string` → `string`. |
| `session.close()` | Release native resources. |

### Type aliases

```ts
type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

type LogEvent = {
  level: LogLevel;
  message: string;
  target: string;
};

type MetricsEvent =
  | { type: 'encrypt' | 'decrypt' | 'store' | 'load'; durationNs: number }
  | { type: 'cache_hit' | 'cache_miss' | 'cache_stale'; name: string };
```

### Compatibility shims

`setMaxStackAllocItemSize(n)` and `setSafetyPaddingOverhead(n)` are accepted
for parity with the canonical Go-based asherah-node package but have no
effect in this Rust binding.

## License

Licensed under the Apache License, Version 2.0.
