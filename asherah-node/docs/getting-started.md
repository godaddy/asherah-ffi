# Getting started

Step-by-step walkthrough from `npm install` to a round-trip
encrypt/decrypt. After this guide, see:

- [`framework-integration.md`](./framework-integration.md) — Express,
  Fastify, NestJS, Koa, AWS Lambda integration patterns.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  configuration with AWS KMS and DynamoDB.
- [`testing.md`](./testing.md) — testing strategies (in-memory
  metastore, static KMS, Jest/Vitest fixtures, mocking).
- [`troubleshooting.md`](./troubleshooting.md) — common errors and
  fixes.

## 1. Install the package

```bash
npm install asherah
```

Requires Node.js ≥ 18. Prebuilt native binaries ship for Linux
(x64/arm64, glibc and musl), macOS (x64/arm64), and Windows
(x64/arm64). The correct binary is selected automatically at install
time.

## 2. Pick an API style

Two coexisting API surfaces — same wire format, same native core:

| Style | Entry points | Use when |
|---|---|---|
| Static / module-level | `asherah.setup()`, `asherah.encryptString()`, … | Configure once, encrypt/decrypt with a partition id. Drop-in compatible with the canonical `godaddy/asherah-node` API. |
| Factory / Session | `new SessionFactory(config)`, `factory.getSession(id)`, `session.encryptString(...)` | Explicit lifecycle, multiple factories with different configs in one process, multi-tenant isolation visible in code. |

There's no functional difference — the static API is a thin convenience
wrapper over the factory/session API. Pick by which one reads better at
your call sites.

## 3. Configure

Both styles use the same config object:

```javascript
import asherah from "asherah";

// Testing-only static master key. Production must use AWS KMS;
// see aws-production-setup.md.
process.env.STATIC_MASTER_KEY_HEX = "22".repeat(32);

const config = {
  serviceName: "my-service",
  productId: "my-product",
  metastore: "memory",       // testing only — use "rdbms" or "dynamodb" in production
  kms: "static",             // testing only — use "aws" in production
  enableSessionCaching: true,
};
```

`serviceName` and `productId` form the prefix for generated
intermediate-key IDs. Pick stable values — changing them later
orphans existing envelope keys.

For the complete builder option table, see the **Configuration**
section of the [main README](../README.md#configuration).

## 4. Encrypt and decrypt — static API

```javascript
asherah.setup(config);
try {
  const ciphertext = asherah.encryptString("user-42", "secret");
  // Persist `ciphertext` (a JSON string) to your storage layer.

  // Later, after reading it back:
  const plaintext = asherah.decryptString("user-42", ciphertext);
  console.log(plaintext);   // "secret"
} finally {
  asherah.shutdown();
}
```

`setup` configures the process-global instance — call once at startup.
`shutdown` releases native resources — call once at shutdown. Sessions
are cached internally per partition id (default cap 1000, LRU-evicted).

For binary payloads use `asherah.encrypt(partitionId, Buffer)` /
`asherah.decrypt(partitionId, Buffer)`.

## 5. Encrypt and decrypt — factory / session API

```javascript
import { SessionFactory } from "asherah";

const factory = new SessionFactory(config);
try {
  const session = factory.getSession("user-42");
  try {
    const ciphertext = session.encryptString("secret");
    const plaintext = session.decryptString(ciphertext);
  } finally {
    session.close();
  }
} finally {
  factory.close();
}
```

The factory and session both expose `close()` and must be closed
explicitly to release native resources. Factories are concurrency-safe
and cache sessions per partition by default — `factory.getSession("u")`
returns the same session instance until evicted.

## 6. Async API

Every sync method has an `*Async` counterpart that runs on the Rust
tokio runtime — the Node.js event loop is not blocked while the
metastore or KMS is I/O-bound:

```javascript
await asherah.setupAsync(config);

const ciphertext = await asherah.encryptStringAsync("user-42", "secret");
const plaintext = await asherah.decryptStringAsync("user-42", ciphertext);

await asherah.shutdownAsync();
```

> **Sync vs async:** prefer sync for Asherah's hot encrypt/decrypt
> paths. The native operation is sub-microsecond — async dispatch
> overhead is larger than the work itself for in-memory and warm cache
> scenarios. Use `*Async` in HTTP request handlers (Express middleware,
> Fastify routes, Lambda handlers) where you're already on an async
> context that touches a network metastore (DynamoDB, MySQL, Postgres)
> and the I/O actually warrants yielding.

## 7. Wire up observability

```javascript
import asherah from "asherah";

// Log records → your callback. Every event from the Rust core
// (encrypt/decrypt path, metastore drivers, KMS clients) flows here.
asherah.setLogHook((level, target, message) => {
  console.log(`[asherah ${level}] ${target}: ${message}`);
});

// Metrics events → your callback. Encrypt/decrypt timings, metastore
// store/load timings, key cache hit/miss/stale counters.
asherah.setMetricsHook((eventType, durationNs, name) => {
  if (eventType === "encrypt" || eventType === "decrypt") {
    myHistogram.observe(eventType, durationNs / 1e6);   // ms
  }
});
```

Hooks are process-global and apply to every factory/session in the
process regardless of which API style created them.

`setLogHookSync` and `setMetricsHookSync` variants fire on the
encrypt/decrypt thread before the operation returns — pick those if
you need thread-local context (trace IDs) intact in the callback or
have verifiably non-blocking handlers. Trade-off: a slow sync callback
extends operation latency.

## 8. Move to production

The example above uses `metastore: "memory"` and `kms: "static"` —
both **testing only**. Memory metastore loses keys on process restart;
static KMS uses a hardcoded master key. For real deployments, follow
[`aws-production-setup.md`](./aws-production-setup.md).

## 9. Handle errors

Asherah surfaces errors via thrown `Error` objects (or rejected
Promises in the async API). Specific error shapes and what to check
first are in [`troubleshooting.md`](./troubleshooting.md).

Common shapes:
- `TypeError: ...` — null/undefined where a value was required
  (programming error).
- `Error: partition id cannot be empty` — empty partition string
  (rejected at the API boundary).
- `Error: decrypt_from_json: ...` — malformed envelope on decrypt.
- `Error: factory_from_config: ...` — invalid config or KMS/metastore
  unreachable.

## What's next

- [`framework-integration.md`](./framework-integration.md) — Express,
  Fastify, NestJS, Koa, AWS Lambda.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS config from KMS key creation through IAM policy.
- The complete [sample app](../../samples/node/index.mjs) exercises
  every API style + async + log hook + metrics hook in one runnable
  program.
