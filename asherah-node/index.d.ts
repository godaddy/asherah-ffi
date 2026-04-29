/// <reference types="node" />

// ============================================================================
//
// Asherah for Node.js
//
// Application-layer envelope encryption with automatic key rotation and a
// pluggable KMS / metastore. Drop-in compatible with the canonical
// `asherah` npm package (PascalCase config + snake_case API aliases) and
// significantly faster (Rust core via napi-rs).
//
// Two API styles are exposed; both are fully supported and produce the
// same wire format:
//
//   1. **Static / module-level API** (legacy): `setup()` once at process
//      startup, then call free `encrypt()` / `decrypt()` functions on the
//      module. This mirrors the canonical `godaddy/asherah-node` API and
//      is the easiest path for existing callers to migrate.
//
//   2. **Factory / Session API** (recommended for new code): construct a
//      `SessionFactory`, hold one or more `AsherahSession` instances, and
//      call `encrypt()` / `decrypt()` on the session. This avoids the
//      hidden-singleton lifecycle of the static API and makes session
//      isolation explicit per partition.
//
// See `samples/node/index.mjs` for a runnable end-to-end example covering
// both styles plus async, log hook, metrics hook, and config variants.
//
// ============================================================================

// ─── Configuration types ────────────────────────────────────────────────────

/**
 * Asherah configuration object using camelCase field names. This is the
 * native shape; it is passed to `setup()`, `setupAsync()`, and the
 * `SessionFactory` constructor.
 *
 * The PascalCase variant ({@link AsherahConfigCompat}) is also accepted
 * everywhere this type is — fields are auto-mapped for compatibility with
 * the canonical Go-based asherah package.
 */
export type AsherahConfig = {
  /** Service name. Forms part of the key hierarchy partition path. Required. */
  serviceName: string;

  /** Product ID. Forms part of the key hierarchy partition path. Required. */
  productId: string;

  /** Intermediate-key expiration in seconds. Default: 90 days. */
  expireAfter?: number | null;

  /** Revoke-check interval in seconds — how often to re-read parent keys
   *  to pick up revocation. Default: 60 minutes. */
  checkInterval?: number | null;

  /** Metastore backend. `'memory'` is testing-only and will not persist
   *  across processes. */
  metastore: 'memory' | 'rdbms' | 'dynamodb';

  /** SQL connection string when `metastore` is `'rdbms'`. Format depends
   *  on `sqlMetastoreDbType`. */
  connectionString?: string | null;

  /** RDBMS replica read consistency: `'eventual'`, `'global'`, or `'session'`. */
  replicaReadConsistency?: string | null;

  /** DynamoDB endpoint URL (typically only set for local DynamoDB). */
  dynamoDbEndpoint?: string | null;
  /** AWS region for DynamoDB. */
  dynamoDbRegion?: string | null;
  /** DynamoDB table name. Default: `EncryptionKey`. */
  dynamoDbTableName?: string | null;
  /** AWS region used for SigV4 signing of DynamoDB requests. */
  dynamoDbSigningRegion?: string | null;

  /** @deprecated Use `dynamoDbEndpoint` (lowercase `b`). */
  dynamoDBEndpoint?: string | null;
  /** @deprecated Use `dynamoDbRegion` (lowercase `b`). */
  dynamoDBRegion?: string | null;
  /** @deprecated Use `dynamoDbTableName` (lowercase `b`). */
  dynamoDBTableName?: string | null;

  /** Maximum number of cached sessions. */
  sessionCacheMaxSize?: number | null;
  /** Session cache TTL in seconds. */
  sessionCacheDuration?: number | null;

  /** KMS backend. `'static'` is testing-only (uses a hard-coded master key). */
  kms?: 'aws' | 'static' | null;

  /** AWS KMS region-to-key-ARN map for multi-region KMS. */
  regionMap?: Record<string, string> | null;
  /** Preferred AWS region when `regionMap` is set. */
  preferredRegion?: string | null;
  /** AWS shared-credentials profile name (typically from `~/.aws/credentials`); forwarded to the Rust aws-config loader for KMS, DynamoDB, and Secrets Manager clients. Omit to use the default credential chain. */
  awsProfileName?: string | null;
  /** Append the AWS region as a suffix to the key ID. */
  enableRegionSuffix?: boolean | null;

  /** Cache `Session` objects by partition ID. Default: `true`. */
  enableSessionCaching?: boolean | null;

  /** Emit verbose log events at the `info`/`debug` level. Use a log hook
   *  ({@link setLogHook}) to consume them. */
  verbose?: boolean | null;

  /** SQL driver: `'mysql'` or `'postgres'` (used with `metastore: 'rdbms'`). */
  sqlMetastoreDbType?: string | null;
  /** @deprecated Use `sqlMetastoreDbType` (lowercase `b`). */
  sqlMetastoreDBType?: string | null;

  /** Compatibility shim for the canonical Go-based asherah-node package.
   *  Has no effect in this Rust-based binding (which is always zero-copy
   *  where possible). */
  disableZeroCopy?: boolean | null;
  /** Compatibility shim — accepted but has no effect (this binding always
   *  validates inputs). */
  nullDataCheck?: boolean | null;
  /** Enable in-memory canary buffers around plaintexts. Costs a small
   *  amount of allocation overhead per operation. */
  enableCanaries?: boolean | null;
};

/**
 * Asherah configuration in canonical PascalCase format, matching the
 * canonical `asherah` npm package. Accepted everywhere {@link AsherahConfig}
 * is — fields are auto-mapped on the way in.
 */
export type AsherahConfigCompat = {
  readonly ServiceName: string;
  readonly ProductID: string;
  readonly ExpireAfter?: number | null;
  readonly CheckInterval?: number | null;
  readonly Metastore: 'memory' | 'rdbms' | 'dynamodb' | 'test-debug-memory';
  readonly ConnectionString?: string | null;
  readonly DynamoDBEndpoint?: string | null;
  readonly DynamoDBRegion?: string | null;
  readonly DynamoDBTableName?: string | null;
  readonly SessionCacheMaxSize?: number | null;
  readonly SessionCacheDuration?: number | null;
  readonly KMS?: 'aws' | 'static' | 'test-debug-static' | null;
  readonly RegionMap?: Record<string, string> | null;
  readonly PreferredRegion?: string | null;
  readonly AwsProfileName?: string | null;
  readonly EnableRegionSuffix?: boolean | null;
  readonly EnableSessionCaching?: boolean | null;
  readonly Verbose?: boolean | null;
  readonly SQLMetastoreDBType?: string | null;
  readonly ReplicaReadConsistency?: 'eventual' | 'global' | 'session' | null;
  readonly DisableZeroCopy?: boolean | null;
  readonly NullDataCheck?: boolean | null;
  readonly EnableCanaries?: boolean | null;
};

// ─── Static / module-level API (legacy) ─────────────────────────────────────

/**
 * Initialize the global Asherah instance. Must be called once before any
 * `encrypt()` / `decrypt()` call on the static API.
 *
 * Subsequent calls to `setup()` without an intervening `shutdown()` throw.
 * For new code, prefer the {@link SessionFactory} API, which avoids the
 * hidden-singleton lifecycle.
 *
 * @example
 * ```js
 * const asherah = require('asherah');
 * asherah.setup({
 *   serviceName: 'my-svc',
 *   productId: 'my-prod',
 *   metastore: 'memory',     // production: 'rdbms' or 'dynamodb'
 *   kms: 'static',           // production: 'aws'
 * });
 * ```
 *
 * @throws if Asherah is already configured (call {@link shutdown} first)
 *         or if the config is invalid.
 */
export declare function setup(config: AsherahConfig | AsherahConfigCompat): void;

/**
 * Async variant of {@link setup}. Resolves once the global instance is
 * configured and the metastore/KMS are reachable. Safe to call from an
 * async context — does not block the Node event loop on KMS/SDK setup.
 */
export declare function setupAsync(config: AsherahConfig | AsherahConfigCompat): Promise<void>;

/**
 * Tear down the global Asherah instance. Releases the native factory and
 * clears any cached sessions. Idempotent — calling on an already-shut-down
 * instance is a no-op.
 */
export declare function shutdown(): void;

/** Async variant of {@link shutdown}. */
export declare function shutdownAsync(): Promise<void>;

/** Returns `true` when {@link setup} has been called and {@link shutdown}
 *  has not yet been called. */
export declare function getSetupStatus(): boolean;

/**
 * Apply a JSON object of environment variables before {@link setup} is
 * called. Equivalent to `process.env[k] = v` for each entry, but evaluated
 * by the native side so configuration via env-var works identically to
 * the canonical SDK.
 *
 * @param env JSON string. Keys must be strings; values may be strings or
 *            `null` (a `null` value unsets the variable).
 */
export declare function setenv(env: string): void;

/**
 * Encrypt `data` for the given partition. Returns a `DataRowRecord` JSON
 * string suitable for storing in a database column.
 *
 * @param partitionId Tenant / user / record-owner identifier. Must be
 *                    non-empty — `null`, `undefined`, and `""` are
 *                    rejected as programming errors.
 * @param data Plaintext bytes. Empty `Buffer` is **valid** and round-trips
 *             to an empty `Buffer` on decrypt — do not short-circuit empty
 *             inputs in caller code (see docs/input-contract.md).
 * @returns The full `DataRowRecord` JSON envelope (Key, Data,
 *          ParentKeyMeta).
 * @throws TypeError if `partitionId` or `data` is null/undefined.
 * @throws Error from the native layer on encryption failure.
 *
 * @example
 * ```js
 * const drr = asherah.encrypt('user-42', Buffer.from('secret'));
 * // store drr in your database
 * ```
 */
export declare function encrypt(partitionId: string, data: Buffer): string;

/** Async variant of {@link encrypt}. The work runs on the Rust tokio
 *  runtime; the Node event loop is NOT blocked. */
export declare function encryptAsync(partitionId: string, data: Buffer): Promise<string>;

/**
 * Decrypt a `DataRowRecord` JSON string produced by {@link encrypt}.
 *
 * @param partitionId Must match the partition the value was encrypted
 *                    under. Non-empty.
 * @param dataRowRecordJson The DRR JSON envelope as a string.
 * @returns Plaintext as a `Buffer`. Length 0 if the original plaintext
 *          was empty — empty round-trips to empty.
 * @throws TypeError if either argument is null/undefined.
 * @throws Error if the JSON is malformed, the partition doesn't match,
 *               the parent key has been revoked, or the AEAD tag fails.
 */
export declare function decrypt(partitionId: string, dataRowRecordJson: string): Buffer;

/** Async variant of {@link decrypt}. */
export declare function decryptAsync(partitionId: string, dataRowRecordJson: string): Promise<Buffer>;

/** UTF-8 string-typed wrapper around {@link encrypt}. Empty `string`
 *  ("") is valid and round-trips. */
export declare function encryptString(partitionId: string, data: string): string;

/** Async variant of {@link encryptString}. */
export declare function encryptStringAsync(partitionId: string, data: string): Promise<string>;

/** UTF-8 string-typed wrapper around {@link decrypt}. */
export declare function decryptString(partitionId: string, dataRowRecordJson: string): string;

/** Async variant of {@link decryptString}. */
export declare function decryptStringAsync(partitionId: string, dataRowRecordJson: string): Promise<string>;

// ─── Factory / Session API (recommended) ────────────────────────────────────

/**
 * Factory for creating per-partition `AsherahSession` instances. Holding
 * a long-lived factory is cheaper than calling `setup()`/`shutdown()`
 * repeatedly and makes session isolation explicit.
 *
 * @example
 * ```js
 * const factory = new asherah.SessionFactory({
 *   serviceName: 'my-svc',
 *   productId: 'my-prod',
 *   metastore: 'memory',
 *   kms: 'static',
 * });
 * const session = factory.getSession('user-42');
 * try {
 *   const ct = session.encryptString('secret');
 *   const pt = session.decryptString(ct);
 * } finally {
 *   session.close();
 *   factory.close();
 * }
 * ```
 */
export declare class SessionFactory {
  /** Construct a factory from an inline config object. */
  constructor(config: AsherahConfig | AsherahConfigCompat);

  /** Construct a factory from environment variables (for parity with the
   *  canonical Go-based asherah module). */
  static fromEnv(): SessionFactory;

  /**
   * Get a session for the given partition. Sessions returned for the same
   * partition share the underlying intermediate key; different partitions
   * are cryptographically isolated.
   *
   * @param partitionId Non-empty tenant / record-owner identifier.
   * @throws TypeError if `partitionId` is null/undefined.
   * @throws Error if `partitionId` is the empty string.
   */
  getSession(partitionId: string): AsherahSession;

  /** Release native resources. After `close()`, `getSession()` will throw. */
  close(): void;
}

/**
 * Per-partition encrypt/decrypt session. Created via
 * {@link SessionFactory.getSession}. Always pair with `close()` to release
 * native resources promptly.
 */
export declare class AsherahSession {
  /** Encrypt a `Buffer` and return the DRR JSON. Empty `Buffer` is valid. */
  encrypt(data: Buffer): string;
  /** Encrypt a UTF-8 string and return the DRR JSON. Empty string is valid. */
  encryptString(data: string): string;
  /** Decrypt a DRR JSON string and return the plaintext as a `Buffer`. */
  decrypt(dataRowRecordJson: string): Buffer;
  /** Decrypt a DRR JSON string and return the plaintext as a UTF-8 string. */
  decryptString(dataRowRecordJson: string): string;
  /** Release native resources. */
  close(): void;
}

// ─── Observability hooks ────────────────────────────────────────────────────

/** Log severity strings carried in {@link LogEvent.level}. */
export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

/**
 * Structured log event delivered to a log hook. Includes the source
 * `target` (typically the Rust module path that emitted the log) and the
 * formatted `message`.
 */
export type LogEvent = {
  /** Severity. Mirrors the Rust `log::Level`. */
  level: LogLevel;
  /** Formatted log message. */
  message: string;
  /** Source module / target string. Useful for filtering. */
  target: string;
};

/** Numeric-level callback for compatibility with the canonical
 *  `godaddy/asherah-node` log hook signature. New code should prefer the
 *  structured {@link LogEvent} variant. */
export type LogHookCallback = (level: number, message: string) => void;

/**
 * Metrics event delivered to a metrics hook. Timing events
 * (`encrypt`/`decrypt`/`store`/`load`) carry `durationNs`; cache events
 * (`cache_hit`/`cache_miss`/`cache_stale`) carry the cache `name`.
 */
export type MetricsEvent =
  | { type: 'encrypt' | 'decrypt' | 'store' | 'load'; durationNs: number }
  | { type: 'cache_hit' | 'cache_miss' | 'cache_stale'; name: string };

/**
 * Install a callback that fires for every log event emitted by the Rust
 * core (encrypt/decrypt path, metastore drivers, KMS clients, etc.).
 *
 * Pass `null` to deregister.
 *
 * Callbacks may fire from any thread (Rust tokio worker threads, DB
 * driver threads). The N-API ThreadsafeFunction layer marshals each
 * event back to the Node event loop, so the callback runs on the main
 * thread — synchronous code in the callback is safe.
 *
 * @example
 * ```js
 * asherah.setLogHook((event) => {
 *   if (event.level === 'warn' || event.level === 'error') {
 *     console.error(`[asherah ${event.level}] ${event.message}`);
 *   }
 * });
 * ```
 */
export declare function setLogHook(
  hook: ((event: LogEvent) => void) | LogHookCallback | null,
): void;

/**
 * Install a callback that fires for every metrics event (encrypt/decrypt
 * timings, store/load timings, cache hit/miss/stale counters).
 *
 * Pass `null` to deregister. Same threading semantics as
 * {@link setLogHook}.
 *
 * @example
 * ```js
 * asherah.setMetricsHook((event) => {
 *   if (event.type === 'encrypt') {
 *     histogram.observe(event.durationNs / 1e6); // ms
 *   } else if (event.type === 'cache_miss') {
 *     counter.inc({ cache: event.name });
 *   }
 * });
 * ```
 */
export declare function setMetricsHook(
  hook: ((event: MetricsEvent) => void) | null,
): void;

// ─── Performance tuning ─────────────────────────────────────────────────────

/** Compatibility shim — accepted but has no effect in the Rust binding
 *  (which manages its own buffer allocation strategy). Provided for API
 *  parity with the canonical Go-based asherah-node package. */
export declare function setMaxStackAllocItemSize(n: number): void;

/** Compatibility shim — accepted but has no effect. */
export declare function setSafetyPaddingOverhead(n: number): void;

// ─── snake_case aliases (canonical asherah-node compatibility) ──────────────

/** Alias for {@link setupAsync}. */
export declare function setup_async(config: AsherahConfig | AsherahConfigCompat): Promise<void>;
/** Alias for {@link shutdownAsync}. */
export declare function shutdown_async(): Promise<void>;
/** Alias for {@link encryptAsync}. */
export declare function encrypt_async(partitionId: string, data: Buffer): Promise<string>;
/** Alias for {@link encryptString}. */
export declare function encrypt_string(partitionId: string, data: string): string;
/** Alias for {@link encryptStringAsync}. */
export declare function encrypt_string_async(partitionId: string, data: string): Promise<string>;
/** Alias for {@link decryptAsync}. */
export declare function decrypt_async(partitionId: string, dataRowRecordJson: string): Promise<Buffer>;
/** Alias for {@link decryptString}. */
export declare function decrypt_string(partitionId: string, dataRowRecordJson: string): string;
/** Alias for {@link decryptStringAsync}. */
export declare function decrypt_string_async(partitionId: string, dataRowRecordJson: string): Promise<string>;
/** Alias for {@link setMaxStackAllocItemSize}. */
export declare function set_max_stack_alloc_item_size(n: number): void;
/** Alias for {@link setSafetyPaddingOverhead}. */
export declare function set_safety_padding_overhead(n: number): void;
/** Alias for {@link setLogHook}. */
export declare function set_log_hook(
  hook: ((event: LogEvent) => void) | LogHookCallback | null,
): void;
/** Alias for {@link setMetricsHook}. */
export declare function set_metrics_hook(
  hook: ((event: MetricsEvent) => void) | null,
): void;
/** Alias for {@link getSetupStatus}. */
export declare function get_setup_status(): boolean;
