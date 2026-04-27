# asherah-java

Java bindings (JNI) for [Asherah](https://github.com/godaddy/asherah-ffi) envelope encryption with automatic key rotation. Published to GitHub Packages Maven.

## Installation

### Maven

```xml
<dependency>
  <groupId>com.godaddy.asherah</groupId>
  <artifactId>appencryption</artifactId>
  <version>0.6.64</version>
</dependency>
```

Add the GitHub Packages repository:

```xml
<repositories>
  <repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/godaddy/asherah-ffi</url>
  </repository>
</repositories>
```

### Gradle

```groovy
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/godaddy/asherah-ffi")
    }
}

dependencies {
    implementation 'com.godaddy.asherah:appencryption:0.6.64'
}
```

The package includes prebuilt native JNI libraries for Linux x64/ARM64, macOS x64/ARM64, and Windows x64/ARM64.

## Quick Start

The simplest way to use Asherah is the static API on the `Asherah` class. Call `setup()` once at startup and `shutdown()` on exit:

```java
import com.godaddy.asherah.jni.Asherah;
import com.godaddy.asherah.jni.AsherahConfig;

AsherahConfig config = AsherahConfig.builder()
        .serviceName("my-service")
        .productId("my-product")
        .metastore("memory")   // testing only
        .kms("static")         // testing only
        .enableSessionCaching(Boolean.TRUE)
        .build();

Asherah.setup(config);
try {
    String ciphertext = Asherah.encryptString("partition-id", "sensitive data");
    String plaintext = Asherah.decryptString("partition-id", ciphertext);
} finally {
    Asherah.shutdown();
}
```

The static API manages a session cache internally. Sessions are created on first use per partition and reused for subsequent calls.

## Factory/Session API

For direct control over session lifecycle, use `AsherahFactory` and `AsherahSession`:

```java
import com.godaddy.asherah.jni.Asherah;
import com.godaddy.asherah.jni.AsherahConfig;
import com.godaddy.asherah.jni.AsherahFactory;
import com.godaddy.asherah.jni.AsherahSession;

AsherahConfig config = AsherahConfig.builder()
        .serviceName("my-service")
        .productId("my-product")
        .metastore("memory")   // testing only
        .kms("static")         // testing only
        .build();

try (AsherahFactory factory = Asherah.factoryFromConfig(config)) {
    try (AsherahSession session = factory.getSession("partition-id")) {
        byte[] ciphertext = session.encryptBytes("sensitive data".getBytes());
        byte[] plaintext = session.decryptBytes(ciphertext);

        // String convenience methods
        String ct = session.encryptString("sensitive data");
        String pt = session.decryptString(ct);
    }
}
```

Both `AsherahFactory` and `AsherahSession` implement `AutoCloseable` and are backed by a `Cleaner` for safety-net finalization.

## Async API

Every encrypt/decrypt method has a `CompletableFuture` variant.

### Static async API

```java
CompletableFuture<byte[]> ct = Asherah.encryptAsync("partition", plaintext);
CompletableFuture<byte[]> pt = Asherah.decryptAsync("partition", ct.get());

// String variants
CompletableFuture<String> ctStr = Asherah.encryptStringAsync("partition", "data");
CompletableFuture<String> ptStr = Asherah.decryptStringAsync("partition", ctStr.get());
```

### Session async API (true async)

```java
try (AsherahSession session = factory.getSession("partition-id")) {
    CompletableFuture<byte[]> ct = session.encryptBytesAsync(plaintext);
    CompletableFuture<byte[]> pt = session.decryptBytesAsync(ct.get());

    CompletableFuture<String> ctStr = session.encryptStringAsync("data");
    CompletableFuture<String> ptStr = session.decryptStringAsync(ctStr.get());
}
```

### Async Behavior

The session-level async methods (`encryptBytesAsync`, `decryptBytesAsync`, etc.) are true async -- the encrypt/decrypt work runs on Rust's tokio runtime and completes the `CompletableFuture` via JNI `AttachCurrentThread`. The calling Java thread is NOT blocked during the native operation.

The static-level async methods (`Asherah.encryptAsync`, `Asherah.decryptAsync`) dispatch to `ForkJoinPool.commonPool()` via `CompletableFuture.supplyAsync()`.

Overhead: approximately 8 microseconds for async vs 1.1 microseconds for sync (64B hot cache). Use async when you need non-blocking behavior; use sync for lowest latency.

## Input contract

**Partition ID** (`null`, `""`): always rejected as programming errors
with `NullPointerException` / `IllegalArgumentException`. No row is
ever written to the metastore under a degenerate partition ID.
(Canonical `com.godaddy.asherah:appencryption` v0.4.0 accepts `null`
partitions and persists `_IK_null_service_product` rows; this binding
is deliberately stricter.)

**Plaintext** to encrypt:
- `null` → `NullPointerException` (sync) / rejected `CompletableFuture`
  (async).
- Empty `String` (`""`) and `new byte[0]` are **valid** plaintexts.
  `encrypt(...)` produces a real `DataRowRecord` envelope; the matching
  `decrypt(...)` returns exactly `""` or `new byte[0]`.

**Ciphertext** to decrypt:
- `null` → `NullPointerException`.
- Empty `String` / `byte[]` → runtime exception from JSON parse (not
  valid `DataRowRecord`).

**Do not short-circuit empty plaintext encryption in caller code** —
empty data is real data, encrypting it produces a genuine envelope, and
skipping encryption leaks the fact that the value was empty. See
[docs/input-contract.md](../docs/input-contract.md) for the full
rationale.

## Migration from Canonical Java SDK

This replaces the canonical `com.godaddy.asherah:appencryption` (v0.3.3), which is a pure Java implementation using Protobuf serialization. This Rust-backed binding is wire-compatible (reads/writes the same metastore format) and significantly faster.

Key differences:

| | Canonical (`appencryption`) | This binding (`asherah-java`) |
|---|---|---|
| Implementation | Pure Java + Protobuf | Rust + JNI |
| Serialization | Protobuf | JSON |
| Configuration | Builder pattern | `AsherahConfig.builder()` |
| Session model | `AppEncryptionSessionFactory` | `AsherahFactory` / `AsherahSession` |
| Memory protection | None | memguard (locked, wiped pages) |
| Async support | None | `CompletableFuture` |

Migration steps:
1. Update the `com.godaddy.asherah:appencryption` version to this implementation (same coordinates)
2. Update the repository URL to `https://maven.pkg.github.com/godaddy/asherah-ffi`
3. Replace `AppEncryptionSessionFactory` with `AsherahFactory` or the static `Asherah` API
4. Both read the same metastore tables -- no data migration required

## Performance

Benchmarked on Apple M4 Max, 64-byte payload, hot session cache:

| Operation | Latency |
|---|---|
| Encrypt | ~1,118 ns |
| Decrypt | ~974 ns |

## Configuration

All configuration is done through `AsherahConfig.builder()`:

| Builder Method | Type | Required | Description |
|---|---|---|---|
| `serviceName` | `String` | Yes | Service identifier for key hierarchy |
| `productId` | `String` | Yes | Product identifier for key hierarchy |
| `metastore` | `String` | Yes | `"rdbms"`, `"dynamodb"`, `"memory"` (testing) |
| `kms` | `String` | No | `"static"` (default) or `"aws"` |
| `connectionString` | `String` | No | RDBMS connection string |
| `dynamoDbEndpoint` | `String` | No | Custom DynamoDB endpoint |
| `dynamoDbRegion` | `String` | No | DynamoDB region |
| `dynamoDbSigningRegion` | `String` | No | DynamoDB signing region |
| `dynamoDbTableName` | `String` | No | DynamoDB table name |
| `regionMap` | `Map<String, String>` | No | AWS KMS region-to-ARN map |
| `preferredRegion` | `String` | No | Preferred AWS KMS region |
| `enableRegionSuffix` | `Boolean` | No | Append region suffix to key IDs |
| `enableSessionCaching` | `Boolean` | No | Enable session caching (default: true) |
| `sessionCacheMaxSize` | `Integer` | No | Max cached sessions |
| `sessionCacheDuration` | `Long` | No | Cache TTL in milliseconds |
| `expireAfter` | `Long` | No | Key expiration in seconds |
| `checkInterval` | `Long` | No | Key check interval in seconds |
| `replicaReadConsistency` | `String` | No | DynamoDB read consistency |
| `verbose` | `Boolean` | No | Enable verbose logging (default: false) |
| `poolMaxOpen` | `Integer` | No | Max open DB connections (default: 0 = unlimited) |
| `poolMaxIdle` | `Integer` | No | Max idle connections to retain (default: 2) |
| `poolMaxLifetime` | `Long` | No | Max connection lifetime in seconds (default: 0 = unlimited) |
| `poolMaxIdleTime` | `Long` | No | Max idle time per connection in seconds (default: 0 = unlimited) |

You can also initialize from environment variables:

```java
AsherahFactory factory = Asherah.factoryFromEnv();
```

## API Reference

### `Asherah` (static API)

| Method | Description |
|---|---|
| `setup(AsherahConfig)` | Initialize the global factory |
| `setupAsync(AsherahConfig)` | Async variant of `setup` |
| `shutdown()` | Release all resources and cached sessions |
| `shutdownAsync()` | Async variant of `shutdown` |
| `getSetupStatus()` | Returns `true` if initialized |
| `encrypt(String, byte[])` | Encrypt bytes, returns DRR JSON bytes |
| `encryptString(String, String)` | Encrypt string, returns DRR JSON string |
| `encryptAsync(String, byte[])` | Async encrypt returning `CompletableFuture<byte[]>` |
| `encryptStringAsync(String, String)` | Async encrypt returning `CompletableFuture<String>` |
| `decrypt(String, byte[])` | Decrypt DRR JSON bytes to plaintext bytes |
| `decryptString(String, String)` | Decrypt DRR JSON string to plaintext string |
| `decryptJson(String, String)` | Decrypt DRR JSON string to plaintext bytes |
| `decryptAsync(String, byte[])` | Async decrypt returning `CompletableFuture<byte[]>` |
| `decryptStringAsync(String, String)` | Async decrypt returning `CompletableFuture<String>` |
| `factoryFromConfig(AsherahConfig)` | Create a standalone factory |
| `factoryFromEnv()` | Create a factory from environment variables |
| `setEnv(Map<String, String>)` | Set environment variables |
| `setEnvJson(String)` | Set environment variables from JSON string |

### `AsherahFactory`

| Method | Description |
|---|---|
| `getSession(String)` | Create a session for a partition ID |
| `close()` | Release the factory (implements `AutoCloseable`) |

### `AsherahSession`

| Method | Description |
|---|---|
| `encryptBytes(byte[])` | Encrypt bytes, returns DRR JSON bytes |
| `encryptString(String)` | Encrypt string, returns DRR JSON string |
| `encryptToJson(byte[])` | Encrypt bytes, returns DRR JSON string |
| `encryptBytesAsync(byte[])` | True async encrypt via tokio |
| `encryptStringAsync(String)` | True async encrypt, string variant |
| `decryptBytes(byte[])` | Decrypt DRR JSON bytes to plaintext bytes |
| `decryptString(String)` | Decrypt DRR JSON string to plaintext string |
| `decryptFromJson(String)` | Decrypt DRR JSON string to plaintext bytes |
| `decryptBytesAsync(byte[])` | True async decrypt via tokio |
| `decryptStringAsync(String)` | True async decrypt, string variant |
| `close()` | Release the session (implements `AutoCloseable`) |

## Observability hooks

### Log hook

Asherah ships first-class SLF4J integration. The simplest way to wire up
logging is to hand it an SLF4J `Logger` directly — the bridge dispatches each
record at its native severity, so any backend the host has bound SLF4J to
(Logback, Log4j 2, `java.util.logging`) receives it without translation.

```java
import com.godaddy.asherah.jni.Asherah;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

Logger asherahLog = LoggerFactory.getLogger("asherah");
Asherah.setLogHook(asherahLog);
// ... later
Asherah.clearLogHook();
```

For per-target dispatch — each Rust source target (`asherah::session`,
`asherah::builders`, etc.) routed to its own `Logger` so host-side filter
rules can match by category — pass an `ILoggerFactory` through the
`AsherahSlf4j` helper:

```java
import com.godaddy.asherah.jni.AsherahSlf4j;
import org.slf4j.LoggerFactory;

Asherah.setLogHook(AsherahSlf4j.logHook(LoggerFactory.getILoggerFactory()));
```

The raw `AsherahLogHook` callback is also available if you don't use SLF4J:

```java
import com.godaddy.asherah.jni.Asherah;
import com.godaddy.asherah.jni.AsherahLogHook;
import org.slf4j.event.Level;

Asherah.setLogHook(event -> {
    // event.getLevel() returns org.slf4j.event.Level directly
    if (event.getLevel().toInt() >= Level.WARN.toInt()) {
        System.err.println("[asherah " + event.getLevel() + "] "
                + event.getTarget() + ": " + event.getMessage());
    }
});
```

The hook may fire from any thread (tokio worker threads, DB driver threads),
so implementations must be thread-safe and should not block. Exceptions
thrown from the hook are caught and silently swallowed by the JNI bridge.

### Metrics hook

Asherah produces timing observations (`encrypt`, `decrypt`, `store`, `load`)
and cache events (`cache_hit`, `cache_miss`, `cache_stale`). Installing a
hook implicitly enables the global metrics gate; clearing it disables it.

If your stack already uses Micrometer (Spring Boot, Micronaut, Quarkus, or any
OpenTelemetry / Prometheus / Datadog / CloudWatch registry), point the
metrics hook at your `MeterRegistry`:

```java
import com.godaddy.asherah.jni.Asherah;
import com.godaddy.asherah.jni.AsherahMicrometer;
import io.micrometer.core.instrument.MeterRegistry;

MeterRegistry registry = ...; // injected by your framework
Asherah.setMetricsHook(AsherahMicrometer.metricsHook(registry));
```

The bridge registers standard instruments on the supplied registry —
`asherah.encrypt.duration` (Timer), `asherah.cache.hits` (Counter, tag
`cache=name`), and so on — and forwards each event to the appropriate one.
The `micrometer-core` dependency is `optional` in the POM: callers that
don't reference `AsherahMicrometer` are not forced to pull it.

For other metrics libraries (StatsD, dropwizard-metrics, etc.) install a raw
callback:

```java
import com.godaddy.asherah.jni.Asherah;

Asherah.setMetricsHook(event -> {
    switch (event.getTypeEnum()) {
        case ENCRYPT:
        case DECRYPT:
        case STORE:
        case LOAD:
            myMetrics.timing("asherah." + event.getType(), event.getDurationNs());
            break;
        case CACHE_HIT:
        case CACHE_MISS:
        case CACHE_STALE:
            myMetrics.counter("asherah." + event.getType(), event.getName());
            break;
    }
});
// ... later
Asherah.clearMetricsHook();
```

| Event type | Duration | Name |
|---|---|---|
| `ENCRYPT` | elapsed ns | `null` |
| `DECRYPT` | elapsed ns | `null` |
| `STORE` | elapsed ns | `null` |
| `LOAD` | elapsed ns | `null` |
| `CACHE_HIT` | `0` | cache identifier |
| `CACHE_MISS` | `0` | cache identifier |
| `CACHE_STALE` | `0` | cache identifier |

The same threading caveats apply as for the log hook — implementations must
be thread-safe and non-blocking, and exceptions are caught.

## License

Licensed under the Apache License, Version 2.0.
