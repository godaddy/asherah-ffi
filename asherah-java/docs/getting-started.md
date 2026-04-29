# Getting started

Step-by-step walkthrough from Maven dependency to a round-trip
encrypt/decrypt. After this guide, see:

- [`framework-integration.md`](./framework-integration.md) —
  Spring Boot, Micronaut, Quarkus, Helidon, Vert.x integration.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS KMS + DynamoDB.
- [`testing.md`](./testing.md) — JUnit 5 fixtures, Testcontainers,
  mocking patterns.
- [`troubleshooting.md`](./troubleshooting.md) — common errors and
  fixes.

## 1. Add the dependency

### Maven

```xml
<dependency>
  <groupId>com.godaddy.asherah</groupId>
  <artifactId>appencryption</artifactId>
  <version>0.6.64</version>
</dependency>

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
    maven { url = uri("https://maven.pkg.github.com/godaddy/asherah-ffi") }
}

dependencies {
    implementation("com.godaddy.asherah:appencryption:0.6.64")
}
```

The published artifact bundles native libraries (JNI) for Linux
(x64/aarch64, glibc and musl), macOS (x64/arm64), and Windows
(x64/arm64). Loaded automatically by the JNI binding at startup. JDK 11+.

## 2. Pick an API style

Two coexisting API surfaces — same wire format, same native core:

| Style | Entry points | Use when |
|---|---|---|
| Static | `Asherah.setup()`, `Asherah.encryptString()`, … | Configure once, encrypt/decrypt with a partition id. Drop-in compatible with the canonical `godaddy/asherah-java` API. |
| Factory / Session | `Asherah.factoryFromConfig(config)`, `factory.getSession(id)`, `session.encryptBytes(...)` | Explicit lifecycle, multiple factories, multi-tenant isolation visible in code. Implements `AutoCloseable` (try-with-resources). |

The static API is a thin convenience wrapper over the factory/session
API. Pick by which one reads better at the call site.

## 3. Configure

Both styles use the same `AsherahConfig`, built via the fluent
builder:

```java
import com.godaddy.asherah.jni.AsherahConfig;

AsherahConfig config = AsherahConfig.builder()
    .serviceName("my-service")
    .productId("my-product")
    .metastore("memory")          // testing only — use "rdbms" or "dynamodb" in production
    .kms("static")                // testing only — use "aws" in production
    .enableSessionCaching(Boolean.TRUE)
    .build();

// Testing-only static master key. Production must use AWS KMS;
// see aws-production-setup.md.
System.setProperty("STATIC_MASTER_KEY_HEX", "22".repeat(32));
```

`serviceName` and `productId` form the prefix for generated
intermediate-key IDs. Pick stable values — changing them later
orphans existing envelope keys.

For the complete builder option list, see the **Configuration**
section of the [main README](../README.md#configuration).

## 4. Encrypt and decrypt — static API

```java
import com.godaddy.asherah.jni.Asherah;

Asherah.setup(config);
try {
    String ciphertext = Asherah.encryptString("user-42", "secret");
    // Persist `ciphertext` (a JSON string) to your storage layer.

    // Later, after reading it back:
    String plaintext = Asherah.decryptString("user-42", ciphertext);
    System.out.println(plaintext);   // "secret"
} finally {
    Asherah.shutdown();
}
```

For binary payloads use `Asherah.encryptBytes(partitionId, byte[])` /
`Asherah.decryptBytes(partitionId, byte[])`.

## 5. Encrypt and decrypt — factory / session API

```java
import com.godaddy.asherah.jni.AsherahFactory;
import com.godaddy.asherah.jni.AsherahSession;

try (AsherahFactory factory = Asherah.factoryFromConfig(config);
     AsherahSession session = factory.getSession("user-42")) {
    String ciphertext = session.encryptString("secret");
    String plaintext = session.decryptString(ciphertext);
}
```

`AsherahFactory` and `AsherahSession` both implement `AutoCloseable` —
use try-with-resources for guaranteed cleanup. The factory's session
cache means `factory.getSession("u")` returns a cached session for
the same partition until LRU-evicted.

`Asherah.factoryFromEnv()` is also available when configuration comes
exclusively from environment variables.

## 6. Async API (CompletableFuture)

Every sync method has an `*Async` counterpart returning
`CompletableFuture<T>`. The work runs on the Rust tokio runtime — your
JVM thread pool is not blocked while metastore or KMS I/O is in
flight.

```java
Asherah.setup(config);
try {
    String ciphertext = Asherah.encryptStringAsync("user-42", "secret").get();
    String plaintext  = Asherah.decryptStringAsync("user-42", ciphertext).get();
} finally {
    Asherah.shutdown();
}
```

For non-blocking flows compose with `thenApply` / `thenCompose`:

```java
Asherah.encryptStringAsync(tenantId, payload)
    .thenCompose(ct -> repository.storeAsync(id, ct))
    .thenAccept(stored -> log.info("Stored {}", stored));
```

> **Sync vs async:** prefer sync for Asherah's hot encrypt/decrypt
> paths. The native operation is sub-microsecond — `CompletableFuture`
> overhead is larger than the work itself for in-memory and warm
> cache scenarios. Use `*Async` in reactive web stacks (WebFlux,
> Micronaut reactive, Vert.x) and async controllers where you're
> already on a non-blocking context that touches a network metastore
> (DynamoDB, MySQL, Postgres) and the I/O actually warrants
> yielding.

## 7. Wire up observability

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

Logger asherahLog = LoggerFactory.getLogger("asherah");

// Bridge log events to SLF4J. event.getLevel() returns
// org.slf4j.event.Level directly — pass through.
Asherah.setLogHook(event -> {
    asherahLog.atLevel(event.getLevel())
              .addKeyValue("target", event.getTarget())
              .log(event.getMessage());
});

// Metrics events: encrypt/decrypt timings + cache counters.
Asherah.setMetricsHook(event -> {
    if (event.getName() == null) {
        // Timing event (encrypt/decrypt/store/load).
        myHistogram.record(event.getType().name(), event.getDurationNs() / 1_000_000.0);
    } else {
        // Cache event (cache_hit/miss/stale).
        myCounter.inc(event.getType().name(), event.getName());
    }
});
```

Hooks are process-global. `Asherah.clearLogHook()` /
`Asherah.clearMetricsHook()` deregister.

`setLogHookSync` / `setMetricsHookSync` variants fire on the
encrypt/decrypt thread before the operation returns — pick those if
you need MDC / trace context intact in the callback or have
verifiably non-blocking handlers.

## 8. Move to production

The example uses `metastore("memory")` and `kms("static")` — both
**testing only**. Memory metastore loses keys on process restart;
static KMS uses a hardcoded master key. For real deployments, follow
[`aws-production-setup.md`](./aws-production-setup.md).

## 9. Handle errors

Asherah surfaces errors via thrown `RuntimeException` (or
`CompletionException` wrapping in async flows). Specific shapes and
what to check first are in
[`troubleshooting.md`](./troubleshooting.md).

Common shapes:
- `NullPointerException` — `null` passed where a value was required.
- `IllegalArgumentException: partition id cannot be empty` — empty
  partition string.
- `RuntimeException: decrypt_from_json: ...` — malformed envelope.
- `RuntimeException: factory_from_config: ...` — invalid config or
  KMS/metastore unreachable.

## What's next

- [`framework-integration.md`](./framework-integration.md) — Spring
  Boot, Micronaut, Quarkus, Helidon, Vert.x.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS config from KMS key creation through IAM policy.
- The complete [sample app](../../samples/java/Sample.java) exercises
  every API style + async + log hook + metrics hook.
