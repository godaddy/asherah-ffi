# Design: Canonical API Compatibility Layers for Java and .NET

## Goal

Provide drop-in compatibility with the canonical Asherah SDKs for Java and C#. Existing code using `com.godaddy.asherah.appencryption.SessionFactory` (Java) or `GoDaddy.Asherah.AppEncryption.SessionFactory` (C#) must work without code changes by adding our package as a dependency. Our existing "new-style" FFI API (`com.godaddy.asherah.jni`, `GoDaddy.Asherah`) remains available alongside the compatibility layer.

## Architecture

The compatibility layer is pure Java / pure C# code that:
1. Accepts the canonical builder patterns and config objects
2. Maps them to our FFI config (string-based `AsherahConfig`)
3. Delegates encrypt/decrypt to our existing FFI session
4. Wraps our FFI session in the canonical `Session<P, D>` generic interface

```
Canonical API surface (SessionFactory, Session<P,D>, CryptoPolicy, etc.)
    │
    ▼
Compatibility adapter (maps builder calls → AsherahConfig, wraps Session)
    │
    ▼
Existing FFI layer (AsherahFactory, AsherahSession, JNI/P-Invoke)
    │
    ▼
Rust native library (libasherah_ffi)
```

## Scope

### What we implement
- `SessionFactory` with the full builder chain (`MetastoreStep → CryptoPolicyStep → KeyManagementServiceStep → BuildStep`)
- `Session<P, D>` interface with all four type combinations
- `Persistence<T>` abstract class with `load()`/`store()` (delegates to encrypt/decrypt + user storage)
- Built-in component classes that map to FFI config strings:
  - `InMemoryMetastoreImpl` → `metastore: "memory"`
  - `JdbcMetastoreImpl` / `AdoMetastoreImpl` → `metastore: "rdbms"` + connection string
  - `DynamoDbMetastoreImpl` → `metastore: "dynamodb"` + region/table/endpoint
  - `StaticKeyManagementServiceImpl` → `kms: "static"` + master key hex
  - `AwsKeyManagementServiceImpl` → `kms: "aws"` + region map
  - `NeverExpiredCryptoPolicy` → default (no expiry config)
  - `BasicExpiringCryptoPolicy` → expire_after + check_interval + cache settings
- `Metastore<T>` / `IMetastore<T>` interface (for type compatibility)
- `KeyManagementService` / `IKeyManagementService` interface
- `CryptoPolicy` abstract class

### What we do NOT implement
- Custom user-provided `Metastore` implementations that bypass our FFI (these require direct DB access from the caller's runtime, which our Rust layer handles internally)
- Custom `KeyManagementService` implementations (same reason)
- Custom `CryptoPolicy` implementations beyond the two canonical ones
- The `Metastore.load()`/`store()` methods on our built-in classes (these are internal to the key management layer, not called by users)

When a user passes a custom `IMetastore` or `IKeyManagementService` to the builder, we throw `UnsupportedOperationException` / `NotSupportedException` with a clear message explaining that custom implementations are not supported — use the built-in ones. This covers 99%+ of real-world usage since virtually all users use the provided implementations.

---

## Java Compatibility Layer

### Package Structure

```
com.godaddy.asherah.appencryption/
  SessionFactory.java          ← builder + factory (delegates to AsherahFactory)
  Session.java                 ← interface with default load/store methods
  SessionJsonImpl.java         ← Session<JSONObject, byte[]> adapter
  SessionBytesImpl.java        ← Session<byte[], byte[]> adapter
  persistence/
    Persistence.java           ← abstract class with load/store/generateKey
    Metastore.java             ← interface (marker for type compat)
    InMemoryMetastoreImpl.java ← maps to metastore="memory"
    JdbcMetastoreImpl.java     ← maps to metastore="rdbms" + connectionString
    DynamoDbMetastoreImpl.java ← maps to metastore="dynamodb" + config
  kms/
    KeyManagementService.java  ← interface (marker for type compat)
    StaticKeyManagementServiceImpl.java ← maps to kms="static"
    AwsKeyManagementServiceImpl.java    ← maps to kms="aws" + regionMap
  crypto/ (or com.godaddy.asherah.crypto/)
    CryptoPolicy.java          ← abstract class
    NeverExpiredCryptoPolicy.java ← default policy (no expiry)
    BasicExpiringCryptoPolicy.java ← configurable expiry
```

### SessionFactory Builder

The builder captures configuration and maps it to `AsherahConfig`:

```java
SessionFactory factory = SessionFactory.newBuilder("productId", "serviceId")
    .withInMemoryMetastore()           // → config.metastore("memory")
    .withNeverExpiredCryptoPolicy()     // → no expiry config (defaults)
    .withStaticKeyManagementService(key) // → config.kms("static")
    .build();
```

Internally:
```java
public SessionFactory build() {
    AsherahConfig.Builder cb = AsherahConfig.builder()
        .productId(productId)
        .serviceName(serviceId);
    metastoreConfig.apply(cb);      // sets metastore, connectionString, etc.
    cryptoPolicyConfig.apply(cb);   // sets expireAfter, checkInterval, caching, etc.
    kmsConfig.apply(cb);            // sets kms, regionMap, preferredRegion
    AsherahConfig config = cb.build();
    AsherahFactory nativeFactory = Asherah.factoryFromConfig(config);
    return new SessionFactory(nativeFactory);
}
```

### Session Adapter

`Session<JSONObject, byte[]>` wraps `AsherahSession`:

```java
class SessionJsonImpl implements Session<JSONObject, byte[]> {
    private final AsherahSession inner;

    public byte[] encrypt(JSONObject payload) {
        // Serialize JSONObject → byte[], encrypt, return DRR as byte[]
        byte[] data = payload.toString().getBytes(StandardCharsets.UTF_8);
        String drrJson = inner.encryptToJson(data);
        return drrJson.getBytes(StandardCharsets.UTF_8);
    }

    public JSONObject decrypt(byte[] dataRowRecord) {
        // Decrypt DRR → plaintext bytes → parse as JSONObject
        String drrJson = new String(dataRowRecord, StandardCharsets.UTF_8);
        byte[] plaintext = inner.decryptFromJson(drrJson);
        return new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
    }
}
```

Four session type combinations:
| Canonical Type | P (payload) | D (data row record) | Encrypt maps to | Decrypt maps to |
|---|---|---|---|---|
| `Session<JSONObject, byte[]>` | JSONObject | byte[] | JSONObject→bytes→encrypt→DRR bytes | DRR bytes→decrypt→JSONObject |
| `Session<byte[], byte[]>` | byte[] | byte[] | bytes→encrypt→DRR bytes | DRR bytes→decrypt→bytes |
| `Session<JSONObject, JSONObject>` | JSONObject | JSONObject | JSONObject→bytes→encrypt→DRR JSONObject | DRR JSONObject→decrypt→JSONObject |
| `Session<byte[], JSONObject>` | byte[] | JSONObject | bytes→encrypt→DRR JSONObject | DRR JSONObject→decrypt→bytes |

### Persistence<T>

The canonical `Persistence<T>` provides `load()`/`store()` that the `Session` default methods call. This is a user-provided storage backend (e.g., database, file). Our compat layer implements the `Session.load()` and `Session.store()` default methods which:

1. `store(payload)`: encrypt payload → serialize DRR → call `persistence.store(key, serializedDRR)` → return key
2. `load(key)`: call `persistence.load(key)` → deserialize DRR → decrypt → return payload

This is pure Java logic on top of our encrypt/decrypt — no FFI changes needed.

### Dependencies

The Java compat layer needs `org.json:json` for `JSONObject`. The canonical SDK uses this. We add it as an optional/provided dependency.

---

## C# Compatibility Layer

### Namespace Structure

```
GoDaddy.Asherah.AppEncryption/
  SessionFactory.cs            ← builder + factory
  Session.cs                   ← abstract class Session<TP, TD>
  Envelope/
    IEnvelopeEncryption.cs     ← interface (marker)
  Persistence/
    Persistence.cs             ← abstract class
    IMetastore.cs              ← interface
    InMemoryMetastoreImpl.cs   ← maps to metastore="memory"
    AdoMetastoreImpl.cs        ← maps to metastore="rdbms"
    DynamoDbMetastoreImpl.cs   ← maps to metastore="dynamodb"
    AdhocPersistence.cs        ← convenience Func-based persistence
  Kms/
    IKeyManagementService.cs   ← interface
    StaticKeyManagementServiceImpl.cs ← maps to kms="static"
    AwsKeyManagementServiceImpl.cs    ← maps to kms="aws"
  Crypto/
    CryptoPolicy.cs            ← abstract class
    NeverExpiredCryptoPolicy.cs
    BasicExpiringCryptoPolicy.cs
```

### SessionFactory Builder

Same pattern as Java, mapping to `AsherahConfig`:

```csharp
SessionFactory factory = SessionFactory.NewBuilder("productId", "serviceId")
    .WithInMemoryMetastore()
    .WithNeverExpiredCryptoPolicy()
    .WithStaticKeyManagementService(masterKey)
    .Build();

Session<JObject, byte[]> session = factory.GetSessionJson("partitionId");
byte[] encrypted = session.Encrypt(payload);
```

### Session<TP, TD>

Abstract class with virtual `Load`/`Store` methods (same as canonical), plus abstract `Encrypt`/`Decrypt`/`EncryptAsync`/`DecryptAsync`. Concrete implementations delegate to `AsherahSession`.

### Dependencies

The C# compat layer needs `Newtonsoft.Json` for `JObject` (canonical uses this). Add as a dependency of the compat package.

---

## Packaging Strategy

### Java

Two options:

**Option A: Single JAR with both APIs** (recommended)
- Package: `com.godaddy.asherah:asherah`
- Contains both `com.godaddy.asherah.jni.*` (new API) and `com.godaddy.asherah.appencryption.*` (compat)
- Users switching from canonical just change the Maven dependency, no import changes
- `org.json:json` added as a dependency

**Option B: Separate compat JAR**
- `com.godaddy.asherah:asherah` (new API, existing)
- `com.godaddy.asherah:asherah-compat` (canonical API surface, depends on asherah-java)
- More modular but adds dependency management burden

Recommendation: **Option A** — single JAR. The compat classes are small (pure adapter code) and having one dependency simplifies migration.

### C#

**Option A: Single NuGet with both APIs** (recommended)
- Package: `GoDaddy.Asherah`
- Contains both `GoDaddy.Asherah` namespace (new API) and `GoDaddy.Asherah.AppEncryption` namespace (compat)
- `Newtonsoft.Json` added as a dependency

**Option B: Separate compat NuGet**
- `GoDaddy.Asherah` (new API, existing)
- `GoDaddy.Asherah.AppEncryption` (compat, depends on GoDaddy.Asherah)

Recommendation: **Option A** — same rationale as Java.

---

## Migration Path for Users

### From Canonical Java SDK

Before (canonical):
```java
import com.godaddy.asherah.appencryption.*;
import com.godaddy.asherah.crypto.*;

SessionFactory factory = SessionFactory.newBuilder("prod", "svc")
    .withInMemoryMetastore()
    .withNeverExpiredCryptoPolicy()
    .withStaticKeyManagementService("masterKey")
    .build();

try (Session<JSONObject, byte[]> session = factory.getSessionJson("partition")) {
    byte[] encrypted = session.encrypt(new JSONObject(data));
    JSONObject decrypted = session.decrypt(encrypted);
}
factory.close();
```

After (our package, zero code changes):
```java
// Same imports, same code — just change Maven dependency
import com.godaddy.asherah.appencryption.*;
import com.godaddy.asherah.crypto.*;

// Identical usage
SessionFactory factory = SessionFactory.newBuilder("prod", "svc")
    .withInMemoryMetastore()
    .withNeverExpiredCryptoPolicy()
    .withStaticKeyManagementService("masterKey")
    .build();
// ... rest unchanged
```

### From Canonical C# SDK

Same — just change NuGet dependency, zero code changes.

---

## Limitations

1. **Custom Metastore/KMS implementations**: Not supported. The builder methods that accept interfaces (`withMetastore(IMetastore)`, `withKeyManagementService(IKeyManagementService)`) will check if the passed object is one of our built-in types. If it's a custom implementation, throw with a clear error message.

2. **CryptoPolicy extensibility**: Only `NeverExpiredCryptoPolicy` and `BasicExpiringCryptoPolicy` are supported. Custom `CryptoPolicy` subclasses passed to `withCryptoPolicy()` throw with a clear error message.

3. **JdbcMetastoreImpl/AdoMetastoreImpl DataSource**: The canonical JDBC metastore takes a `DataSource` object. Our compat layer extracts the connection URL from it if possible, or requires the connection string to be set via environment variable. Same for ADO.NET's `DbProviderFactory`.

4. **Metrics integration**: Canonical supports `withMetricsEnabled()` (Micrometer for Java, App.Metrics for C#). Our compat layer accepts the call but metrics are handled by the Rust layer's own observability.

5. **Logger injection**: Canonical supports `withLogger()`. Our compat layer accepts the call but logging goes through the Rust layer's verbose mode.

---

## Implementation Plan

### Phase 1: Java Compatibility Layer
1. Add `org.json:json` dependency to `asherah-java/java/pom.xml`
2. Create `com.godaddy.asherah.appencryption` package with SessionFactory, Session, builder interfaces
3. Create persistence package (Metastore, Persistence, InMemoryMetastoreImpl, JdbcMetastoreImpl, DynamoDbMetastoreImpl)
4. Create kms package (KeyManagementService, StaticKeyManagementServiceImpl, AwsKeyManagementServiceImpl)
5. Create crypto classes (CryptoPolicy, NeverExpiredCryptoPolicy, BasicExpiringCryptoPolicy)
6. Add tests that mirror canonical SDK usage patterns
7. Verify that canonical SDK test code runs unchanged against our compat layer

### Phase 2: C# Compatibility Layer
1. Add `Newtonsoft.Json` dependency to the .csproj
2. Create `GoDaddy.Asherah.AppEncryption` namespace with SessionFactory, Session<TP,TD>
3. Create Persistence, Kms, Crypto namespaces with all classes
4. Add tests mirroring canonical SDK usage
5. Verify canonical test code runs unchanged

### Phase 3: Validation
1. Take the canonical SDK's own test suites and run them against our compat layer
2. Cross-language interop: encrypt with canonical Java, decrypt with our compat C# (and vice versa)
3. Benchmark to verify no significant overhead from the adapter layer

---

## Size Estimate

- **Java compat layer**: ~15-20 source files, ~1500-2000 lines of adapter code
- **C# compat layer**: ~15-20 source files, ~1500-2000 lines of adapter code
- **Tests**: ~500 lines per language
- The compat code is entirely pure Java/C# — no Rust or FFI changes needed
