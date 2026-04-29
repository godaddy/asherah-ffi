# Troubleshooting

Common errors when integrating the Java binding, what they mean, and
what to check first.

## Decrypt errors

### `decrypt_from_json: expected value at line 1 column 1`

You called `decryptString("")`, `decryptBytes(new byte[0])`, or the
async variants with empty input. Empty bytes can't be a valid
DataRowRecord envelope (smallest legitimate envelope is ~241 bytes).

**Likely cause:** caller code is short-circuiting empty values:

```java
// Bug — encrypt produced an envelope, but storage layer dropped it.
if (envelope.isEmpty()) return "";
return session.decryptString(envelope);
```

**Fix:** check for the empty case *before* decrypt:

```java
String envelope = repo.loadEnvelope(id);
return envelope != null ? session.decryptString(envelope) : null;
```

### `decrypt_from_json: tag mismatch` / `authentication failed`

Envelope JSON parses but the AES-GCM auth tag doesn't verify. Causes:
- Tampered envelope (security incident if unexpected).
- Decrypting under different `serviceName`/`productId` than encrypted.
- Metastore wiped/rotated between encrypt and decrypt.

**Fix:** check `serviceName`/`productId` parity. Inspect the JSON's
`Key.ParentKeyMeta.KeyId` and verify a row with that ID exists in
your metastore.

### `decrypt_from_json: ...` (other JSON errors)

Input is non-empty but not valid Asherah JSON. Likely:
- Storage layer applied additional encoding (base64, gzip) on write.
- Envelope was truncated (column-length limit, transport mangling).

## Configuration errors

### `factory_from_config: Unknown metastore kind 'X'`

`metastore(...)` got a value that isn't `"memory"`, `"rdbms"`,
`"dynamodb"`, or `"sqlite"`.

### `factory_from_config: Unknown KMS type 'X'`

Same shape for `kms(...)`. Accepted: `"static"`, `"aws"`,
`"secrets-manager"`, `"vault"`.

### `factory_from_config: connection string required`

`metastore("rdbms")` without `connectionString(...)`.

### `factory_from_config: KmsKeyId or RegionMap required`

`kms("aws")` without either `kmsKeyId(...)` or `regionMap(...)`.

## Lifecycle / programming errors

### `IllegalStateException: Asherah is already configured; call shutdown() first`

`Asherah.setup(config)` called twice. The static API has exactly one
process-global instance.

**Fix:** if testing reconfiguration, call `Asherah.shutdown()` first.
In production, look for duplicate setup calls (often from multiple
classloaders if you have multiple WAR/EAR deployments in one Tomcat).

### `IllegalStateException: Asherah not configured; call setup() first`

Static API used before `setup()`. Check startup ordering.

### `IllegalArgumentException: partition id cannot be empty`

Empty string passed as partition id. Asherah is stricter than the
canonical `godaddy/asherah-java` v0.x SDK (which silently accepts
empty IDs and writes degenerate `_IK__service_product` rows).

### `NullPointerException`

`null` passed where a value was required. Usually means an upstream
value didn't arrive — check for missing JSON properties, missing
HTTP headers, etc.

## Native library errors

### `UnsatisfiedLinkError: cannot open shared object file`

The JNI library is present but its dynamic-library dependencies
aren't. Most common on Alpine without `libgcc` / `libstdc++`. Add
`apk add libgcc libstdc++` to your Dockerfile.

### `UnsatisfiedLinkError: ... no asherah_jni in java.library.path`

The JNI library wasn't extracted from the JAR. Causes:

- Running with a custom `-Djava.library.path` that overrides the
  binding's auto-extraction.
- Java security manager blocks the temp-directory write the binding
  uses to extract the bundled library.

**Fix:** set `ASHERAH_JAVA_NATIVE` to a directory containing the
library you've extracted manually:

```bash
java -DASHERAH_JAVA_NATIVE=/opt/asherah/native -jar app.jar
```

### Wrong architecture loaded

Apple Silicon (M1/M2) running JVM under Rosetta or vice versa:

```bash
java -XshowSettings:properties 2>&1 | grep os.arch
```

If it says `x86_64` but you're on arm64, install an arm64 JDK and
retry.

## AWS-specific errors

Forwarded from the AWS SDK for Rust running in the native core:

- `dispatch failure: ResolveError` — DNS resolution failed. VPC
  endpoint / network ACL / `AWS_REGION` mismatch.
- `service error: AccessDeniedException` — IAM. The error names the
  missing action.
- `service error: ValidationException: ...AttributeName...` —
  DynamoDB schema mismatch. Asherah expects partition key `Id`
  (string), sort key `Created` (number).
- `service error: KMSInvalidStateException` — KMS key is
  `PendingDeletion`/`Disabled`.

The AWS Java SDK's `DefaultCredentialsProvider` is **not** consulted —
Asherah's native core uses the AWS SDK for Rust's chain. They have
separate caches; configure each independently.

## Spring Boot pitfalls

### `BeanCreationException: ... while creating bean 'asherahFactory'`

The factory's startup hit a config or AWS error. Look further down
the stack trace — the actual cause is wrapped. Common causes:

- Missing `@Value` placeholder (config not loaded). Check
  `application.yml` / `application.properties`.
- IAM role not attached or env vars missing.
- `@Bean(destroyMethod = "close")` is correct on the factory bean —
  if you forgot it, the factory leaks across context restarts.

### Circular dependency on `AsherahFactory`

If `AsherahFactory` depends on a service that depends on it
indirectly, refactor so the factory bean has no service deps —
configuration only.

## Async / CompletableFuture pitfalls

### `CompletionException` wrapping every async error

`CompletableFuture` wraps exceptions in `CompletionException`. Catch
the cause:

```java
try {
    String ct = Asherah.encryptStringAsync(p, s).get();
} catch (ExecutionException ex) {
    Throwable cause = ex.getCause();
    // handle the actual error
}
```

In reactive flows (`Mono.fromFuture`), Reactor unwraps
`CompletionException` automatically — your `onErrorResume` handler
sees the inner exception.

## Diagnostic recipe

When a problem isn't covered above:

1. **Set verbose logging:**
   ```java
   Asherah.setLogHookSync(evt ->
       System.err.println("[asherah " + evt.getLevel() + "] "
           + evt.getTarget() + ": " + evt.getMessage()));
   AsherahConfig cfg = AsherahConfig.builder().verbose(true) /* ... */ .build();
   ```
   Trace records cover every metastore call, KMS call, and
   key-cache decision.

2. **Inspect the metastore directly.** RDBMS: query
   `encryption_key`. DynamoDB: scan `AsherahKeys`. Confirm rows for
   the SK and IK IDs the failing envelope references.

3. **Repro with `metastore("memory")` + `kms("static")`.** Eliminates
   AWS as a variable.

4. **Static-master-key rotation.** Setting `STATIC_MASTER_KEY_HEX` to
   a different value than what was used to encrypt fails decrypt
   with a tag mismatch.
