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

DynamoDB metastore errors (`Metastore: "dynamodb"`) carry the AWS
SDK's error chain, including the AWS message. Exceptions that
aws-sdk-dynamodb does not model, `AccessDeniedException` and
`ValidationException` among them, print as `service error: unhandled
error (<Code>)` followed by the AWS message:

- `service error: unhandled error (AccessDeniedException)` — IAM. The
  AWS message that follows usually names the missing `dynamodb:`
  action.
- `service error: unhandled error (ValidationException)` — for example
  a table schema mismatch. Asherah expects partition key `Id`
  (string), sort key `Created` (number).
- A DNS failure may read `dispatch failure: io error: client error
  (Connect): dns error: …` (not reproduced in testing).

KMS errors (`KMS: "aws"`) never include the AWS message, which embeds
account ids and ARNs. They name the region, the step that failed and a
fixed label for the cause, plus the AWS request id when AWS answered
(look it up in CloudTrail):

```
all KMS backends failed to decrypt (tried regions: us-west-2 [Decrypt service error AccessDeniedException, request id 4f6c8a1e-…])
KMS GenerateDataKey failed in region us-west-2: dispatch failure (other: no credentials available)
```

The `RuntimeException` carries only the outermost context:
`<op> failed: …` for synchronous calls, and the outermost context
alone when an async call's `CompletableFuture` completes
exceptionally. The full chain, with the KMS detail, is in a
warn-level log event (`<op> failed: …`, or `java async operation
failed: …` for async calls); a failed KMS decrypt also produces an error-level
`asherah::kms_aws_envelope` event and a failed KMS encrypt an
error-level `asherah::session` event. The log hook
receives all of these at its default level (warn).

- `service error <code>` — KMS answered. `AccessDeniedException`: the
  IAM or key policy does not allow the call. `DisabledException` /
  `KMSInvalidStateException` / `NotFoundException`: the key is
  disabled, pending deletion, or missing in that region.
  `ThrottlingException`: request rate; retry.
- `dispatch failure (other: <credentials label>)` — no usable AWS
  credentials, so the request never reached KMS:
  - `no credentials available` — no credentials source was found
    (environment, shared files, web identity, container, instance
    metadata). On EC2 it may also mean the instance metadata service
    could not be reached (aws-config reports that case the same way),
    where retrying can help.
  - `credentials provider error` — a configured source failed, for
    example a `credential_process` command that fails or a container
    credentials endpoint that answers HTTP 500.
  - `unexpected credentials provider failure` — for example a
    container credentials endpoint that refuses the connection.
  - `credentials provider timed out`, `invalid credentials
    configuration` — may be reported when a provider times out or its
    configuration is invalid.
- `not sent: no region configured`, `request construction failure
  (invalid endpoint parameters)` — no region is configured, or the
  configured region is not a region name (for example a key ARN where
  `RegionMap` expects a region). Retrying does not help.
- `dispatch failure (io: connection refused)` and other connection-level
  kinds — the KMS endpoint (or VPC endpoint / proxy) could not be
  reached. A DNS failure may also appear as `dispatch failure (io: …)`;
  which kind it names is not fixed.
- `dispatch failure (io: other error)` — commonly a TLS failure: a
  TLS-inspecting proxy, a VPC endpoint whose certificate comes from a
  private CA the client does not trust, or an endpoint that does not
  speak TLS. Retrying does not fix it.
- `dispatch failure (timeout)`, `dispatch failure (other: transient
  error)` — the connection attempt timed out, or the connection closed
  before a response arrived.

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
